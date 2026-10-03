"""Pad the speculative copy's reachable indirect targets (design step 5).

Only the targets an indirect branch inside the copy can arrive at are padded:
address-taking references remapped by ``copy_section`` (relocations, data
pointers, function pointers) and resolved indirect branch targets. The operand
of a direct branch or call is not an indirect target and gets no pad (on
RISC-V, also the operands of a proven direct AUIPC+JALR pair), and neither is
the AUIPC label that a RISC-V ``%pcrel_lo`` operand names.

Return sites are padded in software mode, where a return checks the marker
pair like any other transfer: the block at the address after every call,
including calls the lift thinks never return. The combined mode keeps the
copy's return range clause, so its return sites get no pad.

The pass runs right after the copy is made. Later passes insert block entry
code (guard push, memory logging, landing restore) in front of the pads, and
AnchorTransientPadsPass moves each pad back to its block's first word, so an
indirect branch or a return lands on the marker. The marker words therefore
never feed the instruction-cost model of the copy.

A pad is the same marker as in normal text, in the same mode: ``bti jc`` plus
the magic word in the BTI modes, and the software pair otherwise (review item
6).
"""
import bisect

import gtirb
from gtirb_rewriting import Pass, Patch, RewritingContext, patch_constraints

from teapot.passes.text.indirect_targets import _direct_pair_offsets
from teapot.rewrite_state import TransientPads

_PCREL = gtirb.SymbolicExpression.Attribute.PCREL
_LO = gtirb.SymbolicExpression.Attribute.LO


class PadTransientTargetsPass(Pass):
    def __init__(self, section, decoder, marker_words, directive=".word", arch=None,
                 pad_return_sites=False, state=None):
        self.section = section
        # The rewrite's state (teapot/rewrite_state.py), which receives the pads.
        self.state = state
        self.pad_return_sites = pad_return_sites
        self.decoder = decoder
        self.marker_words = tuple(marker_words)
        # `.word` is four bytes on AArch64/RISC-V but two on x86; x64 passes
        # `.long` so a pad is exactly one marker pair.
        self.directive = directive
        self.arch = arch
        self.padded = 0
        self._blocks_by_interval = {}
        self._addresses_by_interval = {}
        self._instructions_by_block = {}
        self._real_blocks = None

    def marker_text(self):
        return "".join(f"{self.directive} 0x{word:08x}\n" for word in self.marker_words)

    def _paddable_entry(self, block):
        """Resolve a target to the real block that starts at its address.

        Copies keep zero-sized label blocks that share an address with the block
        that actually executes; gtirb-rewriting cannot insert into a zero-sized
        block, and a pad at the shared address belongs at the real block.
        """
        if block.size:
            return block
        if self._real_blocks is None:
            self._real_blocks = {}
            for candidate in self.section.code_blocks:
                if candidate.size:
                    self._real_blocks.setdefault((candidate.byte_interval, candidate.offset), candidate)
        return self._real_blocks.get((block.byte_interval, block.offset))

    def _instructions(self, block):
        instructions = self._instructions_by_block.get(block)
        if instructions is None:
            instructions = list(self.decoder.get_instructions(block))
            self._instructions_by_block[block] = instructions
        return instructions

    def _block_at(self, interval, address):
        blocks = self._blocks_by_interval.get(interval)
        if blocks is None:
            blocks = sorted(
                (block for block in interval.blocks
                 if isinstance(block, gtirb.CodeBlock) and block.size and block.address is not None),
                key=lambda block: block.address)
            self._blocks_by_interval[interval] = blocks
            self._addresses_by_interval[interval] = [block.address for block in blocks]
        addresses = self._addresses_by_interval[interval]
        index = bisect.bisect_right(addresses, address) - 1
        if index < 0:
            return None
        block = blocks[index]
        return block if address < block.address + block.size else None

    def _is_direct_reference(self, interval, position):
        """True when the expression is the operand of a direct branch or call.

        That includes the operands of a RISC-V AUIPC+JALR pair that the
        architecture proves direct: the target's symbol sits on the AUIPC, which
        is not a transfer instruction by itself. Normal text skips them the same
        way (indirect_targets._address_taken).
        """
        if self.arch is None or interval.address is None:
            return False
        address = interval.address + position
        block = self._block_at(interval, address)
        if block is None:
            return False
        for instruction in self._instructions(block):
            if instruction.address <= address < instruction.address + instruction.size:
                if self.arch.is_direct_transfer_instruction(instruction):
                    return True
                break
        return position in _direct_pair_offsets(block, self.decoder, self.arch,
                                                self._instructions_by_block)

    def target_blocks(self):
        """Blocks in the copy that an indirect branch inside it can reach and that need a pad."""
        return {entry for entry in self.reachable_entries() if not self._already_marked(entry)}

    def reachable_entries(self):
        """Every real block in the copy that an indirect branch inside it can reach.

        This includes blocks that already start with the marker and so get no pad;
        later insertions can displace their marker just the same.
        """
        return set(self._resolved_targets().values())

    def _resolved_targets(self):
        """Map each reachable target to the real block that carries its marker."""
        targets = set()
        for interval in self.section.byte_intervals:
            for position, expression in interval.symbolic_expressions.items():
                # A RISC-V %pcrel_lo operand names its own AUIPC's label, not a
                # target; the AUIPC's %pcrel_hi operand names the target. Normal
                # text skips it the same way (indirect_targets._address_taken).
                if {_PCREL, _LO} <= set(expression.attributes):
                    continue
                if self._is_direct_reference(interval, position):
                    continue
                for symbol in expression.symbols:
                    referent = symbol.referent
                    if isinstance(referent, gtirb.CodeBlock) and referent.section is self.section:
                        targets.add(referent)
        for block in self.section.code_blocks:
            for edge in block.outgoing_edges:
                target = edge.target
                if (edge.label is not None and not edge.label.direct and
                        edge.label.type == gtirb.Edge.Type.Branch and
                        isinstance(target, gtirb.CodeBlock) and target.section is self.section):
                    targets.add(target)
        if self.pad_return_sites:
            targets |= self.return_sites()
        resolved = {}
        for block in targets:
            entry = self._paddable_entry(block)
            if entry is not None:
                resolved[block] = entry
        return resolved

    def return_sites(self):
        """The blocks that start where a block ending in a call ends.

        A Call edge, direct or not, marks the call; the lift keeps it even for
        a call it thinks never returns, which has no fallthrough edge.
        """
        sites = set()
        for interval in self.section.byte_intervals:
            by_offset = {block.offset: block for block in interval.blocks
                         if isinstance(block, gtirb.CodeBlock) and block.size}
            for block in by_offset.values():
                if any(edge.label is not None and edge.label.type == gtirb.Edge.Type.Call
                       for edge in block.outgoing_edges):
                    site = by_offset.get(block.offset + block.size)
                    if site is not None:
                        sites.add(site)
        return sites

    def _already_marked(self, block):
        contents = bytes(block.contents)
        if len(contents) < 8:
            return False
        words = (int.from_bytes(contents[0:4], "little"),
                 int.from_bytes(contents[4:8], "little"))
        return words == self.marker_words

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        text_out = self.marker_text()
        resolved = self._resolved_targets()
        entries = set(resolved.values())
        targets = {entry for entry in entries if not self._already_marked(entry)}
        # gtirb-rewriting can place code inserted at a block's start in front
        # of other blocks at that offset, zero-sized labels included, so a
        # target label that shares a real block's address could end up behind
        # the marker. Its symbols name the real block instead, and the real
        # block joins the label's function rows.
        aliases = {label: entry for label, entry in resolved.items() if label is not entry}
        if aliases:
            for symbol in module.symbols:
                entry = aliases.get(symbol.referent)
                if entry is not None:
                    symbol.referent = entry
                    symbol.at_end = False
            for name in ("functionEntries", "functionBlocks"):
                table = module.aux_data.get(name)
                for blocks in (table.data.values() if table is not None else ()):
                    blocks.update(aliases[label] for label in aliases.keys() & blocks)
        if self.state is not None:
            # Every reachable target must start with the marker, padded here or
            # marked already: the anchor pass keeps it at the block's start and
            # the pipeline checks it at the end. The anchor's search for a
            # block's marker stops at the next of the copy's current blocks,
            # which the block's later pieces never pass.
            self.state.pads.set(TransientPads(
                padded_blocks=frozenset(block.uuid for block in entries),
                copy_blocks=frozenset(block.uuid for block in self.section.code_blocks if block.size)))
        for block in sorted(targets, key=lambda b: b.address or 0):
            @patch_constraints()
            def patch(_ctx, text_out=text_out):
                return text_out

            rewriting_ctx.insert_at(block, 0, Patch.from_function(patch))
            self.padded += 1
        print(f"[teapot] padded {self.padded} speculative-copy targets "
              f"({len(aliases)} zero-size label aliases)", flush=True)


class AnchorTransientPadsPass(Pass):
    """Make the pad the first thing at its block's address (design step 5).

    Later passes insert guard push, memory logging and landing restore code at
    the copy's block starts, in front of a pad placed there earlier. Moving the
    pad back to offset zero keeps an indirect branch landing on the marker; the
    move is size-neutral, so no address changes and the branch relaxers still
    see the final code layout.

    Inserted code with labels, such as RISC-V's restore landings, splits the
    block: the padded block keeps the start and the pad moves to the start of a
    later piece. ``padded`` names the blocks that must start with the marker
    (padded by the pad pass, or marked already); only their markers are moved.
    ``originals`` names the copy's blocks when the pad pass ran. Each block
    searches only up to the next of them (without the set, the next padded
    block), which its own later pieces never pass, so it never takes bytes of
    another block. A marker that cannot be found is left to the pipeline's
    end-state check (``TeapotPipeline._verify_target_markers``), which fails the
    build.
    """

    def __init__(self, section, marker_words, directive=".word", padded=(), originals=()):
        self.section = section
        self.marker_words = tuple(marker_words)
        self.directive = directive
        self.padded = frozenset(padded)
        self.originals = frozenset(originals) | self.padded
        self.anchored = 0

    def marker_text(self):
        return "".join(f"{self.directive} 0x{word:08x}\n" for word in self.marker_words)

    def marker_bytes(self):
        return b"".join(word.to_bytes(4, "little") for word in self.marker_words)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        marker = self.marker_bytes()
        # One copy of each byte interval and one offset index per interval.
        layouts = {}

        def layout(interval):
            # Sized code blocks do not overlap, so an offset names one holder.
            entry = layouts.get(interval)
            if entry is None:
                blocks = sorted((b for b in interval.blocks
                                 if isinstance(b, gtirb.CodeBlock) and b.size),
                                key=lambda b: b.offset)
                bounds = sorted({b.offset for b in blocks if b.uuid in self.originals})
                entry = layouts[interval] = (bytes(interval.contents), blocks,
                                             [b.offset for b in blocks], bounds)
            return entry

        owners = sorted((block for block in self.section.code_blocks
                         if block.uuid in self.padded and block.size),
                        key=lambda b: b.address or 0)
        for block in owners:
            contents, blocks, offsets, bounds = layout(block.byte_interval)
            if contents[block.offset:block.offset + len(marker)] == marker:
                continue
            # The block's own marker is the first one after its start and before
            # the next original block: inside the block, or in a later piece.
            following = bisect.bisect_right(bounds, block.offset)
            limit = bounds[following] if following < len(bounds) else len(contents)
            position = contents.find(marker, block.offset, limit)
            if position < 0:
                continue
            index = bisect.bisect_right(offsets, position) - 1
            holder = blocks[index] if index >= 0 else None
            if (holder is None or position + len(marker) > holder.offset + holder.size or
                    holder is not block and holder.uuid in self.originals):
                # Not a marker this block owns: none at all, one that crosses a
                # block boundary, or (defensively) another original block's.
                continue

            @patch_constraints()
            def patch(_ctx):
                return self.marker_text()

            rewriting_ctx.delete_at(holder, position - holder.offset, len(marker))
            rewriting_ctx.insert_at(block, 0, Patch.from_function(patch))
            self.anchored += 1
        print(f"[teapot] anchored {self.anchored} speculative-copy pads", flush=True)
