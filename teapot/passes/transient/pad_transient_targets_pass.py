"""Pad the speculative copy's reachable indirect targets (design step 5).

Only the targets an indirect branch inside the copy can arrive at are padded:
address-taking references remapped by ``copy_section`` (relocations, data
pointers, function pointers) and resolved indirect branch targets. The operand
of a direct branch or call is not an indirect target and gets no pad; neither
do return sites, because returns keep the range clause.

The pass runs after every other pass that writes to the copy, so the pad ends
up as the first word at the block's address: an indirect branch lands on the
marker and the block's entry code (guard push, memory logging, landing restore)
follows it. The marker words therefore never feed the instruction-cost model of
the copy.

A pad is the same marker as in normal text, in the same mode: ``bti jc`` plus
the magic word in the BTI modes, and the software pair otherwise (review item
6).
"""
import bisect

import gtirb
from gtirb_rewriting import Pass, Patch, RewritingContext, patch_constraints


class PadTransientTargetsPass(Pass):
    def __init__(self, section, decoder, marker_words, directive=".word", arch=None):
        self.section = section
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
        for candidate in block.section.code_blocks:
            if (candidate.size and candidate.offset == block.offset and
                    candidate.byte_interval is block.byte_interval):
                return candidate
        return None

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
        """True when the expression is the operand of a direct branch or call."""
        if self.arch is None or interval.address is None:
            return False
        address = interval.address + position
        block = self._block_at(interval, address)
        if block is None:
            return False
        for instruction in self._instructions(block):
            if instruction.address <= address < instruction.address + instruction.size:
                return self.arch.is_direct_transfer_instruction(instruction)
        return False

    def target_blocks(self):
        """Blocks in the copy that an indirect branch inside it can reach."""
        targets = set()
        for interval in self.section.byte_intervals:
            for position, expression in interval.symbolic_expressions.items():
                if self._is_direct_reference(interval, position):
                    continue
                for symbol in expression.symbols:
                    referent = symbol.referent
                    if isinstance(referent, gtirb.CodeBlock) and referent.section is self.section:
                        targets.add(referent)
        for block in self.section.code_blocks:
            for edge in block.outgoing_edges:
                target = edge.target
                if (not edge.label.direct and edge.label.type == gtirb.Edge.Type.Branch and
                        isinstance(target, gtirb.CodeBlock) and target.section is self.section):
                    targets.add(target)
        entries = set()
        for block in targets:
            entry = self._paddable_entry(block)
            if entry is not None and not self._already_marked(entry):
                entries.add(entry)
        return entries

    def _already_marked(self, block):
        contents = bytes(block.contents)
        if len(contents) < 8:
            return False
        words = (int.from_bytes(contents[0:4], "little"),
                 int.from_bytes(contents[4:8], "little"))
        return words == self.marker_words

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        text_out = self.marker_text()
        for block in sorted(self.target_blocks(), key=lambda b: b.address or 0):
            @patch_constraints()
            def patch(_ctx, text_out=text_out):
                return text_out

            rewriting_ctx.insert_at(block, 0, Patch.from_function(patch))
            self.padded += 1
        print(f"[teapot] padded {self.padded} speculative-copy targets", flush=True)


class AnchorTransientPadsPass(Pass):
    """Make the pad the first thing at its block's address (design step 5).

    Later passes insert guard push, memory logging and landing restore code at
    the copy's block starts, in front of a pad placed there earlier. Moving the
    pad back to offset zero keeps an indirect branch landing on the marker; the
    move is size-neutral, so no address changes and the branch relaxers still
    see the final code layout.
    """

    def __init__(self, section, marker_words, directive=".word"):
        self.section = section
        self.marker_words = tuple(marker_words)
        self.directive = directive
        self.anchored = 0

    def marker_text(self):
        return "".join(f"{self.directive} 0x{word:08x}\n" for word in self.marker_words)

    def marker_bytes(self):
        return b"".join(word.to_bytes(4, "little") for word in self.marker_words)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        marker = self.marker_bytes()
        for block in sorted(self.section.code_blocks, key=lambda b: b.address or 0):
            if block.size <= len(marker):
                continue
            start = bytes(block.contents).find(marker)
            if start <= 0 or start + len(marker) > block.size:
                continue

            @patch_constraints()
            def patch(_ctx):
                return self.marker_text()

            rewriting_ctx.delete_at(block, start, len(marker))
            rewriting_ctx.insert_at(block, 0, Patch.from_function(patch))
            self.anchored += 1
        print(f"[teapot] anchored {self.anchored} speculative-copy pads", flush=True)
