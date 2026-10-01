import bisect

import gtirb
from capstone import CS_OP_IMM
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch.architecture import Architecture
from teapot.configs.blacklist import is_blacklisted_function
from teapot.passes.mixins import VisitorPassMixin
from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.utils.misc import distinguish_edges, generate_distinct_label_name

# Labels just after a pad; direct transfers into the padded block go there.
DIRECT_ENTRY_PREFIX = ".L__teapot_direct_entry_"


def _rewriter_wraps(constraints):
    """Whether gtirb-rewriting adds its own prologue and epilogue around the patch."""
    return bool(constraints.clobbers_flags or constraints.clobbers_registers or
                constraints.scratch_registers or constraints.align_stack or
                constraints.preserve_caller_saved_registers)


def _followed_by_label(patch, label):
    def labeled(ctx):
        return f"{patch(ctx)}\n{label}:\n"
    return labeled


class TextIndirectBranchTransformPass(VisitorPassMixin):
    text_section: gtirb.Section
    text_transient_mapping: CopiedSectionMapping

    def __init__(self, text_section: gtirb.Section, text_transient_mapping: CopiedSectionMapping,
                 decoder: GtirbInstructionDecoder, arch: Architecture,
                 reg_manager: LiveRegisterManager = None, landing_pad_targets=None,
                 required_target_symbols=(), potential_targets=frozenset(),
                 flags_dead_blocks=frozenset()):
        self.text_section = text_section
        self.text_transient_mapping = text_transient_mapping
        self.arch = arch
        self.reg_manager = reg_manager
        self.landing_pad_targets = landing_pad_targets if landing_pad_targets is not None else set()
        self.required_target_symbols = frozenset(required_target_symbols)
        # Blocks to pad although the lift found no indirect edge to them, and
        # blocks whose flags are dead on entry (see indirect_targets.py).
        self.potential_targets = frozenset(potential_targets)
        self.flags_dead_blocks = frozenset(flags_dead_blocks)
        self.pad_counts = {"indirect-edge": 0, "no-predecessor": 0, "exported": 0,
                           "potential": 0, "return-site": 0, "no-return-call-site": 0}
        # Label base name -> the direct call and jump operands that should skip that pad.
        self.direct_entries = {}

        self.decoder = decoder

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)
        self.symbol_names = {symbol.name for symbol in module.symbols}
        self.no_return_callers = self._no_return_callers()
        self.direct_entries = {}
        self.visit_functions(functions, self.text_section)
        counts = ", ".join(f"{name} {count}" for name, count in self.pad_counts.items() if count)
        print(f"[teapot] normal-text pads: {counts}", flush=True)

    def end_module(self, module: gtirb.Module, functions) -> None:
        self._retarget_direct_transfers(module)
        super().end_module(module, functions)

    def _direct_operand(self, source: gtirb.CodeBlock):
        """The symbolic operand of the direct call or jump that ends the block, if any."""
        instructions = list(self.decoder.get_instructions(source))
        if not instructions:
            return None
        pair = self.arch.direct_transfer_expression(source, instructions)
        if pair is not None:
            return pair
        last = instructions[-1]
        if (not self.arch.is_direct_transfer_instruction(last) or
                not any(operand.type == CS_OP_IMM for operand in last.operands)):
            return None
        expressions = source.byte_interval.symbolic_expressions
        start = source.offset + last.address - source.address
        found = [expressions[position] for position in range(start, start + last.size)
                 if position in expressions]
        return found[0] if len(found) == 1 else None

    def _direct_operands(self, block: gtirb.CodeBlock):
        """Direct call and jump operands in normal text that name the block's start."""
        operands = {}
        for edge in block.incoming_edges:
            label = edge.label
            if (label is None or not label.direct or
                    label.type not in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) or
                    not isinstance(edge.source, gtirb.CodeBlock) or
                    edge.source.section is not self.text_section):
                continue
            expression = self._direct_operand(edge.source)
            if (isinstance(expression, gtirb.SymAddrConst) and expression.offset == 0 and
                    expression.symbol.referent is block and not expression.symbol.at_end):
                operands[id(expression)] = expression
        return list(operands.values())

    def _retarget_direct_transfers(self, module: gtirb.Module):
        """Point the recorded direct operands at the labels after their pads.

        Normal text runs with an active checkpoint only inside pads, which
        redirect into the copy, so a direct call or jump only ever arrives
        natively, where the pad's checkpoint test falls through. Runs after the
        rewrite: the rewriter keeps expression objects when it moves them.

        Records label -> the pad's own symbol in ``arch.direct_entry_pads``: a
        branch relaxed into an indirect one must land on the pad again.
        """
        self.arch.direct_entry_pads = {}
        if not self.direct_entries:
            return
        labels = {}
        for symbol in module.symbols:
            if symbol.name.startswith(DIRECT_ENTRY_PREFIX):
                # The assembler adds a per-patch suffix to local labels.
                end = symbol.name.rindex(SYMBOL_SUFFIX) + len(SYMBOL_SUFFIX)
                labels[symbol.name[:end]] = symbol
        targets = {}
        for base, expressions in self.direct_entries.items():
            label = labels[base]
            for expression in expressions:
                targets[id(expression)] = (expression, label)
        moved = 0
        cfg = module.ir.cfg
        for interval in self.text_section.byte_intervals:
            blocks = sorted((b for b in interval.blocks if isinstance(b, gtirb.CodeBlock) and b.size),
                            key=lambda b: b.offset)
            offsets = [b.offset for b in blocks]
            for position, expression in list(interval.symbolic_expressions.items()):
                target = targets.get(id(expression))
                if target is None or target[0] is not expression:
                    continue
                label = target[1]
                interval.symbolic_expressions[position] = gtirb.SymAddrConst(
                    0, label, expression.attributes)
                self.arch.direct_entry_pads.setdefault(label, expression.symbol)
                moved += 1
                # Move the CFG edge from the pad's start as well.
                index = bisect.bisect_right(offsets, position) - 1
                if index < 0 or label.at_end:
                    continue
                pad_start = expression.symbol.referent
                for edge in list(blocks[index].outgoing_edges):
                    if (edge.target is pad_start and edge.label is not None and edge.label.direct and
                            edge.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch)):
                        cfg.discard(edge)
                        cfg.add(gtirb.Edge(edge.source, label.referent, edge.label))
        print(f"[teapot] direct transfers past pads: {moved} into {len(self.direct_entries)} blocks",
              flush=True)

    def _no_return_callers(self):
        """Block -> the preceding block, when that ends in a call without a fallthrough edge.

        The lift may think such a call never returns. If it does return, it
        returns here, so this block is a return site like any other.
        """
        callers = {}
        for interval in self.text_section.byte_intervals:
            by_offset = {block.offset: block for block in interval.blocks
                         if isinstance(block, gtirb.CodeBlock) and block.size}
            for block in by_offset.values():
                edges = [edge for edge in block.outgoing_edges if edge.label is not None]
                if (any(edge.label.type == gtirb.cfg.Edge.Type.Call for edge in edges) and
                        not any(edge.label.type == gtirb.cfg.Edge.Type.Fallthrough for edge in edges)):
                    site = by_offset.get(block.offset + block.size)
                    if site is not None:
                        callers[site.uuid] = block
        return callers

    def visit_function(self, function: Function):
        if is_blacklisted_function(function):
            return

        if self.arch.indirect_transform_uses_live_registers() and self.reg_manager is not None:
            self.reg_manager.analyze(function)
        super().visit_function(function)

    def _ensure_landing_pad_symbol(self, original_block_uuid):
        landing_name = self.arch.indirect_transform_landing_pad_label(original_block_uuid)
        if landing_name is None or landing_name in self.symbol_names:
            return

        transient_block = self.text_transient_mapping.code_blocks_map.get(original_block_uuid)
        if transient_block is None:
            return

        gtirb.Symbol(
            name=landing_name,
            payload=transient_block,
            module=self.module)
        self.symbol_names.add(landing_name)

    def _indirect_transform_target_patch(self, target_symbol: gtirb.Symbol, function: Function,
                                         block: gtirb.CodeBlock, instruction_idx: int,
                                         fallback_target_uuid, flags_live=True):
        # The fallback target is not part of live-register allocation.  It is
        # only needed if allocation fails and the arch fallback must redirect
        # through a restore/landing pad.
        patch = self._allocated_indirect_transform_target_patch(
            target_symbol, function, block, instruction_idx)
        if patch is not None:
            return patch

        return self._indirect_transform_fallback_patch(
            target_symbol, fallback_target_uuid or block.uuid, flags_live)

    def _allocated_indirect_transform_target_patch(self, target_symbol: gtirb.Symbol, function: Function,
                                                   block: gtirb.CodeBlock, instruction_idx: int):
        if self.reg_manager is None or not self.arch.indirect_transform_uses_live_registers():
            return None

        patch = self.arch.indirect_branch_target_patch(target_symbol, use_scratch_registers=True)
        try:
            return self.reg_manager.allocate_registers(function, block, instruction_idx, False)(patch)
        except NotEnoughFreeRegistersException:
            return None

    def _indirect_transform_fallback_patch(self, target_symbol: gtirb.Symbol,
                                           target_uuid, flags_live=True):
        # RISC-V fallback jumps through per-block landing pads so fixed first
        # spills are restored before entering the transient copy.  Architectures
        # without landing-pad fallback keep the original target symbol.
        if self.arch.indirect_transform_landing_pad_label(target_uuid) is not None:
            self.landing_pad_targets.add(target_uuid)
            self._ensure_landing_pad_symbol(target_uuid)
        return self.arch.indirect_transform_fallback_patch(
            target_symbol, landing_target_uuid=target_uuid, flags_live=flags_live)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        incoming_edges = list(block.incoming_edges)
        non_fallthrough_edges, fallthrough_edges = distinguish_edges(incoming_edges)

        required_entry = any(symbol.name in self.required_target_symbols for symbol in block.references)
        indirect_edge = any(e.label.type in (gtirb.cfg.Edge.Type.Call, gtirb.cfg.Edge.Type.Branch) and
                            not e.label.direct for e in non_fallthrough_edges)
        reason = ("exported" if required_entry else
                  "indirect-edge" if indirect_edge else
                  # Sometimes GTIRB doesn't detect indirect branches
                  "no-predecessor" if len(incoming_edges) == 0 else
                  "potential" if block.uuid in self.potential_targets else None)
        if reason is not None:
            self.pad_counts[reason] += 1
            # FIXME: Can we handle jump tables better altogether? Maybe there's a better way...
            transient_target = self.text_transient_mapping.code_blocks_map[block.uuid]
            indbr_transform_target_symbol = self._transform_target_symbol(
                ".L__indbr_transform_target_" + function.get_name() + "_",
                block,
                transient_target)
            # Every target must begin with the marker, before any application
            # instruction: an indirect arrival tests the pair at the block's
            # address. So do not apply the usual RISC-V adjustment that moves a
            # patch after a leading AUIPC. Inserting before the complete pair is
            # safe: the rewriter re-anchors its %pcrel_lo (GOT, TLS GD) half.
            if self.rewriting_ctx.resolve_insert_location(block, 0) == (block, 0):
                location = (block, 0)
                insert = self.rewriting_ctx.insert_at
            elif required_entry:
                # Inserting into a split call pair is not an independently
                # callable entry.
                raise ValueError("exported entry lies inside a protected instruction pair")
            else:
                location = self.insertion_register_location(block, 0)
                insert = self.insert_at
            patch = self._indirect_transform_target_patch(
                indbr_transform_target_symbol,
                function, *location, block.uuid,
                flags_live=block.uuid not in self.flags_dead_blocks)
            constraints = patch.constraints
            # Direct calls and jumps skip the pad. Not when the rewriter moved
            # the pad (a direct arrival must run what precedes it), nor when it
            # would restore state after the label.
            operands = (self._direct_operands(block)
                        if location[0] is block and location[1] == 0 else ())
            if operands and not _rewriter_wraps(constraints):
                label = generate_distinct_label_name(DIRECT_ENTRY_PREFIX, block.uuid)
                self.direct_entries[label] = operands
                patch = _followed_by_label(patch, label)
            insert(block, 0, Patch.from_function(patch, constraints))

        caller = None
        if (len(fallthrough_edges) > 0 and
                any(e.label.type == gtirb.cfg.Edge.Type.Call for e in fallthrough_edges[0].source.outgoing_edges)):
            caller = fallthrough_edges[0].source
            self.pad_counts["return-site"] += 1
        elif block.uuid in self.no_return_callers:
            caller = self.no_return_callers[block.uuid]
            self.pad_counts["no-return-call-site"] += 1
        if caller is not None:
            # This insertion is in the caller, before the successor's AUIPC.
            # Its allocation must use the unadjusted successor-entry state.
            transient_target = self.text_transient_mapping.code_blocks_map[block.uuid]
            ret_transform_target_symbol = self._transform_target_symbol(
                ".L__ret_transform_target_" + function.get_name() + "_",
                block,
                transient_target)
            self.insert_at(
                caller,
                caller.size,
                Patch.from_function(
                    self._indirect_transform_target_patch(
                        ret_transform_target_symbol,
                        function,
                        block,
                        0,
                        block.uuid,
                        flags_live=block.uuid not in self.flags_dead_blocks)))

    def _transform_target_symbol(self, prefix: str, block: gtirb.CodeBlock, transient_target: gtirb.CodeBlock):
        target_symbol = gtirb.Symbol(
            name=generate_distinct_label_name(prefix, block.uuid),
            payload=transient_target,
            module=self.module)
        return target_symbol
