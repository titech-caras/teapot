import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch, AllFunctionsScope, FunctionPosition, BlockPosition
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn
from typing import List
import itertools

from teapot.arch.architecture import Architecture
from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.utils.misc import distinguish_edges
from teapot.configs.runtime import SYMBOL_SUFFIX


class TransientInsertRestorePointsPass(VisitorPassMixin, RegInstAwarePassMixin):
    reg_manager: LiveRegisterManager
    text_section: gtirb.Section
    transient_section: gtirb.Section

    # Insert restore points about every 50 instructions, and before the end of each basic block
    INSERTION_SPACING = 50

    def __init__(self, reg_manager: LiveRegisterManager,
                 text_section: gtirb.Section, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder, arch: Architecture, *,
                 linked_function_symbols=()):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.text_section = text_section
        self.transient_section = transient_section
        self.arch = arch
        self.linked_function_symbols = frozenset(linked_function_symbols)

    def _targets_linked_component(self, block, instructions, edge):
        """Recognize only a named transfer to a validated, instrumented provider.

        Do not treat arbitrary addresses/data operands/unnamed indirect targets
        as selected-library calls. Unknown and true external transfers retain
        the existing rollback; barriers/syscalls are handled before this test.
        """
        if not self.linked_function_symbols or not instructions:
            return False
        forwarding_aux = block.module.aux_data.get("symbolForwarding")
        forwarding = forwarding_aux.data if forwarding_aux is not None else {}
        if edge.label.direct:
            expression = self.arch.direct_transfer_expression(block, instructions)
            if expression is not None:
                # A direct pair's relocation names the real callee. Its CFG
                # destination may instead carry a local PLT/PCREL-anchor name.
                symbol = forwarding.get(expression.symbol, expression.symbol)
                return expression.offset == 0 and symbol.name in self.linked_function_symbols
        last = instructions[-1]
        offset = block.offset + last.address - block.address
        names = set()
        for position in range(offset, offset + last.size):
            expression = block.byte_interval.symbolic_expressions.get(position)
            if expression is not None:
                # Only the exported entry was required to have a bouncer.
                # provider+N could enter normal code after that redirection.
                if not isinstance(expression, gtirb.SymAddrConst) or expression.offset != 0:
                    return False
                symbol = forwarding.get(expression.symbol, expression.symbol)
                names.add(symbol.name)
        names.update(forwarding.get(symbol, symbol).name for symbol in edge.target.references)
        return bool(names) and names <= self.linked_function_symbols

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        rewriting_ctx.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main" + SYMBOL_SUFFIX}),
            Patch.from_function(self.arch.unconditional_restore_point_patch())
        )

        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        if self.reg_manager is not None and self.arch.restore_point_patch_uses_live_registers():
            self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
        instruction_len_sum: List[int] = [0] + list(itertools.accumulate(i.size for i in instructions))
        instruction_cost_sum = [0] + list(itertools.accumulate(
            self.arch.static_instruction_cost(inst) for inst in instructions))

        unconditional_rollback_idx = self.__unconditional_rollback_at(block, instructions)
        if unconditional_rollback_idx is not None:
            self.insert_at(block, instruction_len_sum[unconditional_rollback_idx],
                           Patch.from_function(self.arch.unconditional_restore_point_patch()))
            final_conditional_rollback_idx = None
        else:
            try:
                final_conditional_rollback_idx = (
                    next(i for i in range(len(instructions) - 1, -1, -1)
                         if self.__can_insert_restore_point(function, block, i)))
            except StopIteration:
                # Nowhere to insert this without clobbering flags, so just let it be and save the flags
                final_conditional_rollback_idx = len(instructions) - 1

        last_insertion_idx = 0
        insert_until_idx = final_conditional_rollback_idx \
            if unconditional_rollback_idx is None else unconditional_rollback_idx
        while insert_until_idx - last_insertion_idx > self.INSERTION_SPACING * 4 // 3:
            # In the last sub-block, allow a bit more than 50 instructions to be handled by the final rollback
            current_insertion_idx = last_insertion_idx + self.INSERTION_SPACING
            while (current_insertion_idx < insert_until_idx and
                   not self.__can_insert_restore_point(function, block, current_insertion_idx)):
                current_insertion_idx += 1
            if current_insertion_idx >= insert_until_idx:
                # No eligible intermediate point remains. The final point below
                # already has a flag-preserving fallback, so leave the rest of
                # this block to it instead of searching beyond the block forever.
                break

            self.__insert_conditional_restore_point(
                block, function, current_insertion_idx, instruction_len_sum[current_insertion_idx],
                instruction_cost_sum[current_insertion_idx] - instruction_cost_sum[last_insertion_idx])
            last_insertion_idx = current_insertion_idx

        if final_conditional_rollback_idx is not None:
            self.__insert_conditional_restore_point(
                block, function, final_conditional_rollback_idx, instruction_len_sum[final_conditional_rollback_idx],
                instruction_cost_sum[-1] - instruction_cost_sum[last_insertion_idx])

    def __insert_conditional_restore_point(self, block, function, instruction_idx, instruction_offset,
                                           instruction_count):
        if not self.arch.restore_point_patch_uses_live_registers():
            self.insert_at(block, instruction_offset, Patch.from_function(
                self.arch.conditional_restore_point_patch(instruction_count)))
            return

        patch = self.arch.conditional_restore_point_patch(instruction_count)
        if self.reg_manager is not None:
            patch = self.allocate_registers(
                function, block, instruction_idx)(patch)
        self.insert_at(block, instruction_offset, Patch.from_function(patch))

    def __can_insert_restore_point(self, function, block, instruction_idx) -> bool:
        live_registers = self.reg_manager.live_registers(function, block, instruction_idx) \
            if self.reg_manager is not None and self.arch.restore_point_patch_uses_live_registers() else None
        return self.arch.can_insert_restore_point(live_registers)

    def __unconditional_rollback_at(self, block: gtirb.CodeBlock, instructions: List[CsInsn]):
        unconditional_rollback_idx = next((i for i, instruction in enumerate(instructions)
                                           if self.arch.instruction_must_rollback(instruction)), None)
        if unconditional_rollback_idx is None:
            non_fallthrough_edges, _ = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                return None

            # The call may be a jmp because of tail-call optimization
            if (non_fallthrough_edges[0].label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch) and
                (isinstance(non_fallthrough_edges[0].target, gtirb.ProxyBlock) or
                 non_fallthrough_edges[0].target.section.name not in (self.text_section.name, self.transient_section.name)) and
                not self._targets_linked_component(block, instructions, non_fallthrough_edges[0])):
                # is a call to external library function, rollback
                unconditional_rollback_idx = len(instructions) - 1

        return unconditional_rollback_idx
