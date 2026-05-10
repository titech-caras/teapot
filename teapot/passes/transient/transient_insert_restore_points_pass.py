import gtirb
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, Patch, AllFunctionsScope, FunctionPosition, BlockPosition
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import NotEnoughFreeRegistersException
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
                 decoder: GtirbInstructionDecoder, arch: Architecture):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.text_section = text_section
        self.transient_section = transient_section
        self.arch = arch

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

        unconditional_rollback_idx = self.__unconditional_rollback_at(block, instructions)
        if unconditional_rollback_idx is not None:
            self.insert_at(block, instruction_len_sum[unconditional_rollback_idx],
                           Patch.from_function(self.arch.unconditional_restore_point_patch()))
            final_conditional_rollback_idx = None
        else:
            try:
                final_conditional_rollback_idx = (
                    next(i for i in range(len(instructions) - 1, -1, -1)
                         if self.arch.can_insert_restore_point(self.reg_manager, function, block, i)))
            except StopIteration:
                # Nowhere to insert this without clobbering flags, so just let it be and save the flags
                final_conditional_rollback_idx = len(instructions) - 1

        last_insertion_idx = 0
        insert_until_idx = final_conditional_rollback_idx \
            if unconditional_rollback_idx is None else unconditional_rollback_idx
        while insert_until_idx - last_insertion_idx > self.INSERTION_SPACING * 4 // 3:
            # In the last sub-block, allow a bit more than 50 instructions to be handled by the final rollback
            current_insertion_idx = last_insertion_idx + self.INSERTION_SPACING
            while not self.arch.can_insert_restore_point(self.reg_manager, function, block, current_insertion_idx):
                current_insertion_idx += 1

            self.__insert_conditional_restore_point(
                block, function, current_insertion_idx, instruction_len_sum[current_insertion_idx],
                current_insertion_idx - last_insertion_idx)
            last_insertion_idx = current_insertion_idx

        if final_conditional_rollback_idx is not None:
            self.__insert_conditional_restore_point(
                block, function, final_conditional_rollback_idx, instruction_len_sum[final_conditional_rollback_idx],
                len(instructions) - last_insertion_idx)

    def __insert_conditional_restore_point(self, block, function, instruction_idx, instruction_offset,
                                           instruction_count):
        if not self.arch.restore_point_patch_uses_live_registers():
            self.insert_at(block, instruction_offset, Patch.from_function(
                self.arch.conditional_restore_point_patch(instruction_count, False)))
            return

        patch = self.arch.conditional_restore_point_patch(instruction_count)
        if self.reg_manager is not None:
            try:
                patch = self.reg_manager.allocate_registers(
                    function, block, instruction_idx)(patch)
            except NotEnoughFreeRegistersException:
                patch = self.arch.conditional_restore_point_patch(instruction_count, False)
        self.insert_at(block, instruction_offset, Patch.from_function(patch))

    def __unconditional_rollback_at(self, block: gtirb.CodeBlock, instructions: List[CsInsn]):
        unconditional_rollback_idx = next((i for i, instruction in enumerate(instructions)
                                           if self.arch.instruction_must_rollback(instruction)), None)
        if unconditional_rollback_idx is None:
            non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
            if len(non_fallthrough_edges) == 0:
                return None

            # The call may be a jmp because of tail-call optimization
            if (non_fallthrough_edges[0].label.type in (gtirb.EdgeType.Call, gtirb.EdgeType.Branch) and
                (isinstance(non_fallthrough_edges[0].target, gtirb.ProxyBlock) or
                 non_fallthrough_edges[0].target.section.name not in (self.text_section.name, self.transient_section.name))):
                # is a call to external library function, rollback
                unconditional_rollback_idx = len(instructions) - 1

        return unconditional_rollback_idx
