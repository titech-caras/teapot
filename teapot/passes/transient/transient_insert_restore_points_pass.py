import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, SingleBlockScope, FunctionPosition, BlockPosition)
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis import LiveRegisterManager
from capstone_gt import CsInsn
from capstone_gt.x86 import X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE
from typing import List
import functools
import itertools

from teapot.passes.mixins import VisitorPassMixin, RegInstAwarePassMixin
from teapot.utils.misc import distinguish_edges
from teapot.config import SYMBOL_SUFFIX, ROB_LEN


class TransientInsertRestorePointsPass(VisitorPassMixin, RegInstAwarePassMixin):
    reg_manager: LiveRegisterManager
    text_section: gtirb.Section
    transient_section: gtirb.Section

    # Insert restore points about every 50 instructions, and before the end of each basic block
    INSERTION_SPACING = 50

    SERIALIZING_MNEMONICS = [
        "lfence", "mfence", "sfence", "serialize", "cpuid",
        "syscall", "sysenter"
    ]

    def __init__(self, reg_manager: LiveRegisterManager,
                 text_section: gtirb.Section, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder):
        RegInstAwarePassMixin.__init__(self, reg_manager, decoder)
        self.text_section = text_section
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        VisitorPassMixin.begin_module(self, module, functions, rewriting_ctx)
        rewriting_ctx.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main" + SYMBOL_SUFFIX}),
            Patch.from_function(self.__build_unconditional_restore_point_patch())
        )

        self.visit_functions(functions, self.transient_section)

    def visit_function(self, function: Function):
        self.reg_manager.analyze(function)
        VisitorPassMixin.visit_function(self, function)

    def visit_code_block(self, block: gtirb.CodeBlock, function: Function = None):
        instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
        instruction_len_sum: List[int] = [0] + list(itertools.accumulate(i.size for i in instructions))

        unconditional_rollback_idx = self.__unconditional_rollback_at(block, instructions)
        if unconditional_rollback_idx is not None:
            self.rewriting_ctx.insert_at(block, instruction_len_sum[unconditional_rollback_idx],
                                         Patch.from_function(self.__build_unconditional_restore_point_patch()))
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
            while not self.__can_insert_restore_point(function, block, current_insertion_idx):
                current_insertion_idx += 1

            self.rewriting_ctx.insert_at(
                block,
                instruction_len_sum[current_insertion_idx],
                Patch.from_function(
                    self.reg_manager.allocate_registers(function, block, current_insertion_idx)(
                        self.__build_conditional_restore_point_patch(current_insertion_idx - last_insertion_idx)
                    )))
            last_insertion_idx = current_insertion_idx

        if final_conditional_rollback_idx is not None:
            self.rewriting_ctx.insert_at(
                block,
                instruction_len_sum[final_conditional_rollback_idx],
                Patch.from_function(
                    self.reg_manager.allocate_registers(function, block, final_conditional_rollback_idx)(
                        self.__build_conditional_restore_point_patch(len(instructions) - last_insertion_idx)
                    )))

    def __can_insert_restore_point(self, function, block, instruction_idx) -> bool:
        return "rflags" not in (r.name for r in self.reg_manager.live_registers(function, block, instruction_idx))

    def __unconditional_rollback_at(self, block: gtirb.CodeBlock, instructions: List[CsInsn]):
        unconditional_rollback_idx = next((i for i, instruction in enumerate(instructions)
                                           if self.__instruction_must_rollback(instruction)), None)
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

    @classmethod
    def __instruction_must_rollback(cls, instruction: CsInsn) -> bool:
        if instruction.mnemonic in cls.SERIALIZING_MNEMONICS:
            return True

        if instruction.mnemonic.startswith("rep"):
            return True

        # why doesn't this work?
        #if any(prefix in instruction.prefix for prefix in [X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE]):
        #    return True

        return False

    def __build_conditional_restore_point_patch(self, instruction_count: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0]
            return f"""
                mov {r}, instruction_cnt
                add {r}, {instruction_count}
                cmp {r}, {ROB_LEN}
                jge restore_checkpoint_ROB_LEN
                mov instruction_cnt, {r}
            """

        return patch

    def __build_unconditional_restore_point_patch(self):
        @patch_constraints(x86_syntax=X86Syntax.INTEL)
        def patch(ctx: InsertionContext):
            # FIXME: also serializing mnemonics
            return f"jmp restore_checkpoint_EXT_LIB"

        return patch
