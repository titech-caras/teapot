import gtirb
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

from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import CHECKPOINT_LIB_NAME, SYMBOL_SUFFIX, ROB_LEN


class TransientInsertRestorePointsPass(Pass):
    reg_manager: LiveRegisterManager
    transient_section: gtirb.Section

    # Insert restore points about every 50 instructions, and before the end of each basic block
    INSERTION_SPACING = 50

    SERIALIZING_MNEMONICS = [
        "lfence", "mfence", "sfence", "serialize", "cpuid",
        "syscall", "sysenter"
    ]

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section):
        self.reg_manager = reg_manager
        self.transient_section = transient_section
        self.decoder = GtirbInstructionDecoder(transient_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        rewriting_ctx.get_or_insert_extern_symbol("instruction_cnt", "")
        self.restore_checkpoint_symbol = rewriting_ctx.get_or_insert_extern_symbol(
            "restore_checkpoint", CHECKPOINT_LIB_NAME)

        rewriting_ctx.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main" + SYMBOL_SUFFIX}),
            Patch.from_function(self.__build_unconditional_restore_point_patch())
        )

        for function in functions:
            if next(iter(function.get_entry_blocks())).section.name != self.transient_section.name:
                continue
            self.reg_manager.analyze(function)

            for block in function.get_all_blocks():
                instructions: List[CsInsn] = list(self.decoder.get_instructions(block))
                instruction_len_sum: List[int] = [0] + list(itertools.accumulate(i.size for i in instructions))

                unconditional_rollback_idx = self.__unconditional_rollback_at(block, instructions)
                if unconditional_rollback_idx is not None:
                    rewriting_ctx.insert_at(block, instruction_len_sum[unconditional_rollback_idx],
                                            Patch.from_function(self.__build_unconditional_restore_point_patch()))
                    final_conditional_rollback_idx = None
                else:
                    final_conditional_rollback_idx = (
                        next(i for i in range(len(instructions) - 1, -1, -1)
                             if self.__can_insert_checkpoint(function, block, i)))
                    assert final_conditional_rollback_idx is not None

                last_insertion_idx = 0
                insert_until_idx = unconditional_rollback_idx or final_conditional_rollback_idx
                while insert_until_idx - last_insertion_idx > self.INSERTION_SPACING * 4 // 3:
                    # In the last sub-block, allow a bit more than 50 instructions to be handled by the final rollback
                    current_insertion_idx = last_insertion_idx + self.INSERTION_SPACING
                    while not self.__can_insert_checkpoint(function, block, current_insertion_idx):
                        current_insertion_idx += 1

                    rewriting_ctx.insert_at(
                        block,
                        instruction_len_sum[current_insertion_idx],
                        Patch.from_function(
                            self.reg_manager.allocate_registers(function, block, current_insertion_idx, False)(
                                self.__build_conditional_restore_point_patch(current_insertion_idx - last_insertion_idx)
                            )))
                    last_insertion_idx = current_insertion_idx

                if final_conditional_rollback_idx is not None:
                    rewriting_ctx.insert_at(
                        block,
                        instruction_len_sum[final_conditional_rollback_idx],
                        Patch.from_function(
                            self.reg_manager.allocate_registers(function, block, final_conditional_rollback_idx)(
                                self.__build_conditional_restore_point_patch(len(instructions) - last_insertion_idx)
                            )))

    def __can_insert_checkpoint(self, function, block, instruction_idx) -> bool:
        return "rflags" not in (r.name for r in self.reg_manager.live_registers(function, block, instruction_idx))

    def __unconditional_rollback_at(self, block: gtirb.CodeBlock, instructions: List[CsInsn]):
        unconditional_rollback_idx = next((i for i, instruction in enumerate(instructions)
                                           if self.__instruction_must_rollback(instruction)), None)
        if unconditional_rollback_idx is None:
            non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
            if (len(non_fallthrough_edges) > 0 and
                    non_fallthrough_edges[0].label.type == gtirb.EdgeType.Call and
                    non_fallthrough_edges[0].target.section.name != self.transient_section.name):
                # is a call to external library function, rollback before the call instruction
                unconditional_rollback_idx = len(instructions) - 1

        return unconditional_rollback_idx

    @classmethod
    def __instruction_must_rollback(cls, instruction: CsInsn) -> bool:
        if instruction.mnemonic in cls.SERIALIZING_MNEMONICS:
            return True

        if any(prefix in instruction.prefix for prefix in [X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE]):
            return True

        return False

    def __build_conditional_restore_point_patch(self, instruction_count: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0]
            return f"""
                mov {r}, instruction_cnt
                add {r}, {instruction_count}
                cmp {r}, {ROB_LEN}
                jge {self.restore_checkpoint_symbol.name}
                mov instruction_cnt, {r}
            """

        return patch

    def __build_unconditional_restore_point_patch(self):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1)
        def patch(ctx: InsertionContext):
            return f"jmp {self.restore_checkpoint_symbol.name}"

        return patch
