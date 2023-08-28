import gtirb
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from typing import List
from uuid import UUID
import functools


from NaHCO3.config import CHECKPOINT_LIB_NAME


class TransientInsertRestorePointsPass(Pass):
    transient_section: gtirb.Section

    INSERTION_SPACING = 50

    def __init__(self, transient_section: gtirb.Section):
        self.transient_section = transient_section
        self.decoder = GtirbInstructionDecoder(transient_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        restore_point_symbol = rewriting_ctx.get_or_insert_extern_symbol(
            "add_instruction_counter_check_restore", CHECKPOINT_LIB_NAME)
        for block in self.transient_section.code_blocks:
            if block.size == 0:
                continue

            instructions: List[CsInsn] = list(self.decoder.get_instructions(block))

            # Insert restore points about every 50 instructions, and before the end of each basic block
            restore_point_count = max(1, round(len(instructions) / self.INSERTION_SPACING))

            last_insertion_offset = 0
            for i in range(restore_point_count - 1):
                insertion_offset = last_insertion_offset + functools.reduce(
                    lambda x, i: x + i.size,
                    instructions[i * self.INSERTION_SPACING : (i + 1) * self.INSERTION_SPACING],
                    0)
                rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                    self.__build_restore_point_patch(self.INSERTION_SPACING, restore_point_symbol)
                ))
                last_insertion_offset = insertion_offset

            insertion_offset = last_insertion_offset + functools.reduce(
                lambda x, i: x + i.size,
                instructions[(restore_point_count - 1) * self.INSERTION_SPACING:-1],
                0)
            rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                self.__build_restore_point_patch(
                    len(instructions) - (restore_point_count - 1) * self.INSERTION_SPACING, restore_point_symbol)
            ))


    @staticmethod
    def __build_restore_point_patch(instruction_count: int, restore_point_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            push {instruction_count}
            call {restore_point_symbol.name}
            lea rsp, [rsp+8]
        """)
