import gtirb
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, SingleBlockScope, FunctionPosition, BlockPosition)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn
from capstone_gt.x86 import X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE
from typing import List
import functools

from NaHCO3.utils.misc import distinguish_edges
from NaHCO3.config import CHECKPOINT_LIB_NAME, SYMBOL_SUFFIX


class TransientInsertRestorePointsPass(Pass):
    transient_section: gtirb.Section

    # Insert restore points about every 50 instructions, and before the end of each basic block
    INSERTION_SPACING = 50

    SERIALIZING_MNEMONICS = [
        "lfence", "mfence", "sfence", "serialize", "cpuid",
        "syscall", "sysenter"
    ]

    def __init__(self, transient_section: gtirb.Section):
        self.transient_section = transient_section
        self.decoder = GtirbInstructionDecoder(transient_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        conditional_restore_point_symbol = rewriting_ctx.get_or_insert_extern_symbol(
            "add_instruction_counter_check_restore", CHECKPOINT_LIB_NAME)
        unconditional_restore_point_symbol = rewriting_ctx.get_or_insert_extern_symbol(
            "restore_checkpoint", CHECKPOINT_LIB_NAME)

        rewriting_ctx.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT, {"main" + SYMBOL_SUFFIX}),
            Patch.from_function(self.__build_unconditional_restore_point_patch(unconditional_restore_point_symbol))
        )

        for block in self.transient_section.code_blocks:
            if block.size == 0:
                continue

            instructions: List[CsInsn] = list(self.decoder.get_instructions(block))

            insertion_offset = 0
            has_unconditional_rollback = False
            for i, instruction in enumerate(instructions):
                insertion_offset += instruction.size
                if self.__instruction_must_rollback(instruction):
                    rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                        self.__build_unconditional_restore_point_patch(unconditional_restore_point_symbol)))
                    has_unconditional_rollback = True
                    break
                elif i != 0 and i % self.INSERTION_SPACING == 0:
                    rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                        self.__build_conditional_restore_point_patch(
                            self.INSERTION_SPACING, conditional_restore_point_symbol)
                    ))

            if not has_unconditional_rollback:
                non_fallthrough_edges, fallthrough_edges = distinguish_edges(block.outgoing_edges)
                if len(non_fallthrough_edges) == 0:
                    continue

                if (non_fallthrough_edges[0].label.type == gtirb.EdgeType.Call and
                        non_fallthrough_edges[0].target.section.name != self.transient_section.name):
                    # is a call to external library function, rollback
                    rewriting_ctx.register_insert(
                        SingleBlockScope(block, BlockPosition.EXIT),
                        Patch.from_function(
                            self.__build_unconditional_restore_point_patch(unconditional_restore_point_symbol)))
                else:
                    rewriting_ctx.register_insert(
                        SingleBlockScope(block, BlockPosition.EXIT),
                        Patch.from_function(self.__build_conditional_restore_point_patch(
                            len(instructions) % self.INSERTION_SPACING,
                            conditional_restore_point_symbol))
                    )

    @classmethod
    def __instruction_must_rollback(cls, instruction: CsInsn) -> bool:
        if instruction.mnemonic in cls.SERIALIZING_MNEMONICS:
            return True

        if any(prefix in instruction.prefix for prefix in [X86_PREFIX_REP, X86_PREFIX_REPE, X86_PREFIX_REPNE]):
            return True

        return False

    @staticmethod
    def __build_conditional_restore_point_patch(instruction_count: int, restore_point_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            push {instruction_count}
            call {restore_point_symbol.name}
            lea rsp, [rsp+8]
        """)

    @staticmethod
    def __build_unconditional_restore_point_patch(restore_point_symbol: gtirb.Symbol):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            jmp {restore_point_symbol.name} 
        """)
