import capstone_gt.x86
import gtirb
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax
from gtirb_capstone.instructions import GtirbInstructionDecoder
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE
from capstone_gt.x86 import X86_AVX_CC_INVALID, X86_SSE_CC_INVALID
from typing import Iterable
from uuid import UUID
import functools


from NaHCO3.config import CHECKPOINT_LIB_NAME


class TransientInsertMemoryLogsPass(Pass):
    transient_section: gtirb.Section

    def __init__(self, transient_section: gtirb.Section):
        self.transient_section = transient_section
        self.decoder = GtirbInstructionDecoder(transient_section.module.isa)

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext):
        rewriting_ctx.get_or_insert_extern_symbol("register_scratchpad", "")
        rewriting_ctx.get_or_insert_extern_symbol("memory_history_top", "")

        for block in self.transient_section.code_blocks:
            if block.size == 0:
                continue

            instructions: Iterable[CsInsn] = self.decoder.get_instructions(block)
            insertion_offset = 0
            for instruction in instructions:
                mem_write_operand = [x for x in instruction.operands if x.type == CS_OP_MEM and x.access & CS_AC_WRITE]
                if len(mem_write_operand) != 0:
                    if instruction.avx_cc == X86_AVX_CC_INVALID and instruction.sse_cc == X86_SSE_CC_INVALID:
                        # Memory operand is under or equal to 64 bits
                        rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                            self.__build_memory_log_patch(
                                self.__print_mem_operand(instruction, mem_write_operand[0].mem)
                            )))
                    else:
                        # AVX/SSE memory operand
                        # TODO: support AVX instructions
                        pass
                elif instruction.mnemonic == "push" or instruction.mnemonic == "call":
                    rewriting_ctx.insert_at(block, insertion_offset, Patch.from_function(
                        self.__build_memory_log_patch("[rsp - 8]")))

                insertion_offset += instruction.size


    @staticmethod
    def __print_mem_operand(instruction: CsInsn, operand: capstone_gt.x86.X86OpMem) -> str:
        need_sign = False
        s = "["

        if operand.base:
            s += instruction.reg_name(operand.base)
            need_sign = True

        if operand.index:
            if need_sign:
                s += "+"
            s += f"{instruction.reg_name(operand.index)}*{operand.scale}"
            need_sign = True

        if operand.disp:
            if need_sign:
                s += "+" if operand.disp > 0 else "-"
            s += f"{abs(operand.disp)}"

        s += "]"

        return s

    @staticmethod
    def __build_memory_log_patch(mem_operand: str):
        return patch_constraints(x86_syntax=X86Syntax.INTEL)(lambda ctx: f"""
            mov [register_scratchpad + 88], r11
            mov [register_scratchpad + 96], r12
            lea r11, {mem_operand}
            mov r12, [memory_history_top]
            mov [r12], r11
            mov r11, [r11]
            mov [r12 + 8], r11
            lea r12, [r12 + 16]
            mov memory_history_top, r12            
            mov r11, [register_scratchpad + 88]
            mov r12, [register_scratchpad + 96]    
        """)

