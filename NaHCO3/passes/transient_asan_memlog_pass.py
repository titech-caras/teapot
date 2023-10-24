import random

import capstone_gt.x86
import gtirb
from gtirb_functions import Function
from gtirb_rewriting import (Pass, RewritingContext, Patch, patch_constraints,
                             AllFunctionsScope, FunctionPosition, BlockPosition, InsertionContext)
from gtirb_rewriting.patches import CallPatch
from gtirb_rewriting.assembly import X86Syntax, Register
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE
from typing import List, Set
import itertools

from NaHCO3.config import ASAN_SHADOW_OFFSET, SYMBOL_SUFFIX
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.utils.misc import distinguish_edges, generate_distinct_label_name
from NaHCO3.utils.rewriting import reconstruct_instruction_str


class TransientAsanMemlogPass(InstVisitorPassMixin):
    transient_section: gtirb.Section

    def __init__(self, reg_manager: LiveRegisterManager, transient_section: gtirb.Section,
                 decoder: GtirbInstructionDecoder):
        super().__init__(reg_manager, decoder)
        self.transient_section = transient_section

    def begin_module(self, module: gtirb.Module, functions, rewriting_ctx: RewritingContext) -> None:
        super().begin_module(module, functions, rewriting_ctx)

        self.visit_functions(functions, self.transient_section)

    def visit_inst(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                   block: gtirb.CodeBlock, function: Function = None,
                   live_registers: Set[Register] = None):
        if inst.mnemonic in ("lea", "nop", "ret") or inst.mnemonic.startswith("j"):
            # Do not inspect control flow transfers here. For call, we only handle it like a stack push.
            return

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None)
        if inst.mnemonic == "push" or inst.mnemonic == "call":
            asan_instrument = False
            memlog_instrument = True
            mem_operand_str = "[rsp-8]"
            access_size = 8
        elif mem_operand is not None:
            # Workaround for capstone: capstone doesn't correctly identify accesses for
            # a lot of SSE/AVX instructions, so we conservatively identify all first
            # SSE/AVX memory operands as being written.
            is_write = (mem_operand.access & CS_AC_WRITE or
                        (inst.operands[0] == mem_operand and inst.operands[0].size > 8))

            asan_instrument = True
            memlog_instrument = is_write

            # Do not instrument if base register is %rsp/%rbp and constant offset
            if mem_operand.mem.base in (capstone_gt.x86.X86_REG_RSP, capstone_gt.x86.X86_REG_RBP) and \
                    mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID:
                asan_instrument = False

            symexp = operand_symbolic_expression(block, inst, mem_operand)
            if symexp is not None and any(s.name in ("old_rsp", "scratchpad") for s in symexp.symbols):
                # write to the scratchpad in previous instrumentation, don't instrument at all
                return

            if int(ASAN_SHADOW_OFFSET, 16) == mem_operand.mem.disp:
                # Do not check asan for stack poisoning
                asan_instrument = False

            try:
                mem_operand_str = mem_access_to_str(inst, mem_operand.mem, symexp)
            except NotImplementedError:
                print(f"Warning: unsupported symexp at {inst}")
                mem_operand_str = mem_access_to_str(inst, mem_operand.mem, None)

            access_size = mem_operand.size
        else:
            return

        if asan_instrument:
            self.rewriting_ctx.replace_at(block, inst_offset, inst.size, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self.__build_asan_patch(inst, mem_operand_str, access_size,
                                            reconstruct_instruction_str(block, inst), memlog_instrument))))
        elif memlog_instrument:
            self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
                self.reg_manager.allocate_registers(function, block, inst_idx)(
                    self.__build_memlog_patch(inst, mem_operand_str, access_size))))

    @staticmethod
    def __build_memlog_patch(inst: CsInsn, mem_operand_str: str, access_size: int):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3)
        def memlog_patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            store_instructions = ""
            for i in range(0, access_size, 8):
                store_instructions += f"""
                    mov {r3}, [{r2}]
                    mov [{r1}], {r2}
                    mov [{r1} + 8], {r3}
                    lea {r1}, [{r1} + 16]
                    lea {r2}, [{r2} + 8]
                    """

            return f"""
                lea {r2}, {mem_operand_str}
                mov {r1}, [memory_history_top]
                {store_instructions}
                mov memory_history_top, {r1}
            """

        return memlog_patch

    @classmethod
    def __build_asan_patch(cls, inst: CsInsn, mem_operand_str: str, access_size: int, inst_str: str, with_memlog_instrument: bool):
        reads_registers = set([inst.reg_name(r) for r in inst.regs_access()[0] + inst.regs_access()[1]])

        # this actually clobbers flags! (seems like it's usually ok though?)
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3, reads_registers=reads_registers)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers

            r1_shadow_subreg = r1.sizes["8l" if access_size <= 8 else str(access_size)]

            detailed_check_snippet = ""
            if access_size < 8:
                detailed_check_snippet += f"""
                    mov {r3:8l}, {r2:8l}
                    and {r3:8l}, 7 
                """

                if access_size > 1:
                    detailed_check_snippet += f"add {r3:8l}, {access_size - 1}\n"

                detailed_check_snippet += f"""
                    cmp {r3:8l}, {r1_shadow_subreg}
                    jnb .L__asan_check_ok{SYMBOL_SUFFIX}
                """

            return f"""
                lea {r2}, {mem_operand_str}
                mov {r1}, {r2}
                shr {r1}, 3
                mov {r1_shadow_subreg}, [{r1}+{ASAN_SHADOW_OFFSET}]
                test {r1_shadow_subreg}, {r1_shadow_subreg}
                je .L__asan_check_ok{SYMBOL_SUFFIX}
                {detailed_check_snippet}
            .L__asan_check_fail{SYMBOL_SUFFIX}:
                mov old_rsp, rsp
                lea rsp, scratchpad+1048568
                mov scratchpad, rsi
                mov scratchpad+8, rdi
                mov rsi, {r2}
                lea rdi, [rip]
                call report_gadget_specfuzz_asan
                mov rdi, scratchpad+8
                mov rsi, scratchpad
                mov rsp, old_rsp
                jmp .L__asan_memop_skip{SYMBOL_SUFFIX}
            .L__asan_check_ok{SYMBOL_SUFFIX}:
                {cls.__build_memlog_patch(inst, mem_operand_str, access_size)(ctx) if with_memlog_instrument else ""}
                {inst_str}
            .L__asan_memop_skip{SYMBOL_SUFFIX}:
                nop
            """

        return patch
