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
from capstone_gt import CsInsn, CS_OP_MEM
from typing import List, Set
import itertools

from NaHCO3.config import ASAN_SHADOW_OFFSET
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.utils.misc import distinguish_edges


class TransientAsanPass(InstVisitorPassMixin):
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
        if inst.mnemonic == "lea" or inst.mnemonic == "nop" or inst.mnemonic == "call":
            return

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None)
        if mem_operand is None:
            return

        # Do not instrument if base register is %rsp/%rbp and constant offset
        if mem_operand.mem.base in (capstone_gt.x86.X86_REG_RSP, capstone_gt.x86.X86_REG_RBP) and \
                mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID:
            return

        try:
            symexp = operand_symbolic_expression(block, inst, mem_operand)
            if symexp is not None and any(s.name == "scratchpad" for s in symexp.symbols):
                # write to the scratchpad in previous instrumentation, quit
                return

            if int(ASAN_SHADOW_OFFSET, 16) == mem_operand.mem.disp:
                # Do not check for stack poisoning
                return

            mem_operand_str = mem_access_to_str(inst, mem_operand.mem, symexp)
        except NotImplementedError:
            print(f"Warning: unsupported symexp at {inst}")
            mem_operand_str = mem_access_to_str(inst, mem_operand.mem, None)

        self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(
                self.__build_asan_check_patch(inst, mem_operand_str, mem_operand.size)
            )
        ))

    def __build_asan_check_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int):
        # FIXME: this actually clobbers flags! (seems like it's usually ok though?)
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3, clobbers_flags=False)
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
                    jnb .L__asan_check_ok
                """

            # FIXME: SpecFuzz actually continues to execute after Asan trigger
            # FIXME: report gadget, skip the read & write operation, and continue execution if possible
            return f"""
                lea {r2}, {mem_operand_str}
                mov {r1}, {r2}
                shr {r1}, 3
                mov {r1_shadow_subreg}, [{r1}+{ASAN_SHADOW_OFFSET}]
                test {r1_shadow_subreg}, {r1_shadow_subreg}
                je .L__asan_check_ok
                {detailed_check_snippet}
            .L__asan_check_fail:
                mov rsi, {r2}
                lea rdi, [rip]
                jmp report_gadget_specfuzz
            .L__asan_check_ok:
                nop
            """

        return patch
