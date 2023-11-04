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
from capstone_gt import CsInsn, CS_OP_MEM, CS_AC_WRITE, CS_OP_REG
from capstone_gt.x86 import X86OpMem, X86_REG_INVALID, X86_REG_RSP, X86_REG_RIP, X86_REG_RBP
from typing import List, Set, Optional
import itertools

from NaHCO3.config import SYMBOL_SUFFIX, MODE, TAG_ATTACKER, TAG_SECRET
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.patch_helpers import (asan_check_snippet, dift_add_reg_tag_snippet, conditional_patch_wrapper,
                                  report_gadget_snippet)
from NaHCO3.utils.rewriting import mem_access_to_symbolic_str, get_cmov_conditional
from NaHCO3.utils.dift import reg_to_dift_reg_id


class TransientGadgetPolicyPass(InstVisitorPassMixin):
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
        if inst.mnemonic in ("lea", "nop", "ret", "push", "pop", "call") or inst.mnemonic.startswith("j"):
            return

        mem_operand = next(iter(x for x in inst.operands if x.type == CS_OP_MEM), None)
        if mem_operand is None:
            return

        if mem_operand.mem.base in (X86_REG_INVALID, X86_REG_RIP) and \
                mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID:
            return

        mem_operand_str = mem_access_to_symbolic_str(block, inst, mem_operand)
        access_size = mem_operand.size

        # Handle conditional moves
        conditional = get_cmov_conditional(inst)

        if MODE == "Kasper":
            write_operand = next(iter(x for x in inst.operands if x.access & CS_AC_WRITE), None)
            if write_operand == mem_operand or write_operand is None:
                return
            assert write_operand.type == CS_OP_REG

            patch = self.__build_asan_kasper_patch(inst, mem_operand_str, access_size,
                                                   conditional=conditional,
                                                   mem_operand=mem_operand.mem,
                                                   write_reg=self.reg_manager.abi.get_register(
                                                       inst.reg_name(write_operand.reg)))
        elif MODE == "SpecFuzz":
            # Do not instrument if base register is %rsp/%rbp and constant offset
            if mem_operand.mem.base in (X86_REG_RSP, X86_REG_RBP) and \
                    mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID:
                return

            patch = self.__build_asan_patch(inst, mem_operand_str, access_size, conditional=conditional)
        else:
            raise NotImplementedError

        self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(patch)))

    def __build_asan_kasper_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                                  conditional: Optional[str] = None, mem_operand: X86OpMem, write_reg: Register):
        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=3, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers
            base_reg = self.reg_manager.abi.get_register(inst.reg_name(mem_operand.base))
            index_reg = self.reg_manager.abi.get_register(inst.reg_name(mem_operand.index)) \
                if mem_operand.index != X86_REG_INVALID else None

            check_ok_label = f".L__kasper_check_ok{SYMBOL_SUFFIX}"

            asm = f"""
                lea {r2}, {mem_operand_str}
                xor {r1:8l}, {r1:8l}
            """

            asm += dift_add_reg_tag_snippet(r1, reg_add=base_reg)
            if index_reg is not None:
                asm += dift_add_reg_tag_snippet(r1, reg_add=index_reg)

            asm += f"""
                test {r1:8l}, {TAG_SECRET}
                jz .L__kasper_check_tag_attacker{SYMBOL_SUFFIX} 
            .L__kasper_tag_secret{SYMBOL_SUFFIX}:
                {report_gadget_snippet(r2, "KASPER")}
                jmp {check_ok_label}
            .L__kasper_check_tag_attacker{SYMBOL_SUFFIX}:
                test {r1:8l}, {TAG_ATTACKER}
                jz {check_ok_label}
                {asan_check_snippet(r2, access_size, check_ok_label,
                                    r1=r1, r2=r3)}
            .L__kasper_attacker_asan_check_fail{SYMBOL_SUFFIX}:
                {report_gadget_snippet(r2, "SPECFUZZ_ASAN")}
                or byte ptr dift_reg_tags+{reg_to_dift_reg_id(write_reg)}, {TAG_SECRET}
            {check_ok_label}:
                nop
            """

            asm = conditional_patch_wrapper(asm, conditional,
                                            label_key="kasper",
                                            skip_label_name=check_ok_label,
                                            insert_skip_label=False)
            return asm

        return patch

    @classmethod
    def __build_asan_patch(cls, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                           conditional: Optional[str] = None):
        scratch_registers = 3 if access_size < 8 else 2

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if access_size < 8:
                r1, r2, r3 = ctx.scratch_registers
            else:
                r1, r2 = ctx.scratch_registers
                r3 = None

            check_ok_label = f".L__asan_check_ok{SYMBOL_SUFFIX}"

            asm = f"""
                lea {r2}, {mem_operand_str}
                {asan_check_snippet(r2, access_size, check_ok_label,
                                    r1=r1, r2=r3)}
            .L__asan_check_fail{SYMBOL_SUFFIX}:
                {report_gadget_snippet(r2, "SPECFUZZ_ASAN")}
            {check_ok_label}:
                nop
            """

            asm = conditional_patch_wrapper(asm, conditional,
                                            label_key="asan",
                                            skip_label_name=check_ok_label,
                                            insert_skip_label=False)

            return asm

        return patch
