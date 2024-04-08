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

from NaHCO3.config import SYMBOL_SUFFIX, TAG_ATTACKER, TAG_SECRET, TAG_SECRET_NON_CONTROLLED
from NaHCO3.passes.mixins import InstVisitorPassMixin
from NaHCO3.patch_helpers import (asan_check_snippet, dift_add_reg_tag_snippet, conditional_patch_wrapper,
                                  report_gadget_snippet)
from NaHCO3.utils.rewriting import mem_access_to_symbolic_str, get_cmov_conditional
from NaHCO3.utils.dift import reg_to_dift_reg_id


class TransientMemOperandPoliciesPass(InstVisitorPassMixin):
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

        write_operand = next(iter(x for x in inst.operands if x.access & CS_AC_WRITE), None)
        if write_operand is None:
            return
        is_mem_write = write_operand == mem_operand

        if mem_operand.mem.base in (X86_REG_INVALID, X86_REG_RIP) and \
                mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID:
            return

        mem_operand_str = mem_access_to_symbolic_str(block, inst, mem_operand)
        access_size = mem_operand.size

        # Handle conditional moves
        conditional = get_cmov_conditional(inst)

        patch = self.__build_mem_policies_patch(
            inst, mem_operand_str, access_size,
            is_mem_write=is_mem_write, conditional=conditional, mem_operand=mem_operand.mem,
            write_reg=self.reg_manager.abi.get_register(inst.reg_name(write_operand.reg)) if not is_mem_write else None)

        self.rewriting_ctx.insert_at(block, inst_offset, Patch.from_function(
            self.reg_manager.allocate_registers(function, block, inst_idx)(patch)))

    def __build_mem_policies_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                                        is_mem_write: bool, conditional: Optional[str] = None,
                                        mem_operand: X86OpMem, write_reg: Optional[Register]):
        assert is_mem_write or write_reg
        scratch_registers = 4 if access_size < 8 else 3

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if access_size < 8:
                r1, r2, r3, r4 = ctx.scratch_registers
            else:
                r1, r2, r3 = ctx.scratch_registers
                r4 = None

            base_reg = self.reg_manager.abi.get_register(inst.reg_name(mem_operand.base)) \
                if mem_operand.base != X86_REG_INVALID else None
            index_reg = self.reg_manager.abi.get_register(inst.reg_name(mem_operand.index)) \
                if mem_operand.index != X86_REG_INVALID else None

            check_ok_label = f".L__check_ok{SYMBOL_SUFFIX}"

            asm = f"""
                lea {r2}, {mem_operand_str}
                xor {r1:8l}, {r1:8l}
            """

            if base_reg is not None:
                asm += dift_add_reg_tag_snippet(r1, reg_add=base_reg)
            if index_reg is not None:
                asm += dift_add_reg_tag_snippet(r1, reg_add=index_reg)

            if not is_mem_write:
                asm += f"""
                    test {r1:8l}, {TAG_SECRET_NON_CONTROLLED}
                    jnz .L__tag_spectaint_secret{SYMBOL_SUFFIX}
                    test {r1:8l}, {TAG_SECRET}
                    jz .L__asan_check{SYMBOL_SUFFIX}
                .L__tag_secret{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "KASPER_CACHE")}
                    jmp .L__asan_check{SYMBOL_SUFFIX}
                .L__tag_spectaint_secret{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "SPECTAINT_BCB")}
                .L__asan_check{SYMBOL_SUFFIX}:
                    {asan_check_snippet(r2, access_size, check_ok_label, r1=r3, r2=r4)}
                .L__asan_check_fail{SYMBOL_SUFFIX}:
                    test {r1:8l}, {TAG_ATTACKER}
                    jnz .L__asan_check_fail_attacker{SYMBOL_SUFFIX}
                .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "SPECFUZZ_ASAN_READ")}
                    or byte ptr dift_reg_tags+{reg_to_dift_reg_id(write_reg)}, {TAG_SECRET_NON_CONTROLLED}
                    jmp {check_ok_label}    
                .L__asan_check_fail_attacker{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "KASPER_MDS")}
                    or byte ptr dift_reg_tags+{reg_to_dift_reg_id(write_reg)}, {TAG_SECRET}
                {check_ok_label}:
                    nop
                """
            else:
                asm += f"""
                    {asan_check_snippet(r2, access_size, check_ok_label, r1=r3, r2=r4)}
                .L__asan_check_fail{SYMBOL_SUFFIX}:
                    test {r1:8l}, {TAG_ATTACKER}
                    jnz .L__asan_check_fail_attacker{SYMBOL_SUFFIX}
                .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "SPECFUZZ_ASAN_WRITE")}
                    jmp {check_ok_label}
                .L__asan_check_fail_attacker{SYMBOL_SUFFIX}:
                    {report_gadget_snippet(r2, "SPECTAINT_BCBS")}
                {check_ok_label}:
                    nop
                """

            asm = conditional_patch_wrapper(asm, conditional,
                                            label_key="mem_read_policies",
                                            skip_label_name=check_ok_label,
                                            insert_skip_label=False)
            return asm

        return patch
