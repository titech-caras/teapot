from typing import Optional

import gtirb
from capstone_gt import CS_AC_WRITE, CsInsn
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.tags import (
    TAG_ATTACKER,
    TAG_ATTACKER_INDIRECT,
    TAG_SECRET,
    TAG_SECRET_INDIRECT,
)
from teapot.passes.transient.gadget_policy.mem_operand.base import (
    MemOperandPolicyPatch,
    TransientMemOperandPoliciesPassBase,
)


class X64TransientMemOperandPoliciesPass(TransientMemOperandPoliciesPassBase):
    EXPECTED_ARCH = "x64"

    def _build_policy_patch(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                            block: gtirb.CodeBlock, function: Function = None):
        if inst.mnemonic in ("lea", "nop", "ret", "push", "pop", "call") or inst.mnemonic.startswith("j"):
            return None

        mem_operand = self.arch.memory_operand(inst)
        if mem_operand is None:
            return None

        write_operand = next(iter(x for x in inst.operands if x.access & CS_AC_WRITE), None)
        if write_operand is None or write_operand == mem_operand:
            return None

        if not self.arch.mem_operand_uses_dynamic_address(mem_operand):
            return None

        mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
        patch = self._build_patch(
            inst, mem_operand_str, mem_operand.size,
            conditional=self.arch.conditional_move_suffix(inst), mem_operand=mem_operand,
            write_reg=self.reg_manager.abi.get_register(inst.reg_name(write_operand.reg)))
        return MemOperandPolicyPatch(patch, set())

    def _build_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                     conditional: Optional[str], mem_operand, write_reg: Register):
        if access_size > 8:
            scratch_registers = 5
        elif access_size < 8:
            scratch_registers = 4
        else:
            scratch_registers = 3
        addr_regs = self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            if access_size > 8:
                r1, r2, r3, r4, r5 = ctx.scratch_registers
            elif access_size < 8:
                r1, r2, r3, r4 = ctx.scratch_registers
                r5 = None
            else:
                r1, r2, r3 = ctx.scratch_registers
                r4 = None
                r5 = None

            asm = f"""
                lea {r2}, {mem_operand_str}
                {self.arch.clear_register_snippet(r1)}
            """

            for reg in addr_regs:
                asm += self.arch.dift_or_reg_tag_snippet(r1, None, reg)

            done_label = f".L__mem_operand_policy_done{SYMBOL_SUFFIX}"
            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz .L__attacker_tags_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_CACHE", addr_reg=r2, tag_reg=r1)}

            .L__attacker_tags_check{SYMBOL_SUFFIX}:
                test {r1:8l}, {TAG_ATTACKER_INDIRECT}
                jz .L__asan_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {self.arch.dift_queue_reg_tag_snippet(None, None, TAG_SECRET_INDIRECT, write_reg)}

            .L__asan_check{SYMBOL_SUFFIX}:
                {self.arch.asan_check_snippet(
                    r2, access_size, done_label,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    shadow_reg=r3, scratch_reg=r4, end_reg=r5)
                 if self.enable_asan_check else f"jmp {done_label}"}
            .L__asan_check_fail{SYMBOL_SUFFIX}:
                test {r1:8l}, {TAG_ATTACKER}
                jz .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}
            .L__asan_check_fail_attacker{SYMBOL_SUFFIX}:
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {self.arch.dift_queue_reg_tag_snippet(None, None, TAG_SECRET, write_reg)}
                jmp {done_label}
            .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}:
                {self.arch.dift_queue_reg_tag_snippet(None, None, TAG_ATTACKER_INDIRECT, write_reg)}
            {done_label}:
                nop
            """

            return self.arch.conditional_patch_wrapper(
                asm, conditional, label_key="mem_operand_policies",
                skip_label_name=done_label, insert_skip_label=False)

        return patch
