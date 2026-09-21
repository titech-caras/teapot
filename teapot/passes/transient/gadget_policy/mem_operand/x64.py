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
        if self.arch.rep_string_kind(inst) is not None:
            return None
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

        write_reg = self.arch.register_from_name(
            self.reg_manager.abi, inst.reg_name(write_operand.reg))
        if write_reg is None:
            # The x64 ABI/DIFT register map intentionally covers GPRs and XMM
            # registers, but not AVX-512 mask registers such as k0.  The main
            # DIFT pass already omits such unsupported destinations; keep the
            # memory-operand policy consistent instead of failing the rewrite.
            return None

        mem_operand_str = self.arch.mem_operand_to_str(block, inst, mem_operand)
        patch = self._build_patch(
            inst, mem_operand_str, mem_operand.size,
            conditional=self.arch.conditional_move_suffix(inst), mem_operand=mem_operand,
            write_reg=write_reg)
        return MemOperandPolicyPatch(patch, set())

    def _build_patch(self, inst: CsInsn, mem_operand_str: str, access_size: int, *,
                     conditional: Optional[str], mem_operand, write_reg: Optional[Register] = None,
                     queued_tag_operand=None, label_key="mem_operand_policy"):
        scratch_registers = (5 if access_size > 1 else 4) if self.enable_asan_check else 3
        addr_regs = self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)
        # A string load can feed memory or a comparison instead of a GPR. Its
        # per-element queue is consumed by the REP propagation kernel.
        queue_tags = {
            tag: (self.arch.dift_queue_reg_tag_snippet(None, None, tag, write_reg)
                  if write_reg is not None else f"or byte ptr {queued_tag_operand}, {tag}\n")
            for tag in (TAG_SECRET_INDIRECT, TAG_SECRET, TAG_ATTACKER_INDIRECT)
        }

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r1, r2, r3 = ctx.scratch_registers[:3]
            r4 = ctx.scratch_registers[3] if scratch_registers > 3 else None
            r5 = ctx.scratch_registers[4] if scratch_registers > 4 else None

            asm = self.arch.effective_address_snippet(r2, mem_operand_str, r3)
            asm += self.arch.clear_register_snippet(r1)

            for reg in addr_regs:
                asm += self.arch.dift_or_reg_tag_snippet(r1, None, reg)

            label = f".L__{label_key}{SYMBOL_SUFFIX}"
            done_label = f"{label}_done"
            asm += f"""
                test {r1:8l}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                jz {label}_attacker_tags_check
                {self.arch.report_gadget_snippet("KASPER_CACHE", addr_reg=r2, tag_reg=r1)}

            {label}_attacker_tags_check:
                test {r1:8l}, {TAG_ATTACKER_INDIRECT}
                jz {label}_asan_check
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {queue_tags[TAG_SECRET_INDIRECT]}

            {label}_asan_check:
                {self.arch.asan_check_snippet(
                    r2, access_size, done_label,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    shadow_reg=r3, scratch_reg=r4, end_reg=r5)
                 if self.enable_asan_check else f"jmp {done_label}"}
            {label}_asan_check_fail:
                test {r1:8l}, {TAG_ATTACKER}
                jz {label}_asan_check_fail_non_attacker
            {label}_asan_check_fail_attacker:
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg=r2, tag_reg=r1)}
                {queue_tags[TAG_SECRET]}
                jmp {done_label}
            {label}_asan_check_fail_non_attacker:
                {queue_tags[TAG_ATTACKER_INDIRECT]}
            {done_label}:
                nop
            """

            return self.arch.conditional_patch_wrapper(
                asm, conditional, label_key="mem_operand_policies",
                skip_label_name=done_label, insert_skip_label=False)

        return patch
