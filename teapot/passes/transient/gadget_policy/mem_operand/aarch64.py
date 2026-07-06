from typing import Optional

import gtirb
from capstone_gt import CsInsn
from gtirb_functions import Function
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

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


class AArch64TransientMemOperandPoliciesPass(TransientMemOperandPoliciesPassBase):
    EXPECTED_ARCH = "aarch64"

    def _build_policy_patch(self, inst: CsInsn, inst_idx: int, inst_offset: int,
                            block: gtirb.CodeBlock, function: Function = None):
        if inst.mnemonic in ("nop", "ret", "call", "bl", "blr") \
                or inst.mnemonic.startswith(("b.", "cb", "tb")):
            return None
        if self.arch.is_instrumentation_helper_instruction(
                inst, inst_idx, getattr(self, "_current_instructions", None)):
            return None

        mem_operand = self.arch.memory_operand(inst)
        access_size = self.arch.mem_operand_size(inst, mem_operand)
        if mem_operand is None or access_size == 0 or not self.arch.mem_operand_is_read(inst, mem_operand):
            return None
        if not self.arch.mem_operand_uses_dynamic_address(inst, mem_operand):
            return None

        regs_write = self.arch.access_registers(self.reg_manager.abi, inst, 1)
        write_regs = self._load_destination_registers(inst, regs_write)
        if not write_regs:
            return None

        regs_read = self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)

        mem_symexpr = self.arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)
        patch = self._build_patch(
            inst, mem_operand, access_size, write_regs, mem_symexpr,
            reads_registers={reg.name for reg in regs_read})
        return MemOperandPolicyPatch(patch, regs_read)

    def _build_patch(self, inst: CsInsn, mem_operand, access_size: int, write_regs,
                     mem_symexpr: Optional[gtirb.SymbolicExpression], *,
                     reads_registers=None):

        @self.arch.constraints(
            scratch_registers=4,
            clobbers_flags=True,
            reads_registers=reads_registers or set())
        def patch(ctx: InsertionContext):
            tag_reg, addr_reg, tmp_reg, shadow_reg = ctx.scratch_registers[:4]
            done_label = f".L__mem_operand_policy_done{SYMBOL_SUFFIX}"

            asm = ""
            asm += self.arch.clear_register_snippet(tag_reg)
            for reg in self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand):
                asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            asm += self.arch.mem_operand_address_snippet(
                self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_operand,
                ctx.stack_adjustment, mem_symexpr=mem_symexpr)
            asm += f"""
                and {tmp_reg:32}, {tag_reg:32}, #{TAG_SECRET | TAG_SECRET_INDIRECT}
                cbz {tmp_reg:32}, .L__attacker_tags_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_CACHE", addr_reg, tag_reg, shadow_reg, tmp_reg)}

            .L__attacker_tags_check{SYMBOL_SUFFIX}:
                and {tmp_reg:32}, {tag_reg:32}, #{TAG_ATTACKER_INDIRECT}
                cbz {tmp_reg:32}, .L__asan_check{SYMBOL_SUFFIX}
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg, tag_reg, shadow_reg, tmp_reg)}
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_SECRET_INDIRECT, write_regs)}

            .L__asan_check{SYMBOL_SUFFIX}:
                {self.arch.asan_check_snippet(
                    addr_reg, access_size, done_label,
                    shadow_offset=self.dift_layout.asan_shadow_offset,
                    scratch_reg=tmp_reg, shadow_reg=shadow_reg)
                 if self.enable_asan_check else f"b {done_label}"}
            .L__asan_check_fail{SYMBOL_SUFFIX}:
                and {tmp_reg:32}, {tag_reg:32}, #{TAG_ATTACKER}
                cbz {tmp_reg:32}, .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}
            .L__asan_check_fail_attacker{SYMBOL_SUFFIX}:
                {self.arch.report_gadget_snippet("KASPER_MDS", addr_reg, tag_reg, shadow_reg, tmp_reg)}
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_SECRET, write_regs)}
                b {done_label}
            .L__asan_check_fail_non_attacker{SYMBOL_SUFFIX}:
                {self.arch.dift_queue_reg_tag_snippet(tmp_reg, shadow_reg, TAG_ATTACKER_INDIRECT, write_regs)}
            {done_label}:
                nop
            """
            return asm

        return patch
