from typing import Optional

import gtirb
from capstone_gt import CS_OP_MEM, CsInsn

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.transient.gadget_policy.port_contention.base import TransientPortContentionPolicyPassBase


class RISCV64TransientPortContentionPolicyPass(TransientPortContentionPolicyPassBase):
    EXPECTED_ARCH = "riscv64"

    def predicate_instruction_index(self, instructions) -> Optional[int]:
        if not instructions:
            return None

        mnemonic = instructions[-1].mnemonic.lower()
        if self.arch.is_branch_mnemonic(mnemonic):
            return len(instructions) - 1
        return None

    def build_patch(self, block: gtirb.CodeBlock, inst: CsInsn, inst_offset: int):
        mem_operand = next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None)
        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_read |= self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand)

        if not regs_read and mem_operand is None:
            return None

        patch = self._build_patch(inst, regs_read)
        return patch, regs_read

    def _build_patch(self, inst: CsInsn, regs_read):
        @self.arch.constraints(
            scratch_registers=3,
            reads_registers={reg.name for reg in regs_read})
        def patch(ctx):
            tag_reg, addr_reg, tmp_reg = ctx.scratch_registers[:3]
            done_label = f".L__port_contention_policy_done{SYMBOL_SUFFIX}"

            asm = ""
            asm += "\n" + self.arch.clear_register_snippet(tag_reg)
            for reg in regs_read:
                asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            asm += f"""
                andi {tmp_reg}, {tag_reg}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                beqz {tmp_reg}, {done_label}
                {self.arch.clear_register_snippet(addr_reg)}
                {self.arch.report_gadget_snippet(
                    "KASPER_PORT", addr_reg, tag_reg, tmp_reg, save_float_state=False)}
            {done_label}:
                nop
            """
            return asm

        return patch
