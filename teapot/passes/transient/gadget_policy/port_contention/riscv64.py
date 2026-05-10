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
        arch = self.arch
        abi = self.reg_manager.abi
        mem_operand = next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None)
        regs_read = arch.access_registers(abi, inst, 0)
        regs_read |= arch.mem_operand_registers(abi, inst, mem_operand)

        if not regs_read and mem_operand is None:
            return None

        fixed_regs = arch.fixed_spill_registers(abi, 3)

        @arch.constraints()
        def patch(ctx):
            tag_reg, addr_reg, tmp_reg = fixed_regs
            done_label = f".L__port_contention_policy_done{SYMBOL_SUFFIX}"

            asm = arch.save_regs_to_first_spill(fixed_regs)
            asm += "\n" + arch.clear_register_snippet(tag_reg)
            for reg in regs_read:
                asm += arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            asm += f"""
                andi {tmp_reg}, {tag_reg}, {TAG_SECRET | TAG_SECRET_INDIRECT}
                beqz {tmp_reg}, {done_label}
                {arch.clear_register_snippet(addr_reg)}
                {arch.report_gadget_snippet(
                    "KASPER_PORT", addr_reg, tag_reg, tmp_reg, save_float_state=False)}
            {done_label}:
                nop
            """
            asm += arch.restore_regs_from_first_spill(fixed_regs)
            return asm

        return patch, regs_read
