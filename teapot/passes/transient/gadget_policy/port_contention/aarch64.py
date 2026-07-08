from typing import Optional

import gtirb
from capstone_gt import CS_OP_MEM, CS_OP_REG, CsInsn

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.transient.gadget_policy.port_contention.base import TransientPortContentionPolicyPassBase


class AArch64TransientPortContentionPolicyPass(TransientPortContentionPolicyPassBase):
    EXPECTED_ARCH = "aarch64"

    def predicate_instruction_index(self, instructions) -> Optional[int]:
        if not instructions:
            return None

        last = instructions[-1]
        mnemonic = last.mnemonic.lower()
        if mnemonic.startswith(("cb", "tb")):
            return len(instructions) - 1
        if not mnemonic.startswith("b."):
            return None

        for idx in range(len(instructions) - 2, -1, -1):
            if self._is_flag_writer(self.reg_manager.abi, instructions[idx]):
                return idx
        return None

    def _predicate_regs(self, inst: CsInsn) -> set:
        mnemonic = inst.mnemonic.lower()
        if mnemonic.startswith(("cb", "tb")):
            return self._operand_regs(inst, inst.operands[:1])
        if not self._is_flag_writer(self.reg_manager.abi, inst):
            return set()

        regs = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        if regs:
            return regs

        if mnemonic in {"cmp", "cmn", "tst", "ccmp", "ccmn"}:
            return self._operand_regs(inst, inst.operands)

        return self._operand_regs(inst, inst.operands[1:])

    def _operand_regs(self, inst: CsInsn, operands) -> set:
        flag_register = self.reg_manager.abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None
        result = set()
        for operand in operands:
            if operand.type != CS_OP_REG:
                continue
            reg = self.arch.register_from_name(self.reg_manager.abi, inst.reg_name(operand.reg), flag_name)
            if reg is not None:
                result.add(reg)
        return result

    @staticmethod
    def _is_flag_writer(abi, inst: CsInsn) -> bool:
        flag_register = abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None
        if flag_name is not None:
            try:
                for reg_id in inst.regs_access()[1]:
                    if inst.reg_name(reg_id).lower() == flag_name:
                        return True
            except Exception:
                pass

        mnemonic = inst.mnemonic.lower()
        return mnemonic in {"cmp", "cmn", "tst", "ccmp", "ccmn"} or mnemonic in {
            "adds", "subs", "ands", "adcs", "sbcs",
        }

    def build_patch(self, block: gtirb.CodeBlock, inst: CsInsn, inst_offset: int):
        mem_operand = next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None)
        regs_read = self.arch.access_registers(self.reg_manager.abi, inst, 0)
        regs_read |= self._predicate_regs(inst)
        if mem_operand is not None:
            regs_read.update(self.arch.mem_operand_registers(self.reg_manager.abi, inst, mem_operand))

        if not regs_read and mem_operand is None:
            return None

        mem_symexpr = None
        if mem_operand is not None:
            mem_symexpr = self.arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)

        patch = self._build_patch(inst, mem_operand, mem_symexpr, regs_read)
        return patch, regs_read

    def _build_patch(self, inst: CsInsn, mem_operand, mem_symexpr, regs_read):
        @self.arch.constraints(
            scratch_registers=4,
            reads_registers={reg.name for reg in regs_read})
        def patch(ctx):
            tag_reg, addr_reg, tmp_reg, call_tmp_reg = ctx.scratch_registers[:4]
            done_label = f".L__port_contention_policy_done{SYMBOL_SUFFIX}"

            asm = ""
            asm += "\n" + self.arch.clear_register_snippet(tag_reg)
            for reg in regs_read:
                asm += self.arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            if mem_operand is not None:
                asm += self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi, inst, addr_reg, tmp_reg, mem_operand,
                    ctx.stack_adjustment, mem_symexpr=mem_symexpr)
                asm += self.arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                asm += f"""
                    ldrb {tmp_reg:32}, [{addr_reg}]
                    orr {tag_reg:32}, {tag_reg:32}, {tmp_reg:32}
                """

            asm += f"""
                and {tmp_reg:32}, {tag_reg:32}, #{TAG_SECRET | TAG_SECRET_INDIRECT}
                cbz {tmp_reg:32}, {done_label}
                {self.arch.clear_register_snippet(addr_reg)}
                {self.arch.report_gadget_snippet("KASPER_PORT", addr_reg, tag_reg, tmp_reg, call_tmp_reg)}
            {done_label}:
                nop
            """
            return asm

        return patch
