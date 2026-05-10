from typing import Optional

import gtirb
from capstone_gt import CS_OP_MEM, CS_OP_REG, CsInsn

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import AARCH64_SHADOW_STACK_GADGET_PORT_OFFSET
from teapot.configs.tags import TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.passes.transient.gadget_policy.port_contention.base import TransientPortContentionPolicyPassBase


class AArch64TransientPortContentionPolicyPass(TransientPortContentionPolicyPassBase):
    EXPECTED_ARCH = "aarch64"

    def predicate_instruction_index(self, instructions) -> Optional[int]:
        abi = self.reg_manager.abi
        if not instructions:
            return None

        last = instructions[-1]
        mnemonic = last.mnemonic.lower()
        if mnemonic.startswith(("cb", "tb")):
            return len(instructions) - 1
        if not mnemonic.startswith("b."):
            return None

        for idx in range(len(instructions) - 2, -1, -1):
            if self._is_flag_writer(abi, instructions[idx]):
                return idx
        return None

    def _predicate_regs(self, arch, abi, inst: CsInsn) -> set:
        mnemonic = inst.mnemonic.lower()
        if mnemonic.startswith(("cb", "tb")):
            return self._operand_regs(arch, abi, inst, inst.operands[:1])
        if not self._is_flag_writer(abi, inst):
            return set()

        regs = arch.access_registers(abi, inst, 0)
        if regs:
            return regs

        if mnemonic in {"cmp", "cmn", "tst", "ccmp", "ccmn"}:
            return self._operand_regs(arch, abi, inst, inst.operands)

        return self._operand_regs(arch, abi, inst, inst.operands[1:])

    @staticmethod
    def _operand_regs(arch, abi, inst: CsInsn, operands) -> set:
        flag_register = abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None
        result = set()
        for operand in operands:
            if operand.type != CS_OP_REG:
                continue
            reg = arch.register_from_name(abi, inst.reg_name(operand.reg), flag_name)
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
        arch = self.arch
        abi = self.reg_manager.abi
        mem_operand = next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None)
        regs_read = arch.access_registers(abi, inst, 0)
        regs_read |= self._predicate_regs(arch, abi, inst)
        if mem_operand is not None:
            regs_read.update(arch.mem_operand_registers(abi, inst, mem_operand))

        if not regs_read and mem_operand is None:
            return None

        mem_symexpr = None
        if mem_operand is not None:
            mem_symexpr = arch.operand_symbolic_expression(block, inst, mem_operand, inst_offset)

        fixed_regs = arch.fixed_spill_registers(abi, 4)
        frame_offset = AARCH64_SHADOW_STACK_GADGET_PORT_OFFSET
        saved_reg_offsets = arch.fixed_scratch_offsets(fixed_regs, frame_offset)

        @arch.constraints()
        def patch(ctx):
            tag_reg, addr_reg, tmp_reg, call_tmp_reg = fixed_regs
            done_label = f".L__port_contention_policy_done{SYMBOL_SUFFIX}"

            asm = arch.save_regs_to_shadow_stack(
                fixed_regs, save_flags=False, frame_offset=frame_offset, preserve_sp=True)
            asm += "\n" + arch.clear_register_snippet(tag_reg)
            for reg in regs_read:
                asm += arch.dift_or_reg_tag_snippet(tag_reg, tmp_reg, reg)

            if mem_operand is not None:
                asm += arch.mem_operand_address_snippet(
                    abi, inst, addr_reg, tmp_reg, mem_operand,
                    ctx.stack_adjustment, mem_symexpr=mem_symexpr,
                    saved_reg_offsets=saved_reg_offsets, saved_reg_base="shadow_sp")
                asm += arch.dift_shadow_addr_snippet(addr_reg, tmp_reg, self.dift_layout.xor_mask)
                asm += f"""
                    ldrb {tmp_reg:32}, [{addr_reg}]
                    orr {tag_reg:32}, {tag_reg:32}, {tmp_reg:32}
                """

            asm += f"""
                and {tmp_reg:32}, {tag_reg:32}, #{TAG_SECRET | TAG_SECRET_INDIRECT}
                cbz {tmp_reg:32}, {done_label}
                {arch.clear_register_snippet(addr_reg)}
                {arch.report_gadget_snippet("KASPER_PORT", addr_reg, tag_reg, tmp_reg, call_tmp_reg)}
            {done_label}:
                nop
            """
            asm += arch.restore_regs_from_shadow_stack(
                fixed_regs, save_flags=False, frame_offset=frame_offset, preserve_sp=True)
            return asm

        return patch, regs_read
