from capstone import CS_OP_IMM, CS_OP_REG
from gtirb_rewriting.assembly import Register


class RISCV64DiftPatchesMixin:
    def dift_register_id(self, reg) -> int:
        return int(self.x_register_name(reg)[1:])

    def dift_ignored_register_names(self):
        return {"sp", "zero"}

    def dift_should_skip_instruction(self, inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        if self._writes_only_zero(inst):
            return True
        if self.is_stack_pointer_update(inst):
            return True
        return mnemonic.startswith("j") or self.is_branch_mnemonic(mnemonic)

    @staticmethod
    def _writes_only_zero(inst) -> bool:
        # The real form of nop is `addi zero, zero, 0`: a write to zero is no write.
        operands = inst.operands
        return (bool(operands) and operands[0].type == CS_OP_REG and inst.reg_name(operands[0].reg) == "zero" and
                inst.mnemonic.lower() in {"addi", "addiw", "add", "addw"})

    @staticmethod
    def dift_clears_destination_tags(inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        if mnemonic in {"lui", "auipc"}:
            return True
        operands = inst.operands
        if (mnemonic in {"addi", "addiw"} and len(operands) == 3 and operands[1].type == CS_OP_REG and
                inst.reg_name(operands[1].reg) == "zero" and operands[2].type == CS_OP_IMM):
            # `li rd, imm` and c.li in their real form.
            return True
        if len(inst.operands) >= 3 and all(op.type == CS_OP_REG for op in inst.operands[:3]):
            return inst.operands[1].reg == inst.operands[2].reg and mnemonic in {"xor", "sub"}
        return False

    def dift_or_reg_tag_snippet(self, tag_reg, tmp_reg, reg: Register) -> str:
        return f"""
            {self.load_address(tmp_reg, "dift_reg_tags")}
            lbu {tmp_reg}, {self.dift_register_id(reg)}({tmp_reg})
            or {tag_reg}, {tag_reg}, {tmp_reg}
        """

    def dift_store_reg_tag_snippet(self, tag_reg, tmp_reg, reg: Register) -> str:
        return f"""
            {self.load_address(tmp_reg, "dift_reg_tags")}
            sb {tag_reg}, {self.dift_register_id(reg)}({tmp_reg})
        """

    def dift_queue_reg_tag_snippet(self, tmp_reg, value_reg, tag: int, write_reg: Register) -> str:
        asm = f"""
            {self.load_address(tmp_reg, "dift_reg_queue_pending")}
            li {value_reg}, 1
            sb {value_reg}, 0({tmp_reg})
        """
        for reg in self.dift_write_registers(write_reg):
            asm += f"""
                {self.load_address(tmp_reg, f"dift_reg_queued_tags+{self.dift_register_id(reg)}")}
                lbu {value_reg}, 0({tmp_reg})
                ori {value_reg}, {value_reg}, {tag}
                sb {value_reg}, 0({tmp_reg})
            """
        return asm

    def dift_apply_queued_tag_snippet(self, tag_reg, addr_reg, tmp_reg, done_label: str) -> str:
        asm = f"""
            {self.load_address(tmp_reg, "dift_reg_queue_pending")}
            lbu {tag_reg}, 0({tmp_reg})
            beqz {tag_reg}, {done_label}
            sb zero, 0({tmp_reg})
        """
        for offset in range(0, 48, 8):
            asm += f"""
                {self.load_address(tmp_reg, f"dift_reg_queued_tags+{offset}")}
                ld {tag_reg}, 0({tmp_reg})
                {self.load_address(addr_reg, f"dift_reg_tags+{offset}")}
                ld {tmp_reg}, 0({addr_reg})
                or {tmp_reg}, {tmp_reg}, {tag_reg}
                sd {tmp_reg}, 0({addr_reg})
                {self.load_address(addr_reg, f"dift_reg_queued_tags+{offset}")}
                sd zero, 0({addr_reg})
            """
        return asm

    def dift_shadow_addr_snippet(self, addr_reg, tmp_reg, xor_mask: int) -> str:
        return f"""
            li {tmp_reg}, {xor_mask}
            xor {addr_reg}, {addr_reg}, {tmp_reg}
        """
