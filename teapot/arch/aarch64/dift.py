from capstone_gt import CS_OP_IMM, CS_OP_REG
from gtirb_rewriting.assembly import Register


class AArch64DiftPatchesMixin:
    def dift_register_id(self, reg) -> int:
        name = self.x_register_name(reg)
        if name.startswith("x") and name[1:].isdigit():
            return int(name[1:])
        if name == "sp":
            return 31

        raise KeyError(f"No AArch64 DIFT register id for {reg}")

    def dift_ignored_register_names(self):
        return {"sp", "wsp", "x31"}

    def dift_should_skip_instruction(self, inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        if mnemonic in ("nop", "ret", "bl", "blr"):
            return True
        if self.is_stack_pointer_update(inst):
            return True
        return mnemonic.startswith(("b.", "cb", "tb"))

    @staticmethod
    def dift_clears_destination_tags(inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        if mnemonic in {"adr", "adrp"}:
            return True
        if mnemonic in {"mov", "movz", "movn"} and len(inst.operands) >= 2 \
                and inst.operands[1].type == CS_OP_IMM:
            return True
        if len(inst.operands) >= 3 and all(op.type == CS_OP_REG for op in inst.operands[:3]):
            return inst.operands[1].reg == inst.operands[2].reg and mnemonic in {"eor", "sub"}
        return False

    def dift_or_reg_tag_snippet(self, tag_reg, tmp_reg, reg: Register) -> str:
        return f"""
            {self.load_address(tmp_reg, "dift_reg_tags")}
            ldrb {tmp_reg:32}, [{tmp_reg}, #{self.dift_register_id(reg)}]
            orr {tag_reg:32}, {tag_reg:32}, {tmp_reg:32}
        """

    def dift_store_reg_tag_snippet(self, tag_reg, tmp_reg, reg: Register) -> str:
        return f"""
            {self.load_address(tmp_reg, "dift_reg_tags")}
            strb {tag_reg:32}, [{tmp_reg}, #{self.dift_register_id(reg)}]
        """

    def dift_queue_reg_tag_snippet(self, tmp_reg, value_reg, tag: int, write_reg: Register) -> str:
        asm = ""
        for reg in self.dift_write_registers(write_reg):
            asm += f"""
                {self.load_address(tmp_reg, f"dift_reg_queued_tags+{self.dift_register_id(reg)}")}
                ldrb {value_reg:32}, [{tmp_reg}]
                orr {value_reg:32}, {value_reg:32}, #{tag}
                strb {value_reg:32}, [{tmp_reg}]
            """
        return asm

    def dift_apply_queued_tag_snippet(self, tag_reg, addr_reg, tmp_reg, done_label: str) -> str:
        asm = ""
        for offset in range(0, 48, 8):
            asm += f"""
                {self.load_address(tmp_reg, f"dift_reg_queued_tags+{offset}")}
                ldr {tag_reg}, [{tmp_reg}]
                cbz {tag_reg}, 1f
                {self.load_address(addr_reg, f"dift_reg_tags+{offset}")}
                ldr {tmp_reg}, [{addr_reg}]
                orr {tmp_reg}, {tmp_reg}, {tag_reg}
                str {tmp_reg}, [{addr_reg}]
                {self.load_address(addr_reg, f"dift_reg_queued_tags+{offset}")}
                str xzr, [{addr_reg}]
            1:
            """
        return asm

    def dift_shadow_addr_snippet(self, addr_reg, tmp_reg, xor_mask: int) -> str:
        return f"""
            {self.mov_u64(tmp_reg, xor_mask)}
            eor {addr_reg}, {addr_reg}, {tmp_reg}
        """
