from gtirb_rewriting import Register
from capstone_gt import CS_OP_IMM, CS_OP_REG


class X64DiftPatchesMixin:
    @staticmethod
    def dift_register_id(reg) -> int:
        name = reg.name.lower()

        if name.startswith("xmm"):
            return int(name.replace("xmm", "")) + 16

        mapping = {register_name: idx for idx, register_name in enumerate([
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        ])}
        if name in mapping:
            return mapping[name]

        raise KeyError(f"No x64 DIFT register id for {reg.name}")

    @staticmethod
    def dift_should_skip_instruction(inst) -> bool:
        return inst.mnemonic in ("nop", "ret", "call") or inst.mnemonic.startswith("j")

    @staticmethod
    def dift_clears_destination_tags(inst) -> bool:
        if (inst.mnemonic.startswith("xor")
                and inst.operands[0].type == CS_OP_REG
                and inst.operands[1].type == CS_OP_REG
                and inst.operands[0].reg == inst.operands[1].reg):
            return True
        return (
            (inst.mnemonic in ("mov", "push") or inst.mnemonic.startswith("cmov"))
            and inst.operands[0].type == CS_OP_IMM
        )

    def dift_or_reg_tag_snippet(self, tag_reg: Register, tmp_reg, reg: Register):
        return f"or {tag_reg:8l}, dift_reg_tags+{self.dift_register_id(reg)}\n"

    def dift_store_reg_tag_snippet(self, tag_reg: Register, tmp_reg, reg: Register) -> str:
        return f"mov dift_reg_tags+{self.dift_register_id(reg)}, {tag_reg:8l}\n"

    def dift_queue_reg_tag_snippet(self, tmp_reg, value_reg, tag: int, write_reg: Register) -> str:
        return "".join(
            f"or byte ptr dift_reg_queued_tags+{self.dift_register_id(reg)}, {tag}\n"
            for reg in self.dift_write_registers(write_reg)
        )

    @staticmethod
    def dift_apply_queued_tag_snippet(tag_reg: Register, addr_reg: Register, tmp_reg, done_label: str) -> str:
        asm = ""
        for offset in range(0, 48, 8):
            asm += f"""
                cmp qword ptr dift_reg_queued_tags+{offset}, 0
                jz 1f
                mov {tag_reg}, qword ptr dift_reg_queued_tags+{offset}
                or qword ptr dift_reg_tags+{offset}, {tag_reg}
                mov qword ptr dift_reg_queued_tags+{offset}, 0
            1:
            """
        return asm

    @staticmethod
    def dift_shadow_addr_snippet(addr_reg: Register, tmp_reg, xor_mask: int) -> str:
        return "".join(f"btc {addr_reg}, {bit}\n" for bit in range(64) if xor_mask & (1 << bit))
