from gtirb_rewriting import Register
from capstone import CS_OP_IMM, CS_OP_REG


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

    def dift_should_skip_instruction(self, inst) -> bool:
        # Basic execution/rollback support only: neither the x87 register
        # stack nor RFLAGS has a DIFT tag model. Leave tags untouched instead
        # of treating implicit-source stores as writes of an untainted value.
        return (inst.mnemonic.split()[-1] in ("nop", "pushf", "pushfq", "popf", "popfq")
                or self.is_control_transfer_instruction(inst) or self.is_x87_instruction(inst))

    @staticmethod
    def dift_clears_destination_tags(inst) -> bool:
        mnemonic = inst.mnemonic.split()[-1]
        operands = inst.operands
        # Only bitwise/vector XORs and integer SUB have an unconditional zero
        # result here. Floating SUB may produce NaNs. A merging writemask keeps
        # old lanes, so do not treat the EVEX mask operand as a zeroing idiom.
        source_indices = ((0, 1) if mnemonic in {'xor', 'sub', 'pxor', 'xorps', 'xorpd'}
                          and len(operands) == 2 else
                          (1, 2) if mnemonic in {'vpxor', 'vpxord', 'vpxorq', 'vxorps', 'vxorpd'}
                          and len(operands) == 3 else None)
        if (source_indices is not None
                and all(operands[i].type == CS_OP_REG for i in source_indices)
                and operands[source_indices[0]].reg == operands[source_indices[1]].reg):
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
        return "mov byte ptr dift_reg_queue_pending, 1\n" + "".join(
            f"or byte ptr dift_reg_queued_tags+{self.dift_register_id(reg)}, {tag}\n"
            for reg in self.dift_write_registers(write_reg)
        )

    @staticmethod
    def dift_shadow_addr_snippet(addr_reg: Register, tmp_reg, xor_mask: int) -> str:
        return "".join(f"btc {addr_reg}, {bit}\n" for bit in range(64) if xor_mask & (1 << bit))
