from capstone import CS_OP_REG
from capstone.x86 import X86_REG_EFLAGS
from gtirb_rewriting import Register

# CMPXCHG8B/16B compare edx:eax (rdx:rax) with memory, store ecx:ebx (rcx:rbx) when equal and load the
# memory into edx:eax otherwise. Capstone 6.0.0-Alpha11 reports only al for both register sets.
_COMPARE_EXCHANGE_PAIRS = {
    "cmpxchg8b": (("eax", "ebx", "ecx", "edx"), ("eax", "edx")),
    "cmpxchg16b": (("rax", "rbx", "rcx", "rdx"), ("rax", "rdx")),
}


class X64RegisterMixin:
    @staticmethod
    def instruction_writes_flags(inst) -> bool:
        try:
            return X86_REG_EFLAGS in inst.regs_access()[1]
        except Exception:
            return False

    def access_registers(self, abi, inst, acc_type: int):
        # TEST has two read-only value operands. Capstone 5 omits reads (and
        # can report writes) for the register in its memory-first forms.
        if inst.mnemonic == 'test' and acc_type == 1:
            return set()
        try:
            regs = list(inst.regs_access()[acc_type])
        except Exception:
            regs = []
        if inst.mnemonic == 'test' and acc_type == 0:
            regs.extend(op.reg for op in inst.operands if op.type == CS_OP_REG)

        result = set()
        # Prefixes are part of Capstone's mnemonic ("lock cmpxchg8b").
        pair = _COMPARE_EXCHANGE_PAIRS.get(inst.mnemonic.split()[-1])
        if pair is not None:
            result.update(reg for reg in (self.register_from_name(abi, name) for name in pair[acc_type])
                          if reg is not None)
        for reg_id in regs:
            if reg_id == X86_REG_EFLAGS:
                continue
            reg = self.register_from_name(abi, inst.reg_name(reg_id))
            if reg is not None:
                result.add(reg)
        return result

    @staticmethod
    def clear_register_snippet(reg: Register) -> str:
        return f"xor {reg:32}, {reg:32}\n"
