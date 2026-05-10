from capstone_gt.x86 import X86_REG_EFLAGS
from gtirb_rewriting import Register


class X64RegisterMixin:
    @staticmethod
    def instruction_writes_flags(inst) -> bool:
        try:
            return X86_REG_EFLAGS in inst.regs_access()[1]
        except Exception:
            return False

    def access_registers(self, abi, inst, acc_type: int):
        try:
            regs = inst.regs_access()[acc_type]
        except Exception:
            regs = []

        result = set()
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
