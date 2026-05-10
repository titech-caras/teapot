import re
from typing import Set


class RISCV64RegisterMixin:
    def zero_register_names(self) -> Set[str]:
        return {"zero"}

    def x_register_name(self, reg) -> str:
        sizes = getattr(reg, "sizes", None)
        if sizes is not None:
            for name in sizes.values():
                if re.fullmatch(r"x(?:[0-9]|[12][0-9]|3[01])", name):
                    return name

        name = self.register_name(reg).lower()
        if re.fullmatch(r"x(?:[0-9]|[12][0-9]|3[01])", name):
            return name

        if self.abi is not None:
            return self.x_register_name(self.abi.get_register(name))

        raise KeyError(f"No RISC-V x-register name for {reg}")

    def access_registers(self, abi, inst, acc_type: int) -> Set:
        flag_register = abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None
        return (
            super().access_registers(abi, inst, acc_type) |
            self.fallback_access_regs(abi, inst, acc_type, flag_name)
        )

    @staticmethod
    def is_stack_pointer_update(inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        op_str = "".join(inst.op_str.lower().split())
        if mnemonic in {"c.addi16sp"}:
            return True
        if mnemonic in {"addi", "c.addi", "add", "sub"} and op_str.startswith("sp,sp,"):
            return True
        return False

    @staticmethod
    def clear_register_snippet(reg) -> str:
        return f"li {reg}, 0\n"

    @staticmethod
    def fixed_scratch_registers(count: int = 4):
        return ("t0", "t1", "t2", "t3")[:count]
