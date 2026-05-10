from typing import Set

from capstone_gt import CS_OP_REG


_COMPARE_MNEMONICS = {"cmp", "cmn", "tst", "ccmp", "ccmn"}
_STORE_PREFIXES = ("str", "stp", "stur", "stlr", "stxr")


class AArch64RegisterMixin:
    def zero_register_names(self) -> Set[str]:
        return {"xzr", "wzr"}

    def register_from_name(self, abi, name: str, flag_name=None):
        if name is not None:
            name = name.lower()
            if name == "fp":
                name = "x29"
            elif name == "lr":
                name = "x30"
            elif name == "wsp":
                name = "sp"
        return super().register_from_name(abi, name, flag_name)

    def x_register_name(self, reg) -> str:
        name = getattr(reg, "name", str(reg)).lower()
        if name.startswith("w") and name[1:].isdigit():
            return "x" + name[1:]
        if name == "wsp":
            return "sp"
        if name == "wzr":
            return "xzr"
        if name == "fp":
            return "x29"
        if name == "lr":
            return "x30"
        return name

    def access_registers(self, abi, inst, acc_type: int) -> Set:
        result = super().access_registers(abi, inst, acc_type)
        if acc_type == 0 and self._needs_explicit_read_fallback(inst):
            result |= self._fallback_operand_registers(abi, inst)
        return result

    @staticmethod
    def is_stack_pointer_update(inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        op_str = "".join(inst.op_str.lower().split())
        return mnemonic in {"add", "sub"} and op_str.startswith(("sp,sp,", "wsp,wsp,"))

    def _fallback_operand_registers(self, abi, inst) -> Set:
        flag_register = abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None
        result = set()
        for operand in inst.operands:
            if operand.type == CS_OP_REG:
                reg = self.register_from_name(abi, inst.reg_name(operand.reg), flag_name)
                if reg is not None:
                    result.add(reg)
            elif getattr(operand, "mem", None) is not None:
                for reg_id in (operand.mem.base, operand.mem.index):
                    if not reg_id:
                        continue
                    reg = self.register_from_name(abi, inst.reg_name(reg_id), flag_name)
                    if reg is not None:
                        result.add(reg)
        return result

    @staticmethod
    def _needs_explicit_read_fallback(inst) -> bool:
        mnemonic = inst.mnemonic.lower()
        return (
            mnemonic in _COMPARE_MNEMONICS or
            mnemonic.startswith(_STORE_PREFIXES) or
            mnemonic.startswith(("cb", "tb"))
        )

    @staticmethod
    def clear_register_snippet(reg) -> str:
        return f"mov {reg:32}, wzr\n"

    @staticmethod
    def fixed_scratch_registers(count: int = 5):
        return ("x13", "x14", "x15", "x16", "x17")[:count]

    @staticmethod
    def w_reg(reg: str) -> str:
        reg = f"{reg}"
        if reg.startswith("x"):
            return "w" + reg[1:]
        return reg
