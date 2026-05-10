from abc import ABC, abstractmethod
import re
from typing import Optional, Set

from teapot.utils.registers import register_from_name


class ArchitectureRegisterMixin(ABC):
    @staticmethod
    def register_name(reg) -> str:
        return reg.name if hasattr(reg, "name") else str(reg)

    def zero_register_names(self) -> Set[str]:
        return set()

    def access_registers(self, abi, inst, acc_type: int) -> Set:
        flag_register = abi.flag_register()
        flag_name = flag_register.name if flag_register is not None else None

        try:
            regs = inst.regs_access()[acc_type]
        except Exception:
            regs = []

        result = set()
        for reg_id in regs:
            reg_name = inst.reg_name(reg_id)
            if reg_name is None:
                continue
            reg = register_from_name(
                abi, reg_name,
                flag_name, self.zero_register_names())
            if reg is not None:
                result.add(reg)
        return result

    def register_from_name(self, abi, name: str, flag_name: Optional[str] = None):
        if name is None:
            return None
        if flag_name is None:
            flag_register = abi.flag_register()
            flag_name = flag_register.name if flag_register is not None else None
        return register_from_name(abi, name, flag_name, self.zero_register_names())

    def registers_in_operand_string(self, abi, operand_str: Optional[str]) -> Set:
        if operand_str is None:
            return set()

        operand = operand_str.lower()
        result = set()
        for name in sorted(abi._register_map, key=len, reverse=True):
            if not re.search(rf"(?<![A-Za-z0-9_.]){re.escape(name.lower())}(?![A-Za-z0-9_.])", operand):
                continue
            try:
                result.add(abi.get_register(name))
            except KeyError:
                pass
        return result

    def is_stack_pointer_update(self, inst) -> bool:
        return False

    @classmethod
    def fixed_spill_registers(cls, abi, count: int):
        return tuple(abi.get_register(name) for name in cls.fixed_scratch_registers(count))

    @staticmethod
    def fixed_scratch_offsets(registers, frame_offset: int = 0):
        return {
            getattr(reg, "name", str(reg)): frame_offset + idx * 8
            for idx, reg in enumerate(registers)
        }

    @abstractmethod
    def clear_register_snippet(self, reg) -> str:
        pass
