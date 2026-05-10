from typing import Iterable, Optional

from gtirb_rewriting.assembly import Register


def get_register(abi, reg) -> Register:
    if isinstance(reg, Register):
        return reg
    return abi.get_register(str(reg))


def register_from_name(abi, name: str, flag_name: Optional[str],
                       zero_names: Iterable[str] = ()) -> Optional[Register]:
    name = name.lower()
    zero_names = set(zero_names)
    if name == flag_name or name in zero_names:
        return None
    if name in abi._register_map:
        reg = abi.get_register(name)
        if reg.name == flag_name or reg.name in zero_names:
            return None
        return reg
    return None


def registers_in_abi_order(abi, registers):
    register_indices = {
        reg: idx for idx, reg in enumerate(abi.all_registers())
    }
    return sorted(registers, key=lambda reg: register_indices.get(reg, 1000))
