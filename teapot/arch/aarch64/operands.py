from typing import Optional

import gtirb
from capstone.arm64 import (
    ARM64_EXT_SXTW,
    ARM64_EXT_UXTW,
    ARM64_SFT_LSL,
    ARM64_VAS_16B,
    ARM64_VAS_1B,
    ARM64_VAS_1D,
    ARM64_VAS_1H,
    ARM64_VAS_1Q,
    ARM64_VAS_1S,
    ARM64_VAS_2D,
    ARM64_VAS_2H,
    ARM64_VAS_2S,
    ARM64_VAS_4B,
    ARM64_VAS_4H,
    ARM64_VAS_4S,
    ARM64_VAS_8B,
    ARM64_VAS_8H,
)
from capstone_gt import CS_AC_READ, CS_AC_WRITE, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, CsInsn

from teapot.utils.registers import get_register


_AARCH64_VECTOR_ARRANGEMENTS = {
    ARM64_VAS_16B: (16, 1),
    ARM64_VAS_8B: (8, 1),
    ARM64_VAS_4B: (4, 1),
    ARM64_VAS_1B: (1, 1),
    ARM64_VAS_8H: (8, 2),
    ARM64_VAS_4H: (4, 2),
    ARM64_VAS_2H: (2, 2),
    ARM64_VAS_1H: (1, 2),
    ARM64_VAS_4S: (4, 4),
    ARM64_VAS_2S: (2, 4),
    ARM64_VAS_1S: (1, 4),
    ARM64_VAS_2D: (2, 8),
    ARM64_VAS_1D: (1, 8),
    ARM64_VAS_1Q: (1, 16),
}


_ATOMIC_FETCH_MNEMONIC_PREFIXES = (
    "ldadd", "ldclr", "ldeor", "ldset",
    "ldsmax", "ldsmin", "ldumax", "ldumin",
)
_ATOMIC_STORE_ALIAS_MNEMONIC_PREFIXES = (
    "stadd", "stclr", "steor", "stset",
    "stsmax", "stsmin", "stumax", "stumin",
)
_ATOMIC_RMW_MNEMONIC_PREFIXES = (
    *_ATOMIC_FETCH_MNEMONIC_PREFIXES,
    *_ATOMIC_STORE_ALIAS_MNEMONIC_PREFIXES,
    "swp", "cas",
)


def aarch64_is_atomic_rmw_mnemonic(mnemonic: str) -> bool:
    """Return whether *mnemonic* performs an atomic read/modify/write."""
    return mnemonic.lower().startswith(_ATOMIC_RMW_MNEMONIC_PREFIXES)


def aarch64_atomic_written_operand_indices(mnemonic: str):
    """Return explicit register operands written by an atomic instruction."""
    mnemonic = mnemonic.lower()
    if mnemonic.startswith(_ATOMIC_FETCH_MNEMONIC_PREFIXES) or mnemonic.startswith("swp"):
        return (1,)
    if mnemonic.startswith("casp"):
        return (0, 1)
    if mnemonic.startswith("cas"):
        return (0,)
    return ()


def aarch64_atomic_read_operand_indices(mnemonic: str):
    """Return explicit register operands read by an atomic instruction."""
    mnemonic = mnemonic.lower()
    if mnemonic.startswith("casp"):
        return (0, 1, 2, 3)
    if mnemonic.startswith("cas"):
        return (0, 1)
    if aarch64_is_atomic_rmw_mnemonic(mnemonic):
        return (0,)
    return ()


class AArch64OperandMixin:
    @staticmethod
    def aarch64_lo12_symbolic_disp(symexpr: Optional[gtirb.SymbolicExpression]) -> Optional[str]:
        if not isinstance(symexpr, gtirb.SymAddrConst):
            return None
        if gtirb.SymbolicExpression.Attribute.LO12 not in symexpr.attributes:
            return None

        disp = f":lo12:{symexpr.symbol.name}"
        if symexpr.offset > 0:
            disp += f"+{symexpr.offset}"
        elif symexpr.offset < 0:
            disp += str(symexpr.offset)
        return disp

    @staticmethod
    def aarch64_reg_name(abi, name: str) -> str:
        name = name.lower()
        if name == "fp":
            name = "x29"
        elif name == "lr":
            name = "x30"
        if name in ("xzr", "wzr"):
            return "xzr"
        if name == "wsp":
            name = "sp"
        return get_register(abi, name).name

    @staticmethod
    def aarch64_structure_mem_operand_size(inst: CsInsn) -> int:
        mnemonic = inst.mnemonic.lower()
        structure_prefixes = (
            "ld1", "ld2", "ld3", "ld4",
            "st1", "st2", "st3", "st4",
        )
        if not mnemonic.startswith(structure_prefixes):
            return 0

        replicate_load = mnemonic.startswith(("ld1r", "ld2r", "ld3r", "ld4r"))
        total_size = 0
        found_vector = False
        for operand in inst.operands:
            if operand.type != CS_OP_REG:
                continue
            name = inst.reg_name(operand.reg).lower()
            if not name.startswith("v"):
                continue

            arrangement = _AARCH64_VECTOR_ARRANGEMENTS.get(getattr(operand, "vas", 0))
            if arrangement is None:
                return 0
            lanes, element_size = arrangement
            lane_access = getattr(operand, "vector_index", -1) >= 0
            total_size += element_size if replicate_load or lane_access else lanes * element_size
            found_vector = True

        return total_size if found_vector else 0

    @staticmethod
    def aarch64_mem_operand_size(inst: CsInsn) -> int:
        mnemonic = inst.mnemonic.lower()
        atomic_rmw = aarch64_is_atomic_rmw_mnemonic(mnemonic)
        if atomic_rmw and mnemonic.endswith("b"):
            return 1
        if atomic_rmw and mnemonic.endswith("h"):
            return 2
        if mnemonic.startswith((
                "ldrb", "strb", "ldurb", "sturb", "ldarb", "stlrb",
                "ldaxrb", "stlxrb", "ldxrb", "stxrb", "ldursb", "ldrsb")):
            return 1
        if mnemonic.startswith((
                "ldrh", "strh", "ldurh", "sturh", "ldarh", "stlrh",
                "ldaxrh", "stlxrh", "ldxrh", "stxrh", "ldursh", "ldrsh")):
            return 2
        if mnemonic.startswith(("ldrsw", "ldursw")):
            return 4

        structure_size = AArch64OperandMixin.aarch64_structure_mem_operand_size(inst)
        if structure_size:
            return structure_size

        reg_sizes = []
        for op in inst.operands:
            if op.type != CS_OP_REG:
                continue
            name = inst.reg_name(op.reg).lower()
            if name == "wzr" or name.startswith(("w", "s")):
                reg_sizes.append(4)
            elif name in {"fp", "lr", "sp", "xzr"} or name.startswith(("x", "d")):
                reg_sizes.append(8)
            elif name.startswith("q"):
                reg_sizes.append(16)
            elif name.startswith("h"):
                reg_sizes.append(2)
            elif name.startswith("b"):
                reg_sizes.append(1)

        if mnemonic.startswith(("ldp", "stp", "casp")) and len(reg_sizes) >= 2:
            return reg_sizes[0] + reg_sizes[1]
        if reg_sizes:
            return reg_sizes[0]
        return 8

    def mem_operand_address_snippet(self, abi, inst, addr_reg, tmp_reg, mem_operand,
                                    stack_adjustment: int = 0, **kwargs) -> str:
        unknown_kwargs = set(kwargs) - {"mem_symexpr", "saved_reg_offsets", "saved_reg_base", "sp_is_shadow_stack"}
        if unknown_kwargs:
            raise TypeError(f"Unexpected AArch64 memory operand arguments: {sorted(unknown_kwargs)}")

        base = mem_operand.mem.base
        index = mem_operand.mem.index
        disp = mem_operand.mem.disp
        symbolic_disp = self.aarch64_lo12_symbolic_disp(kwargs.get("mem_symexpr"))
        asm = ""
        addr_reg = get_register(abi, addr_reg)
        tmp_reg = get_register(abi, tmp_reg)
        saved_reg_offsets = kwargs.get("saved_reg_offsets") or {}
        saved_reg_base = kwargs.get("saved_reg_base", "sp")
        sp_is_shadow_stack = kwargs.get("sp_is_shadow_stack", False)

        def original_reg_value(reg_id, destination_reg) -> str:
            destination_reg = get_register(abi, destination_reg)
            source_name = self.aarch64_reg_name(abi, inst.reg_name(reg_id))
            if source_name in saved_reg_offsets:
                offset = saved_reg_offsets[source_name]
                suffix = "" if offset == 0 else f", #{offset}"
                if saved_reg_base == "shadow_sp":
                    return (
                        f"mov {destination_reg}, sp\n"
                        f"{self.shadow_stack_adjust_reg('sub', destination_reg)}\n"
                        f"ldr {destination_reg}, [{destination_reg}{suffix}]\n"
                    )
                return f"ldr {destination_reg}, [{saved_reg_base}{suffix}]\n"
            return f"mov {destination_reg}, {source_name}\n"

        def load_original_reg(reg_id, destination_reg) -> str:
            raw_reg_name = inst.reg_name(reg_id)
            source_name = self.aarch64_reg_name(abi, raw_reg_name)
            destination_reg = get_register(abi, destination_reg)
            if source_name in saved_reg_offsets:
                offset = saved_reg_offsets[source_name]
                suffix = "" if offset == 0 else f", #{offset}"
                if saved_reg_base == "shadow_sp":
                    return (
                        f"mov {destination_reg}, sp\n"
                        f"{self.shadow_stack_adjust_reg('sub', destination_reg)}\n"
                        f"ldr {destination_reg}, [{destination_reg}{suffix}]\n"
                    )
                return f"ldr {destination_reg}, [{saved_reg_base}{suffix}]\n"
            if raw_reg_name.startswith("w"):
                return f"mov {destination_reg:32}, {raw_reg_name}\n"
            return f"mov {destination_reg}, {source_name}\n"

        def add_original_reg(reg_id) -> str:
            raw_reg_name = inst.reg_name(reg_id)
            asm = load_original_reg(reg_id, tmp_reg)

            extension = getattr(mem_operand, "ext", 0)
            if extension == ARM64_EXT_UXTW:
                asm += f"mov {tmp_reg:32}, {tmp_reg:32}\n"
            elif extension == ARM64_EXT_SXTW:
                asm += f"sxtw {tmp_reg}, {tmp_reg:32}\n"
            elif raw_reg_name.startswith("w"):
                asm += f"mov {tmp_reg:32}, {tmp_reg:32}\n"

            shift = getattr(mem_operand, "shift", None)
            if shift is not None and shift.type == ARM64_SFT_LSL and shift.value:
                asm += f"lsl {tmp_reg}, {tmp_reg}, #{shift.value}\n"

            asm += f"add {addr_reg}, {addr_reg}, {tmp_reg}\n"
            return asm

        if base:
            base_name = inst.reg_name(base)
            asm += original_reg_value(base, addr_reg)
            if base_name in ("sp", "wsp") and sp_is_shadow_stack:
                asm += self.shadow_stack_adjust_reg("add", addr_reg) + "\n"
            if base_name in ("sp", "wsp") and stack_adjustment:
                asm += self.add_sub_constant_from_base("add", addr_reg, addr_reg, tmp_reg, stack_adjustment)
        else:
            asm += self.mov_u64(addr_reg, disp)
            disp = 0

        if index:
            asm += add_original_reg(index)
        if symbolic_disp is not None:
            asm += f"add {addr_reg}, {addr_reg}, {symbolic_disp}\n"
            disp = 0
        if disp > 0:
            asm += self.add_sub_constant_from_base("add", addr_reg, addr_reg, tmp_reg, disp)
        elif disp < 0:
            asm += self.add_sub_constant_from_base("sub", addr_reg, addr_reg, tmp_reg, -disp)
        return asm

    def operand_symbolic_expression(self, block: gtirb.CodeBlock, inst, operand,
                                    inst_offset: int = None):
        interval = block.byte_interval
        if interval is None:
            return None

        if inst_offset is None:
            symexpr_offset = inst.address - interval.address if interval.address else inst.address
        else:
            symexpr_offset = block.offset + inst_offset
        if operand.type == CS_OP_MEM:
            disp_offset = getattr(inst, "disp_offset", None)
            if disp_offset is not None:
                return interval.symbolic_expressions.get(symexpr_offset + disp_offset, None)
            return interval.symbolic_expressions.get(symexpr_offset, None)
        if operand.type == CS_OP_IMM:
            imm_offset = getattr(inst, "imm_offset", None)
            if imm_offset is not None:
                return interval.symbolic_expressions.get(symexpr_offset + imm_offset, None)
            return interval.symbolic_expressions.get(symexpr_offset, None)
        return None

    def mem_operand_address_register_names(self, inst, mem_operand):
        if mem_operand is None:
            return set()

        result = set()
        for reg_id in (mem_operand.mem.base, mem_operand.mem.index):
            if not reg_id:
                continue
            reg_name = inst.reg_name(reg_id).lower()
            if reg_name.startswith("w") and reg_name[1:].isdigit():
                reg_name = "x" + reg_name[1:]
            if reg_name == "wsp":
                reg_name = "sp"
            if reg_name not in {"sp", "xzr"}:
                result.add(reg_name)
        return result

    def mem_operand_uses_dynamic_address(self, inst, mem_operand) -> bool:
        return bool(self.mem_operand_address_register_names(inst, mem_operand))

    @staticmethod
    def mem_operand_is_read(inst, operand) -> bool:
        mnemonic = inst.mnemonic.lower()
        if aarch64_is_atomic_rmw_mnemonic(mnemonic):
            return True
        if mnemonic.startswith("ld"):
            return True
        if mnemonic.startswith("st"):
            return False
        access = getattr(operand, "access", 0)
        if access & CS_AC_READ:
            return True
        if access:
            return False
        return mnemonic.startswith(("ldr", "ldp", "ldur", "ldar", "ldxr"))

    @staticmethod
    def mem_operand_is_write(inst, operand) -> bool:
        mnemonic = inst.mnemonic.lower()
        if aarch64_is_atomic_rmw_mnemonic(mnemonic):
            return True
        if mnemonic.startswith("st"):
            return True
        if mnemonic.startswith("ld"):
            return False
        access = getattr(operand, "access", 0)
        if access & CS_AC_WRITE:
            return True
        if access:
            return False
        return mnemonic.startswith(("str", "stp", "stur", "stlr", "stxr"))

    @classmethod
    def mem_operand_size(cls, inst, operand) -> int:
        if operand is None:
            return 0
        if inst.mnemonic.lower().startswith(("ldp", "stp")):
            return cls.aarch64_mem_operand_size(inst)
        size = getattr(operand, "size", 0)
        return size or cls.aarch64_mem_operand_size(inst)
