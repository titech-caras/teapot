import re
from dataclasses import dataclass
from itertools import count
from typing import Optional, Set

import gtirb
from capstone_gt import CS_AC_READ, CS_AC_WRITE, CS_OP_MEM, CS_OP_REG, CsInsn
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.utils.registers import get_register, register_from_name


_RISCV64_LOAD_MNEMONICS = {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "flw", "fld"}
_RISCV64_STORE_MNEMONICS = {"sb", "sh", "sw", "sd", "fsw", "fsd"}
_RISCV64_COMPRESSED_LOAD_MNEMONICS = {"c.lw", "c.ld", "c.lwsp", "c.ldsp", "c.flw", "c.fld", "c.flwsp", "c.fldsp"}
_RISCV64_COMPRESSED_STORE_MNEMONICS = {"c.sw", "c.sd", "c.swsp", "c.sdsp", "c.fsw", "c.fsd", "c.fswsp", "c.fsdsp"}
_RISCV64_BRANCH_MNEMONICS = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez"}
_RISCV64_READ_WRITE_OPERAND0_MNEMONICS = {
    "c.add", "c.addi", "c.addi16sp", "c.addiw", "c.and", "c.andi",
    "c.or", "c.slli", "c.srai", "c.srli", "c.sub", "c.subw", "c.xor",
}
_PCREL_ADDRESS_LABEL_COUNTER = count()


@dataclass(frozen=True)
class Riscv64FallbackMemOperand:
    base_name: str
    disp: int


class RISCV64OperandMixin:
    @staticmethod
    def operand_symbolic_expression(block: gtirb.CodeBlock, inst, operand,
                                    inst_offset: int = None):
        interval = block.byte_interval
        if interval is None:
            return None

        if inst_offset is None:
            symexpr_offset = inst.address - interval.address if interval.address else inst.address
        else:
            symexpr_offset = block.offset + inst_offset
        return interval.symbolic_expressions.get(symexpr_offset)

    @staticmethod
    def _paired_pcrel_hi_expression(symexpr):
        if not isinstance(symexpr, gtirb.SymAddrConst):
            return None
        if not {
                gtirb.SymbolicExpression.Attribute.PCREL,
                gtirb.SymbolicExpression.Attribute.LO,
        }.issubset(symexpr.attributes):
            return None

        anchor = symexpr.symbol.referent
        if not isinstance(anchor, gtirb.ByteBlock) or anchor.byte_interval is None:
            return None

        high = anchor.byte_interval.symbolic_expressions.get(anchor.offset)
        if not isinstance(high, gtirb.SymAddrConst):
            return None
        if not any(
                attr in high.attributes
                for attr in (
                    gtirb.SymbolicExpression.Attribute.HI,
                    gtirb.SymbolicExpression.Attribute.GOT,
                    gtirb.SymbolicExpression.Attribute.TLSGD,
                )):
            return None
        return high

    @staticmethod
    def _symbolic_reference(symexpr: gtirb.SymAddrConst) -> str:
        symbol = symexpr.symbol.name
        if symexpr.offset > 0:
            return f"{symbol}+{symexpr.offset}"
        if symexpr.offset < 0:
            return f"{symbol}{symexpr.offset}"
        return symbol

    @classmethod
    def _pcrel_address_snippet(cls, addr_reg, symexpr: gtirb.SymAddrConst) -> str:
        if gtirb.SymbolicExpression.Attribute.GOT in symexpr.attributes:
            modifier = "got_pcrel_hi"
        elif gtirb.SymbolicExpression.Attribute.TLSGD in symexpr.attributes:
            modifier = "tls_gd_pcrel_hi"
        elif (
                gtirb.SymbolicExpression.Attribute.PCREL in symexpr.attributes and
                gtirb.SymbolicExpression.Attribute.HI in symexpr.attributes):
            modifier = "pcrel_hi"
        else:
            raise ValueError("Unsupported RISC-V PC-relative address expression")

        label = f".L__riscv64_mem_addr_{next(_PCREL_ADDRESS_LABEL_COUNTER)}{SYMBOL_SUFFIX}"
        target = cls._symbolic_reference(symexpr)
        return f"""
            {label}:
            auipc {addr_reg}, %{modifier}({target})
            addi {addr_reg}, {addr_reg}, %pcrel_lo({label})
        """

    @staticmethod
    def bare_mnemonic(mnemonic: str) -> str:
        return mnemonic[2:] if mnemonic.startswith("c.") else mnemonic

    @classmethod
    def is_load_mnemonic(cls, mnemonic: str) -> bool:
        return cls.bare_mnemonic(mnemonic) in _RISCV64_LOAD_MNEMONICS \
            or mnemonic in _RISCV64_COMPRESSED_LOAD_MNEMONICS

    @classmethod
    def is_store_mnemonic(cls, mnemonic: str) -> bool:
        return cls.bare_mnemonic(mnemonic) in _RISCV64_STORE_MNEMONICS \
            or mnemonic in _RISCV64_COMPRESSED_STORE_MNEMONICS

    @classmethod
    def is_branch_mnemonic(cls, mnemonic: str) -> bool:
        return cls.bare_mnemonic(mnemonic) in _RISCV64_BRANCH_MNEMONICS

    @classmethod
    def fallback_mem_operand(cls, inst: CsInsn) -> Optional[Riscv64FallbackMemOperand]:
        mnemonic = inst.mnemonic.lower()
        if not (cls.is_load_mnemonic(mnemonic) or cls.is_store_mnemonic(mnemonic)):
            return None

        match = re.search(r"(^|,\s*)(-?(?:0x[0-9a-fA-F]+|\d+))\(([^()]+)\)\s*$", inst.op_str)
        if match is None:
            return None

        return Riscv64FallbackMemOperand(match.group(3).strip(), int(match.group(2), 0))

    @classmethod
    def fallback_access_regs(cls, abi, inst: CsInsn, acc_type: int,
                             flag_name: Optional[str]) -> Set[Register]:
        mnemonic = inst.mnemonic.lower()
        is_store = cls.is_store_mnemonic(mnemonic)
        is_branch = cls.is_branch_mnemonic(mnemonic)
        read_write_operand0 = mnemonic in _RISCV64_READ_WRITE_OPERAND0_MNEMONICS
        result = set()

        for idx, operand in enumerate(inst.operands):
            if operand.type == CS_OP_MEM:
                if acc_type == 0 and operand.mem.base:
                    reg = register_from_name(abi, inst.reg_name(operand.mem.base), flag_name, ("zero",))
                    if reg is not None:
                        result.add(reg)
                continue

            if operand.type != CS_OP_REG:
                continue

            access = getattr(operand, "access", 0)
            if access:
                if not (access & (CS_AC_READ if acc_type == 0 else CS_AC_WRITE)):
                    continue
            elif acc_type == 1:
                if is_store or is_branch or idx != 0:
                    continue
            elif not is_store and not is_branch and idx == 0 and not read_write_operand0:
                continue

            reg = register_from_name(abi, inst.reg_name(operand.reg), flag_name, ("zero",))
            if reg is not None:
                result.add(reg)

        return result

    @staticmethod
    def fallback_register_from_mem_operand(abi, inst: CsInsn, operand,
                                           flag_name: Optional[str] = None) -> Set[Register]:
        regs = set()

        if isinstance(operand, Riscv64FallbackMemOperand):
            reg = register_from_name(abi, operand.base_name, flag_name, ("zero",))
            if reg is not None:
                regs.add(reg)
            return regs

        if operand is None or getattr(operand, "type", None) != CS_OP_MEM:
            return regs

        for reg_id in (getattr(operand.mem, "base", 0), getattr(operand.mem, "index", 0)):
            if not reg_id:
                continue
            reg = register_from_name(abi, inst.reg_name(reg_id), flag_name, ("zero",))
            if reg is not None:
                regs.add(reg)
        return regs

    @classmethod
    def mem_operand_register_names(cls, abi, inst: CsInsn, *operands) -> Set[str]:
        scratch_names = {reg.name.lower() for reg in abi._scratch_registers()}
        result = set()
        for operand in operands:
            result.update(
                reg.name
                for reg in cls.fallback_register_from_mem_operand(abi, inst, operand)
                if reg.name.lower() in scratch_names
            )
        return result

    @staticmethod
    def riscv64_mem_operand_size(inst: CsInsn) -> int:
        mnemonic = inst.mnemonic.lower()
        if mnemonic in {"lb", "lbu", "sb"}:
            return 1
        if mnemonic in {"lh", "lhu", "sh"}:
            return 2
        if mnemonic in {"lw", "lwu", "sw", "flw", "fsw", "c.lw", "c.lwsp", "c.sw", "c.swsp", "c.flw", "c.flwsp",
                        "c.fsw", "c.fswsp"}:
            return 4
        if mnemonic in {"ld", "sd", "fld", "fsd", "c.ld", "c.ldsp", "c.sd", "c.sdsp", "c.fld", "c.fldsp",
                        "c.fsd", "c.fsdsp"}:
            return 8
        return 8

    @classmethod
    def memory_operand(cls, inst):
        return next(iter(op for op in inst.operands if op.type == CS_OP_MEM), None) \
            or cls.fallback_mem_operand(inst)

    def mem_operand_address_snippet(self, abi, inst, addr_reg, tmp_reg, mem_operand,
                                    stack_adjustment: int = 0, **kwargs) -> str:
        addr_reg = get_register(abi, addr_reg)
        tmp_reg = get_register(abi, tmp_reg)
        saved_reg_offsets = kwargs.get("saved_reg_offsets", {}) or {}
        stack_adjustment = stack_adjustment or 0

        pcrel_hi = self._paired_pcrel_hi_expression(kwargs.get("mem_symexpr"))
        if pcrel_hi is not None:
            return self._pcrel_address_snippet(addr_reg, pcrel_hi)

        def load_original_reg(base_name: Optional[str]) -> str:
            normalized = abi.normalize_register_name(base_name)
            if normalized in saved_reg_offsets:
                return f"""
                    {self.load_address(addr_reg, f"scratchpad+{saved_reg_offsets[normalized]}")}
                    ld {addr_reg}, 0({addr_reg})
                """
            return f"mv {addr_reg}, {get_register(abi, base_name)}\n" if base_name else f"li {addr_reg}, 0\n"

        if isinstance(mem_operand, Riscv64FallbackMemOperand):
            base_name = mem_operand.base_name
            asm = load_original_reg(base_name)
            disp = mem_operand.disp + (
                stack_adjustment
                if abi.normalize_register_name(base_name) == "sp" else 0)
            if disp:
                asm += self.add_constant_from_base(addr_reg, addr_reg, tmp_reg, disp)
            return asm

        base = mem_operand.mem.base
        base_name = inst.reg_name(base) if base else None
        disp = mem_operand.mem.disp + (
            stack_adjustment
            if abi.normalize_register_name(base_name) == "sp" else 0)
        asm = load_original_reg(base_name)
        if disp:
            asm += self.add_constant_from_base(addr_reg, addr_reg, tmp_reg, disp)
        return asm

    def mem_operand_registers(self, abi, inst, operand, flag_name=None):
        if flag_name is None:
            flag_register = abi.flag_register()
            flag_name = flag_register.name if flag_register is not None else None
        return self.fallback_register_from_mem_operand(abi, inst, operand, flag_name)

    def mem_operand_address_tag_registers(self, abi, inst, operand, *,
                                          block: Optional[gtirb.CodeBlock] = None,
                                          inst_offset: Optional[int] = None,
                                          flag_name: Optional[str] = None):
        if self.is_pcrel_lo_relocation(block, inst_offset):
            return set()
        static_base_registers = {"sp", "gp", "tp", "zero"}
        return {
            reg
            for reg in self.mem_operand_registers(abi, inst, operand, flag_name)
            if abi.normalize_register_name(reg.name).lower() not in static_base_registers
        }

    @staticmethod
    def is_pcrel_lo_relocation(block: gtirb.CodeBlock = None, inst_offset: int = None) -> bool:
        if block is None or inst_offset is None or block.byte_interval is None:
            return False

        symbolic = block.byte_interval.symbolic_expressions.get(block.offset + inst_offset)
        if not isinstance(symbolic, gtirb.SymAddrConst):
            return False

        return (
            gtirb.SymbolicExpression.Attribute.PCREL in symbolic.attributes and
            gtirb.SymbolicExpression.Attribute.LO in symbolic.attributes
        )

    @classmethod
    def mem_operand_is_read(cls, inst, operand) -> bool:
        mnemonic = inst.mnemonic.lower()
        if cls.is_load_mnemonic(mnemonic):
            return True
        if cls.is_store_mnemonic(mnemonic):
            return False
        access = getattr(operand, "access", 0)
        if access & CS_AC_READ:
            return True
        if access:
            return False
        return False

    @classmethod
    def mem_operand_is_write(cls, inst, operand) -> bool:
        mnemonic = inst.mnemonic.lower()
        if cls.is_store_mnemonic(mnemonic):
            return True
        if cls.is_load_mnemonic(mnemonic):
            return False
        access = getattr(operand, "access", 0)
        if access & CS_AC_WRITE:
            return True
        if access:
            return False
        return False

    @classmethod
    def mem_operand_size(cls, inst, operand) -> int:
        if operand is None:
            return 0
        return getattr(operand, "size", 0) or cls.riscv64_mem_operand_size(inst)
