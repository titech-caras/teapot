import re
from itertools import count
from typing import Optional, Set

import gtirb
from capstone import CS_AC_READ, CS_AC_WRITE, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, CsInsn
from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import SYMBOL_SUFFIX
from teapot.configs.slots import SCRATCHPAD_FIRST_SPILL_OFFSET
from teapot.utils.registers import get_register, register_from_name
from teapot.datacls.stack_access import StackAccess


_RISCV64_LOAD_MNEMONICS = {"lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "flw", "fld"}
_RISCV64_STORE_MNEMONICS = {"sb", "sh", "sw", "sd", "fsw", "fsd"}
_RISCV64_BRANCH_MNEMONICS = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}
_RISCV64_ATOMIC_MEMORY_MNEMONIC_RE = re.compile(
    r"^(amo(?:add|and|maxu?|minu?|or|swap|xor)|lr|sc)\.([wd])"
    r"(?:\.(?:aqrl|aq|rl))?$"
)
_PCREL_ADDRESS_LABEL_COUNTER = count()


def riscv64_atomic_memory_access(mnemonic: str):
    """Return the memory access kind and width for an A-extension operation.

    Capstone reports the LR/SC and AMO address as a memory operand but gives
    RISC-V memory operands no size. Keep the architectural classification
    here so all consumers (memlog, DIFT, memory checks) see the same memory
    operation.
    """
    match = _RISCV64_ATOMIC_MEMORY_MNEMONIC_RE.fullmatch(mnemonic.lower())
    if match is None:
        return None

    operation = match.group(1)
    kind = "amo" if operation.startswith("amo") else operation
    width = 4 if match.group(2) == "w" else 8
    return kind, width


class RISCV64OperandMixin:
    def saved_return_registers(self):
        return tuple(self.abi.get_register(name) for name in ("sp", "s0", "ra"))

    def stack_register_assignment(self, inst):
        operands = inst.operands
        if not operands or operands[0].type != CS_OP_REG:
            return None
        dst = self.register_from_name(self.abi, inst.reg_name(operands[0].reg))
        # addi also stands for mv and the stack adjustments c.addi, c.addi16sp and c.addi4spn.
        if (inst.mnemonic == "addi" and len(operands) == 3 and
                operands[1].type == CS_OP_REG and operands[2].type == CS_OP_IMM):
            # Without the type check on operand 1, Capstone's operand union
            # would reinterpret an immediate as a register id and fabricate a
            # frame assignment that was never written.
            source, delta = operands[1], operands[2].imm
        else:
            return None
        src = self.register_from_name(self.abi, inst.reg_name(source.reg))
        if dst is None or src is None:
            # A copy from zero is a constant load (Capstone 6 spells li as `addi rd, zero, imm`), and a
            # write to zero is a nop: neither assigns one register from another.
            return None
        return dst, src, delta

    @staticmethod
    def mem_operand_base_name(inst, operand) -> Optional[str]:
        """Base register of a memory operand."""
        return inst.reg_name(operand.mem.base) if operand.mem.base else None

    def stack_memory_access(self, inst):
        mem = self.memory_operand(inst)
        if mem is None:
            return None
        base = self.register_from_name(self.abi, self.mem_operand_base_name(inst, mem))
        displacement = mem.mem.disp
        return_offset = None
        if inst.mnemonic in {"ld", "sd"}:
            if inst.operands[0].type == CS_OP_REG and inst.reg_name(inst.operands[0].reg) == "ra":
                return_offset = 0
        return StackAccess(base, displacement, self.mem_operand_size(inst, mem), return_offset)

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

        if symexpr.offset:
            return None
        anchor = symexpr.symbol.referent
        if not isinstance(anchor, gtirb.ByteBlock) or anchor.byte_interval is None:
            return None

        high_offset = anchor.offset + (anchor.size if symexpr.symbol.at_end else 0)
        high = anchor.byte_interval.symbolic_expressions.get(high_offset)
        if not isinstance(high, gtirb.SymAddrConst):
            return None
        if not (
                gtirb.SymbolicExpression.Attribute.GOT in high.attributes or
                gtirb.SymbolicExpression.Attribute.TLSGD in high.attributes or
                {
                    gtirb.SymbolicExpression.Attribute.PCREL,
                    gtirb.SymbolicExpression.Attribute.HI,
                }.issubset(high.attributes)):
            return None
        return high

    def mem_operand_address_expression(self, block, inst, operand, inst_offset=None):
        expression = self.operand_symbolic_expression(block, inst, operand, inst_offset)
        if isinstance(expression, gtirb.SymAddrConst) and {
                gtirb.SymbolicExpression.Attribute.PCREL,
                gtirb.SymbolicExpression.Attribute.LO,
        }.issubset(expression.attributes):
            # Rewriting temporarily isolates zero-size instruction anchors in
            # intervals without the AUIPC expression. Resolve the exact pair
            # now, while input IR is intact, not inside a deferred callback.
            # Retain symbol identity so later renaming still applies.
            high = self._paired_pcrel_hi_expression(expression)
            if high is None:
                raise ValueError("RISC-V memory PC-relative LO has no valid HI anchor")
            return gtirb.SymAddrConst(high.offset, high.symbol, high.attributes)
        return expression

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

    # Capstone decodes compressed instructions to their uncompressed real form (c.ldsp is ld, c.beqz is
    # beq with zero), so the uncompressed names cover them.
    @staticmethod
    def is_load_mnemonic(mnemonic: str) -> bool:
        return mnemonic in _RISCV64_LOAD_MNEMONICS

    @staticmethod
    def is_store_mnemonic(mnemonic: str) -> bool:
        return mnemonic in _RISCV64_STORE_MNEMONICS

    @staticmethod
    def is_branch_mnemonic(mnemonic: str) -> bool:
        return mnemonic in _RISCV64_BRANCH_MNEMONICS

    @staticmethod
    def registers_from_mem_operand(abi, inst: CsInsn, operand,
                                   flag_name: Optional[str] = None) -> Set[Register]:
        regs = set()
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
                for reg in cls.registers_from_mem_operand(abi, inst, operand)
                if reg.name.lower() in scratch_names
            )
        return result

    @staticmethod
    def riscv64_mem_operand_size(inst: CsInsn) -> int:
        mnemonic = inst.mnemonic.lower()
        atomic_access = riscv64_atomic_memory_access(mnemonic)
        if atomic_access is not None:
            return atomic_access[1]
        if mnemonic in {"lb", "lbu", "sb"}:
            return 1
        if mnemonic in {"lh", "lhu", "sh"}:
            return 2
        if mnemonic in {"lw", "lwu", "sw", "flw", "fsw"}:
            return 4
        if mnemonic in {"ld", "sd", "fld", "fsd"}:
            return 8
        return 8

    @staticmethod
    def memory_operand(inst):
        return next((op for op in inst.operands if op.type == CS_OP_MEM), None)

    def mem_operand_address_snippet(self, abi, inst, addr_reg, tmp_reg, mem_operand,
                                    stack_adjustment: int = 0, **kwargs) -> str:
        addr_reg = get_register(abi, addr_reg)
        tmp_reg = get_register(abi, tmp_reg)
        saved_reg_offsets = kwargs.get("saved_reg_offsets", {}) or {}
        stack_adjustment = stack_adjustment or 0

        mem_symexpr = kwargs.get("mem_symexpr")
        if isinstance(mem_symexpr, gtirb.SymAddrConst) and (
                gtirb.SymbolicExpression.Attribute.GOT in mem_symexpr.attributes or
                gtirb.SymbolicExpression.Attribute.TLSGD in mem_symexpr.attributes or
                {gtirb.SymbolicExpression.Attribute.PCREL,
                 gtirb.SymbolicExpression.Attribute.HI}.issubset(mem_symexpr.attributes)):
            return self._pcrel_address_snippet(addr_reg, mem_symexpr)
        if (
                isinstance(mem_symexpr, gtirb.SymAddrConst) and
                gtirb.SymbolicExpression.Attribute.LO in mem_symexpr.attributes and
                gtirb.SymbolicExpression.Attribute.PCREL not in mem_symexpr.attributes):
            target = self._symbolic_reference(mem_symexpr)
            return f"""
                lui {addr_reg}, %hi({target})
                addi {addr_reg}, {addr_reg}, %lo({target})
            """

        pcrel_hi = self._paired_pcrel_hi_expression(mem_symexpr)
        if pcrel_hi is not None:
            return self._pcrel_address_snippet(addr_reg, pcrel_hi)
        if isinstance(mem_symexpr, gtirb.SymAddrConst) and {
                gtirb.SymbolicExpression.Attribute.PCREL,
                gtirb.SymbolicExpression.Attribute.LO,
        }.issubset(mem_symexpr.attributes):
            raise ValueError("RISC-V memory PC-relative LO has no valid HI anchor")

        def load_original_reg(base_name: Optional[str]) -> str:
            normalized = abi.normalize_register_name(base_name)
            if normalized in saved_reg_offsets:
                return f"""
                    {self.load_address(addr_reg, f"scratchpad+{saved_reg_offsets[normalized]}")}
                    ld {addr_reg}, 0({addr_reg})
                """
            return f"mv {addr_reg}, {get_register(abi, base_name)}\n" if base_name else f"li {addr_reg}, 0\n"

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
        return self.registers_from_mem_operand(abi, inst, operand, flag_name)

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
        atomic_access = riscv64_atomic_memory_access(mnemonic)
        if atomic_access is not None:
            return atomic_access[0] in {"amo", "lr"}
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
        atomic_access = riscv64_atomic_memory_access(mnemonic)
        if atomic_access is not None:
            return atomic_access[0] in {"amo", "sc"}
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
