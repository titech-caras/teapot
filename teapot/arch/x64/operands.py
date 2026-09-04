import re

import capstone_gt.x86
import gtirb
from capstone_gt import CS_AC_READ, CS_AC_WRITE, CS_OP_REG
from capstone_gt.x86 import X86_REG_INVALID, X86_REG_RIP
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression


class X64OperandMixin:
    # Capstone 5 reports the memory destination of the four rotate families as
    # read-only, even though these forms update it in place.  Keep this narrow:
    # comparisons and tests also have a first, read-only memory operand.
    _UNMARKED_MEMORY_RMW_MNEMONICS = frozenset(("rcl", "rcr", "rol", "ror"))
    _SEGMENT_OVERRIDE_RE = re.compile(r"(?i)(?<![0-9A-Za-z_])(fs|gs):")
    _REGISTER_NAMES = frozenset(
        name[len("X86_REG_"):].lower()
        for name in dir(capstone_gt.x86)
        if name.startswith("X86_REG_")
    )

    @staticmethod
    def operand_symbolic_expression(block: gtirb.CodeBlock, inst, operand, inst_offset=None):
        if not hasattr(operand, "type"):
            return None
        return operand_symbolic_expression(block, inst, operand)

    @classmethod
    def _disambiguate_register_named_symbols(
            cls, operand_str: str, symexpr: gtirb.SymbolicExpression) -> str:
        if isinstance(symexpr, gtirb.SymAddrConst):
            symbols = (symexpr.symbol,)
        else:
            symbols = ()

        for symbol in symbols:
            name = symbol.name
            if name.lower() not in cls._REGISTER_NAMES:
                continue
            token = re.compile(
                rf"(?<![0-9A-Za-z_.$@]){re.escape(name)}"
                rf"(?![0-9A-Za-z_.$@])(?!\s*:)")
            operand_str, replacements = token.subn(
                f"offset {name}", operand_str, count=1)
            if replacements != 1:
                raise ValueError(
                    f"could not disambiguate register-named symbol {name!r} "
                    f"in {operand_str!r}")
        return operand_str

    def mem_operand_to_str(self, block: gtirb.CodeBlock, inst, mem_operand) -> str:
        try:
            symexpr = self.operand_symbolic_expression(block, inst, mem_operand)
            operand_str = mem_access_to_str(inst, mem_operand.mem, symexpr)
            return self._disambiguate_register_named_symbols(operand_str, symexpr)
        except NotImplementedError:
            print(f"Warning: unsupported symexp at {inst}")
            return mem_access_to_str(inst, mem_operand.mem, None)

    @classmethod
    def mem_operand_segment(cls, mem_operand_str: str):
        match = cls._SEGMENT_OVERRIDE_RE.search(mem_operand_str)
        return match.group(1).lower() if match else None

    @classmethod
    def effective_address_snippet(cls, addr_reg, mem_operand_str: str, segment_reg=None) -> str:
        """Materialize the linear address of an x86 memory operand.

        LEA deliberately ignores FS/GS segment bases.  Instrumentation that
        needs a linear address must therefore read the segment base and add it
        explicitly instead of emitting ``lea reg, fs:[...]``.
        """
        segment = cls.mem_operand_segment(mem_operand_str)
        if segment is None:
            return f"lea {addr_reg}, {mem_operand_str}\n"
        if segment_reg is None:
            raise ValueError("a scratch register is required for an FS/GS address")
        segmentless, replacements = cls._SEGMENT_OVERRIDE_RE.subn(
            "", mem_operand_str, count=1)
        assert replacements == 1
        return f"""
            lea {addr_reg}, {segmentless}
            rd{segment}base {segment_reg}
            lea {addr_reg}, [{addr_reg} + {segment_reg}]
        """

    @staticmethod
    def _is_unmarked_vector_store(inst, operand) -> bool:
        """Recognize store forms whose memory access flags Capstone gets wrong.

        Capstone 5 labels the memory destination of instructions such as
        ``movq [rdi], xmm8`` as read-only.  Intel syntax places that destination
        first and a vector source later in the operand list, which distinguishes
        the store from scalar memory comparisons and vector loads.
        """
        if not inst.operands or inst.operands[0] != operand:
            return False
        for source in inst.operands[1:]:
            if source.type != CS_OP_REG:
                continue
            name = inst.reg_name(source.reg).lower()
            if name.startswith(("xmm", "ymm", "zmm", "mm", "k")):
                return True
        return False

    @classmethod
    def _is_unmarked_memory_rmw(cls, inst, operand) -> bool:
        """Recognize read-modify-write forms Capstone labels read-only."""
        return bool(
            inst.operands and
            inst.operands[0] == operand and
            operand.access & CS_AC_READ and
            inst.mnemonic.lower() in cls._UNMARKED_MEMORY_RMW_MNEMONICS
        )

    @classmethod
    def mem_operand_is_read(cls, inst, operand) -> bool:
        if cls._is_unmarked_vector_store(inst, operand):
            return False
        return bool(operand.access & CS_AC_READ)

    @classmethod
    def mem_operand_is_write(cls, inst, operand) -> bool:
        # Capstone misses write accesses for some vector stores and memory
        # read-modify-write instructions.  Recover only instruction shapes
        # whose destination semantics are unambiguous.
        return bool(
            operand.access & CS_AC_WRITE or
            (inst.operands[0] == operand and inst.operands[0].size > 8) or
            cls._is_unmarked_vector_store(inst, operand) or
            cls._is_unmarked_memory_rmw(inst, operand)
        )

    @staticmethod
    def mem_operand_uses_dynamic_address(mem_operand) -> bool:
        return not (
            mem_operand.mem.base in (X86_REG_INVALID, X86_REG_RIP) and
            mem_operand.mem.index == capstone_gt.x86.X86_REG_INVALID
        )
