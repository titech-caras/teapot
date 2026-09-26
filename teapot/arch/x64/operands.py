import re

import capstone.x86
import gtirb
from capstone import CS_AC_READ, CS_AC_WRITE, CS_OP_MEM, CS_OP_REG
from capstone.x86 import X86_REG_INVALID, X86_REG_RIP
from gtirb_capstone.x86 import mem_access_to_str, operand_symbolic_expression


class X64OperandMixin:
    @staticmethod
    def rep_string_kind(inst):
        # String instructions have a one-byte opcode and no encoded operands.
        # Capstone drops F2 from prefix[] on noncanonical MOVSD string forms;
        # inspect the bytes without confusing these with SSE MOVSD/CMPSD.
        kind = {0xa4: "movs", 0xa5: "movs", 0xaa: "stos", 0xab: "stos",
                0xac: "lods", 0xad: "lods", 0xa6: "cmps", 0xa7: "cmps",
                0xae: "scas", 0xaf: "scas"}.get(inst.opcode[0])
        if kind and any(prefix in (0xf2, 0xf3) for prefix in inst.bytes[:-1]):
            return kind
        return None

    # Capstone (5 and 6.0) reports the memory destination of the four rotate
    # families as read-only, even though these forms update it in place.
    # Keep this narrow: comparisons and tests also have a first, read-only
    # memory operand.
    _UNMARKED_MEMORY_RMW_MNEMONICS = frozenset(("rcl", "rcr", "rol", "ror"))
    _SETCC_MNEMONICS = frozenset((
        "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta",
        "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg",
    ))
    # Capstone (5 and 6.0) marks scalar FST/FSTP, FIST/FISTP/FISTTP and FNSTCW
    # memory destinations as reads. These x87 forms have an implicit source, so
    # the vector-source recognizer cannot see them. Include the correctly marked
    # widths too, keeping the architectural store families together.
    _X87_MEMORY_STORE_MNEMONICS = frozenset((
        "fst", "fstp", "fist", "fistp", "fisttp", "fbstp", "fnstcw", "fnstsw",
        "fnstenv", "fnsave",
    ))
    _SEGMENT_OVERRIDE_RE = re.compile(r"(?i)(?<![0-9A-Za-z_])(fs|gs):")
    _REGISTER_NAMES = frozenset(
        name[len("X86_REG_"):].lower()
        for name in dir(capstone.x86)
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

        Capstone (5 and 6.0) labels the memory destination of instructions
        such as ``movq [rdi], xmm8`` as read-only.  Intel syntax places that
        destination first and a vector source later in the operand list, which
        distinguishes the store from scalar memory comparisons and vector loads.
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
    def _is_setcc_memory_store(cls, inst, operand) -> bool:
        # Capstone (5 and 6.0) marks most SETcc memory destinations as read-only.
        # Every condition writes one byte, including zero when false; omitting
        # its memlog entry allows a transient store to survive rollback.
        return bool(
            len(inst.operands) == 1 and inst.operands[0] == operand and
            operand.type == CS_OP_MEM and operand.size == 1 and
            inst.mnemonic.lower() in cls._SETCC_MNEMONICS
        )

    @classmethod
    def _is_x87_memory_store(cls, inst, operand) -> bool:
        return bool(
            len(inst.operands) == 1 and inst.operands[0] == operand and
            operand.type == CS_OP_MEM and
            inst.mnemonic.lower() in cls._X87_MEMORY_STORE_MNEMONICS
        )

    @staticmethod
    def is_x87_instruction(inst) -> bool:
        # The legacy x87 escapes and FWAIT. Capstone's FPU group omits some
        # forms, notably FNSTSW AX; opcodes also avoid matching SSE mnemonics.
        return inst.opcode[0] == 0x9b or 0xd8 <= inst.opcode[0] <= 0xdf

    @staticmethod
    def mem_operand_size(inst, operand) -> int:
        if operand is None:
            return 0
        # Capstone (5 and 6.0) reports F(N)SAVE/FRSTOR as 4 bytes and overlooks
        # 66h on F(N)STENV/FLDENV. These legacy images use 16/32-bit operand
        # sizes, including in long mode: a 14/28-byte environment and eight
        # 10-byte x87 registers in the full state image.
        if inst.mnemonic in ("fnsave", "frstor", "fnstenv", "fldenv"):
            size = 14 if 0x66 in inst.prefix else 28
            return size + 80 if inst.mnemonic in ("fnsave", "frstor") else size
        return operand.size

    @classmethod
    def mem_operand_is_read(cls, inst, operand) -> bool:
        if cls.is_x87_instruction(inst):
            # x87 memory forms are either loads or stores, not RMW. Capstone (5
            # and 6.0) also marks FRSTOR as a write.
            return not cls._is_x87_memory_store(inst, operand)
        if (cls._is_unmarked_vector_store(inst, operand) or
                cls._is_setcc_memory_store(inst, operand)):
            return False
        return bool(operand.access & CS_AC_READ)

    @classmethod
    def mem_operand_is_write(cls, inst, operand) -> bool:
        if cls.is_x87_instruction(inst):
            # In particular, a ten-byte FLD/FBLD must not fall through to the
            # legacy wide-memory heuristic and be mistaken for a store.
            return cls._is_x87_memory_store(inst, operand)
        # Capstone misses write accesses for some vector stores and memory
        # read-modify-write instructions.  Recover only instruction shapes
        # whose destination semantics are unambiguous.
        return bool(
            operand.access & CS_AC_WRITE or
            (inst.operands[0] == operand and inst.operands[0].size > 8) or
            cls._is_unmarked_vector_store(inst, operand) or
            cls._is_unmarked_memory_rmw(inst, operand) or
            cls._is_setcc_memory_store(inst, operand)
        )

    @staticmethod
    def mem_operand_uses_dynamic_address(mem_operand) -> bool:
        return not (
            mem_operand.mem.base in (X86_REG_INVALID, X86_REG_RIP) and
            mem_operand.mem.index == capstone.x86.X86_REG_INVALID
        )
