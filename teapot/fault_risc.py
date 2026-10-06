"""Exact scalar-load recipes for the v4 A64/RV64 adaptive backend.

Only the final emitter consumes these recipes. Covered loads and non-relocated
template words are raw data; relocation-bearing words use ordinary instruction
relocations. The same pure encoder reconstructs expected final-link bytes.
"""
from dataclasses import dataclass, replace
import struct

VERSION, ENTRY_SIZE, FLAGS, ISOLATION = 4, 128, 2, 65536
ORIG, MEMLOG, SHADOW = 1, 2, 3
DESTINATION, DEAD = 1, 2
MEMLOG_PREFIX = ".L__teapot_fault_memlog_"
SHADOW_PREFIX = ".L__teapot_fault_shadow_"
RV_NAMES = ("zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
            "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6")


def origin_marker(arch, origin):
    """Zero-byte producer provenance; never infer optimized LLVM load origin."""
    if not getattr(arch, "fault_memlog_markers", False):
        return ""
    if origin not in (MEMLOG, SHADOW):
        raise ValueError("unsupported generated RISC load origin")
    prefix = MEMLOG_PREFIX if origin == MEMLOG else SHADOW_PREFIX
    return f"{prefix}{arch.next_label_number('fault_risc_origin')}:\n"


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def ordinary_registers(isa):
    if isa == "aarch64":
        return frozenset(range(31)) - {18, 29}
    if isa == "riscv64":
        return frozenset(range(1, 32)) - {2, 3, 4, 8}
    raise ValueError("unsupported fault-check ISA")


@dataclass(frozen=True)
class Load:
    isa: str
    word: int
    width: int
    base: int
    destination: int
    displacement: int = 0
    index: int = 255
    extension: int = 0
    shift: int = 0
    kind: int = 0
    input_size: int = 4

    @property
    def code(self):
        return struct.pack("<I", self.word)

    @property
    def address_inputs(self):
        return {self.base} | ({self.index} if self.index != 255 else set())


def decode_load(isa, code):
    """Closed instruction vocabulary; never infer EA from printed operands.

    Includes scalar non-writeback ordinary loads only. SP/FP/platform-register
    operands, zero destinations, atomics, pairs, FP/SIMD and PC-relative loads
    stay on the kernel path. RV C.LW/C.LD widen semantically to LW/LD.
    """
    if isa not in ("aarch64", "riscv64") or len(code) not in (2, 4):
        return None
    input_size = len(code)
    word = int.from_bytes(code, "little")
    if isa == "aarch64":
        if input_size != 4 or word & (1 << 26):
            return None
        size, opc = word >> 30, (word >> 22) & 3
        if opc == 0 or (opc == 2 and size == 3) or (opc == 3 and size >= 2):
            return None
        base, dest = (word >> 5) & 31, word & 31
        if word & 0x3b000000 == 0x39000000:
            load = Load(isa, word, 1 << size, base, dest,
                        ((word >> 10) & 4095) << size, kind=1)
        elif word & 0x3b200c00 == 0x38000000:
            load = Load(isa, word, 1 << size, base, dest,
                        _signed((word >> 12) & 511, 9), kind=2)
        elif word & 0x3b200c00 == 0x38200800:
            extension = (word >> 13) & 7
            if extension not in (2, 3, 6, 7):
                return None
            load = Load(isa, word, 1 << size, base, dest, index=(word >> 16) & 31,
                        extension=extension, shift=size if word & 4096 else 0, kind=3)
        else:
            return None
    else:
        if input_size == 2:
            kind = word >> 13
            if word & 3 or kind not in (2, 3):
                return None
            dest, base = 8 + ((word >> 2) & 7), 8 + ((word >> 7) & 7)
            immediate = ((word >> 10) & 7) << 3
            immediate |= (((word >> 6) & 1) << 2 | ((word >> 5) & 1) << 6) if kind == 2 else \
                         ((word >> 5) & 3) << 6
            word = immediate << 20 | base << 15 | kind << 12 | dest << 7 | 3
        if word & 127 != 3 or (word >> 12) & 7 == 7:
            return None
        kind = (word >> 12) & 7
        load = Load(isa, word, 1 << (kind & 3), (word >> 15) & 31,
                    (word >> 7) & 31, _signed(word >> 20, 12), kind=4, input_size=input_size)
    ordinary = ordinary_registers(isa)
    if load.destination not in ordinary or not load.address_inputs <= ordinary:
        return None
    return load


class BoundaryMasks:
    """Snapshot validated masks at actual boundaries before *any* final split.

    Construct once after the last ordinary rewrite. Selection must consume all
    proofs before raw splits/widening. Moved or changed blocks cannot reuse the
    snapshot. ABI volatility and masks at former offsets are never evidence.
    """
    def __init__(self, manager, blocks, isa):
        import gtirb
        manager.refresh(preserve_liveness=True)
        self.module, self.masks, self.blocks = manager.module, manager.masks, {}
        self.names = tuple(manager.module.aux_data["liveRegisterNames"].data)
        self.rule = manager.module.aux_data["liveRegisterFlagRule"].data
        indices = {}
        for bit, register in enumerate(manager.registers):
            name = register.name
            number = None
            if isa == "aarch64" and name.startswith("x") and name[1:].isdigit():
                number = int(name[1:])
            elif isa == "riscv64" and name in RV_NAMES:
                number = RV_NAMES.index(name)
            if number in ordinary_registers(isa):
                indices[bit] = number
        for block in blocks:
            if block.module is not self.module or block.address is None:
                continue
            instructions = tuple(manager.decoder.get_instructions(block))
            actual = bytes(block.byte_interval.contents[block.offset:block.offset + block.size])
            if b"".join(bytes(i.bytes) for i in instructions) != actual:
                continue
            proofs = {}
            for insn in instructions:
                displacement = insn.address - block.address
                mask = self.masks.get(gtirb.Offset(block, displacement))
                if mask is not None:
                    proofs[displacement] = (mask, frozenset(number for bit, number in indices.items()
                                                            if not mask & (1 << bit)))
            self.blocks[block] = (block.byte_interval, block.offset, block.size, block.address, actual, proofs)

    def block_proofs(self, block):
        """One linear check per block; the candidate walk consumes this once."""
        import gtirb
        aux = self.module.aux_data.get("liveRegisterSets")
        names = self.module.aux_data.get("liveRegisterNames")
        rule = self.module.aux_data.get("liveRegisterFlagRule")
        saved = self.blocks.get(block)
        if (saved is None or aux is None or aux.data is not self.masks or
                names is None or tuple(names.data) != self.names or rule is None or rule.data != self.rule):
            return {}
        interval, offset, size, address, code, proofs = saved
        if ((block.byte_interval, block.offset, block.size, block.address) != (interval, offset, size, address) or
                bytes(interval.contents[offset:offset + size]) != code):
            return {}
        return {displacement: dead for displacement, (mask, dead) in proofs.items()
                if self.masks.get(gtirb.Offset(block, displacement)) == mask}

    def dead_gprs(self, block, displacement):
        return self.block_proofs(block).get(displacement, frozenset())


@dataclass(frozen=True)
class Recipe:
    bootstrap: int
    temp0: int
    temp1: int
    template: int


def choose_recipe(load, origin, dead=frozenset()):
    if load.input_size not in (2, 4) or decode_load(load.isa, load.code) != replace(load, input_size=4):
        return None
    if origin not in (ORIG, MEMLOG, SHADOW):
        return None
    ordinary = ordinary_registers(load.isa)
    if load.destination not in load.address_inputs:
        bootstrap, template = load.destination, DESTINATION
    else:
        # Generated instruction boundaries do not have original-input proof.
        candidates = (set(dead) & ordinary) - load.address_inputs - {load.destination}
        if origin != ORIG or not candidates:
            return None
        bootstrap, template = min(candidates), DEAD
    temps = sorted(ordinary - load.address_inputs - {load.destination, bootstrap})
    if len(temps) < 2:
        return None
    return Recipe(bootstrap, temps[0], temps[1], template)


def branch(isa, source, target):
    displacement = target - source
    if isa == "aarch64":
        if source & 3 or target & 3 or not -(1 << 27) <= displacement < (1 << 27):
            raise ValueError("A64 branch alignment/range")
        return 0x14000000 | ((displacement >> 2) & 0x3ffffff)
    if isa == "riscv64":
        if source & 1 or target & 1 or not -(1 << 20) <= displacement < (1 << 20):
            raise ValueError("RV JAL alignment/range")
        return 0x6f | ((displacement >> 20) & 1) << 31 | ((displacement >> 1) & 1023) << 21 | \
            ((displacement >> 11) & 1) << 20 | ((displacement >> 12) & 255) << 12
    raise ValueError("unsupported fault-check ISA")


@dataclass(frozen=True)
class Relocation:
    offset: int
    target: str
    kind: str
    anchor: int = 0


@dataclass(frozen=True)
class Template:
    isa: str
    code: bytes
    relocations: tuple
    copy_offset: int
    fail_offset: int


def guard_template(load, recipe):
    """Fixed words plus ordinary instruction relocations, no application stack.

    On a synchronous kernel-generated copied-load fault only transient rollback
    is legal: destination-bootstrap has changed D, so this fault context must
    never be printed or forwarded. Asynchronous faults and application signals
    retain the baseline instrumentation-context routing semantics.
    """
    expected = choose_recipe(load, ORIG if recipe.template == DEAD else MEMLOG,
                             {recipe.bootstrap} if recipe.template == DEAD else set())
    if expected != recipe:
        raise ValueError("invalid RISC register recipe")
    words, relocs = [], []
    b, t0, t1 = recipe.bootstrap, recipe.temp0, recipe.temp1
    def emit(word):
        words.append(word)
        return (len(words) - 1) * 4
    def address(register, target, middle=None):
        anchor = len(words) * 4
        if load.isa == "aarch64":
            relocs.append(Relocation(emit(0x90000000 | register), target, "page"))
            if middle is not None:
                emit(middle)
            relocs.append(Relocation(emit(0x91000000 | register << 5 | register), target, "lo12"))
        else:
            assert middle is None
            relocs.append(Relocation(emit(register << 7 | 0x17), target, "hi", anchor))
            relocs.append(Relocation(emit(register << 15 | register << 7 | 0x13), target, "lo", anchor))
    def rv_i(op, rd, rs, immediate=0):
        return op | rd << 7 | rs << 15 | (immediate & 4095) << 20
    def rv_store(rs, offset):
        return 0x3023 | (offset & 31) << 7 | b << 15 | rs << 20 | (offset >> 5) << 25
    def rv_cond(rs1, rs2, offset, funct3):
        if offset & 1 or not -4096 <= offset < 4096:
            raise ValueError("RV conditional branch range")
        return 0x63 | funct3 << 12 | rs1 << 15 | rs2 << 20 | ((offset >> 11) & 1) << 7 | \
            ((offset >> 1) & 15) << 8 | ((offset >> 5) & 63) << 25 | ((offset >> 12) & 1) << 31
    address(b, "spill")
    if load.isa == "aarch64":
        emit(0xf9000000 | b << 5 | t0)
        emit(0xf9000400 | b << 5 | t1)
        emit(0xd53b4200 | t0)                    # MRS NZCV
        emit(0xf9000800 | b << 5 | t0)
        if load.index != 255:
            emit(0x8b200000 | load.index << 16 | load.extension << 13 | load.shift << 10 |
                 load.base << 5 | t0)
        else:
            imm = abs(load.displacement)
            op = 0xd1000000 if load.displacement < 0 else 0x91000000
            emit(op | (imm & 4095) << 10 | load.base << 5 | t0)
            if imm >> 12:
                emit(op | 1 << 22 | (imm >> 12) << 10 | t0 << 5 | t0)
        # This useful, independent data-TBI normalization separates ADRP/ADD.
        # LLD may relax an adjacent policy pair to NOP/ADR, violating the exact
        # template. Keep the same words/count and all NZCV/GPR dependencies.
        address(t1, "policy", 0xd3400000 | 55 << 10 | t0 << 5 | t0)
        emit(0xf9400000 | t1 << 5 | t1)
        emit(0xeb00001f | t1 << 16 | t0 << 5)
        low = emit(0)
        emit(0xf9400800 | b << 5 | t0)
        emit(0xd51b4200 | t0)                    # MSR NZCV
        emit(0xf9400000 | b << 5 | t0)
        emit(0xf9400400 | b << 5 | t1)
    else:
        emit(rv_store(t0, 0)); emit(rv_store(t1, 8))
        emit(rv_i(0x13, t0, load.base, load.displacement))
        address(t1, "policy")
        emit(rv_i(0x3003, t1, t1))
        low = emit(0)
        address(t1, "policy")
        emit(rv_i(0x3003, t1, t1, 8))
        disabled = emit(0)
        high = emit(0)
        restore = len(words) * 4
        words[disabled // 4] = rv_cond(t1, 0, restore - disabled, 0)
        emit(rv_i(0x3003, t0, b)); emit(rv_i(0x3003, t1, b, 8))
    copy = emit(load.word)
    relocs.append(Relocation(emit(0x14000000 if load.isa == "aarch64" else 0x6f), "return", "branch"))
    fail = len(words) * 4
    if load.isa == "aarch64":
        words[low // 4] = 0x54000003 | ((fail - low) // 4) << 5  # B.LO
        relocs.append(Relocation(emit(0x14000000), "rollback", "branch"))
    else:
        words[low // 4] = rv_cond(t0, t1, fail - low, 6)
        words[high // 4] = rv_cond(t0, t1, fail - high, 7)
        # Only this fail arm uses architectural t0, explicitly destroyed by
        # the existing rollback wrapper; never gp/tp/sp or a continuation.
        address(5, "rollback")
        emit(rv_i(0x67, 0, 5))
    return Template(load.isa, struct.pack("<" + "I" * len(words), *words), tuple(relocs), copy, fail)


def resolve_template(template, start, targets):
    """Reconstruct expected bytes for validation/tests, not an ELF mutator."""
    code = bytearray(template.code)
    for reloc in template.relocations:
        word = struct.unpack_from("<I", code, reloc.offset)[0]
        target = targets[reloc.target]
        if reloc.kind == "branch":
            word = branch(template.isa, start + reloc.offset, target)
        elif reloc.kind == "page":
            delta = (target >> 12) - ((start + reloc.offset) >> 12)
            if not -(1 << 20) <= delta < (1 << 20):
                raise ValueError("A64 ADRP range")
            word |= (delta & 3) << 29 | ((delta >> 2) & 0x7ffff) << 5
        elif reloc.kind == "lo12":
            word |= (target & 4095) << 10
        else:
            delta = target - (start + reloc.anchor)
            high = (delta + 0x800) >> 12
            if not -(1 << 19) <= high < (1 << 19):
                raise ValueError("RV AUIPC range")
            word |= (high & 0xfffff) << 12 if reloc.kind == "hi" else (delta & 4095) << 20
        struct.pack_into("<I", code, reloc.offset, word)
    return bytes(code)
