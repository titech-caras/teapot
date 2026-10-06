"""x64 adaptive prechecks: exact windows and a deliberately small raw template.

The cold template never touches the application's stack, DF or vector state.
Its three private words are not allocator spill slots. LAHF/SETO + ADD/SAHF
preserve the six arithmetic flags on the continuation path. The runtime is
single-threaded, as is the rest of libcheckpoint's scratch storage.

Raw bytes are intentional: printing an instruction can shorten its encoding.
Relative fields, including a displaced RIP-relative operand, remain symbolic.
Both final-link and startup validation use the template, not a promise in JSON.
"""
from dataclasses import dataclass
from bisect import bisect_left, bisect_right
import struct

WINDOW_VERSION = 3
WINDOW_ENTRY_SIZE = 128
WINDOW_FLAGS = 2
MAX_WINDOW = 19  # a <5-byte prefix followed by one <=15-byte instruction
ORIG, MEMLOG = 1, 2
REGISTERS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
REG32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
         "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
GPR_NAMES = frozenset(REGISTERS + REG32 + ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "spl", "bpl", "sil", "dil") +
    tuple(f"r{number}{suffix}" for number in range(8, 16) for suffix in ("b", "w")))
INPUT_TAG = "TEAPOT_FAULT_ORIG"
MEMLOG_PREFIX = ".L__teapot_fault_memlog_"


class Boundaries:
    """Indexed reference/marker barriers; selection must not scan a whole ELF."""
    def __init__(self, addresses):
        self.values = frozenset(addresses)
        self.ordered = tuple(sorted(self.values))

    def __contains__(self, address): return address in self.values

    def interior(self, start, end):
        index = bisect_right(self.ordered, start)
        return index < len(self.ordered) and self.ordered[index] < end


def interior_boundary(boundaries, start, end):
    if isinstance(boundaries, Boundaries): return boundaries.interior(start, end)
    return any(start < target < end for target in boundaries)


@dataclass(frozen=True)
class Address:
    base: int
    index: int = 255
    scale: int = 1
    displacement: int = 0
    width: int = 64

    def lea(self):
        if (self.base not in range(16) or self.base in (4, 5) or
                self.index not in (*range(16), 255) or self.index in (4, 5) or
                self.scale not in (1, 2, 4, 8) or self.width not in (32, 64) or
                not -(1 << 31) <= self.displacement < (1 << 31) or
                (self.index == 255 and self.scale != 1)):
            raise ValueError("unsupported fault-check effective address")
        sib = self.index != 255 or self.base % 8 == 4
        rex = (0x4c if self.width == 64 else 0x44) | (self.base >> 3)
        if self.index != 255: rex |= (self.index >> 3) << 1
        code = (b"\x67" if self.width == 32 else b"") + bytes((rex, 0x8d, 0x98 | (4 if sib else self.base % 8)))
        if sib:
            code += bytes(((1, 2, 4, 8).index(self.scale) << 6 |
                           (4 if self.index == 255 else self.index % 8) << 3 | self.base % 8,))
        return code + struct.pack("<i", self.displacement)


def decoder():
    import capstone as cs
    result = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    result.detail = True
    return result


def scalar_access(instruction):
    """First slice: ordinary scalar accesses with one exact, explicit GPR EA.

    Bit-test memory operands, implicit/string accesses and every instruction
    with LOCK/REP are excluded: their dereference is not this simple EA.
    """
    from capstone import x86_const as x
    allowed = {"mov", "movabs", "movzx", "movsx", "movsxd", "cmp", "test",
               "add", "adc", "sub", "sbb", "and", "or", "xor", "inc", "dec",
               "neg", "not", "imul", "mul", "idiv", "div", "shl", "shr", "sar",
               "sal", "rol", "ror", "rcl", "rcr"}
    # CMOV can read memory even when its condition is false.
    if instruction.mnemonic not in allowed and not instruction.mnemonic.startswith("cmov"):
        return None
    if any(prefix in (0xf0, 0xf2, 0xf3) for prefix in instruction.prefix): return None
    memory = [op for op in instruction.operands if op.type == x.X86_OP_MEM]
    if len(memory) != 1 or memory[0].size not in (1, 2, 4, 8): return None
    if any(op.type == x.X86_OP_REG and instruction.reg_name(op.reg) not in GPR_NAMES
           for op in instruction.operands): return None
    mem = memory[0].mem
    if mem.segment: return None
    names = REG32 if instruction.addr_size == 4 else REGISTERS
    base, index = instruction.reg_name(mem.base), instruction.reg_name(mem.index)
    if base not in names or (index and index not in names): return None
    address = Address(names.index(base), names.index(index) if index else 255,
                      mem.scale if index else 1, mem.disp, instruction.addr_size * 8)
    try: address.lea()
    except ValueError: return None
    return address


def movable(instruction):
    """An intentionally bounded tail-copy vocabulary; no control or I/O.

    Moving RIP-relative data accesses is allowed only with a proved symbolic
    operand. Selection's relocation check handles that independently.
    """
    if scalar_access(instruction) is not None: return True
    from capstone import x86_const as x
    if any(prefix in (0xf0, 0xf2, 0xf3) for prefix in instruction.prefix): return False
    if instruction.mnemonic not in {"mov", "movzx", "movsx", "movsxd", "lea", "cmp", "test", "add", "adc",
                                    "sub", "sbb", "and", "or", "xor", "inc", "dec", "neg", "not", "nop",
                                    "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr"}:
        return False
    for op in instruction.operands:
        if op.type == x.X86_OP_MEM:
            # 32-bit EIP-relative arithmetic wraps; this backend's symbolic
            # copy relocation proves only the ordinary 64-bit RIP form.
            if op.mem.segment or instruction.reg_name(op.mem.base) != "rip": return False
        elif op.type == x.X86_OP_REG:
            name = instruction.reg_name(op.reg)
            if name not in GPR_NAMES or name in ("rsp", "esp", "sp", "spl"):
                return False
    return True


def select_window(instructions, index, boundaries=()):
    """Select complete instructions within one block, stopping at references.

    A failed selection does NOT silently select a window across a target.
    The caller may separately widen the covered instruction, or skip the site.
    """
    access = instructions[index]
    if scalar_access(access) is None: return ()
    start = access.address; selected = []
    for insn in instructions[index:]:
        if insn.address != start + sum(i.size for i in selected): return ()
        if selected and (insn.address in boundaries or not movable(insn)): return ()
        if interior_boundary(boundaries, insn.address, insn.address + insn.size): return ()
        selected.append(insn)
        if sum(i.size for i in selected) >= 5: return tuple(selected)
    return ()


def guard_template(address, window):
    """Return raw template, symbolic disp32 fields and copy offset.

    Each relocation tuple is (offset, target-key, addend), relative to its own
    4-byte field. Target-key can be spill/low/rollback/return. The failure jump
    uses the assembly wrapper, never the C restore function.
    """
    code = bytearray(); relocations = []
    def relative(opcode, target, offset=0):
        code.extend(opcode); at = len(code); code.extend(bytes(4))
        relocations.append((at, target, offset - 4)); return at
    relative(b"\x48\x89\x05", "spill")       # saved rax
    relative(b"\x4c\x89\x1d", "spill", 8)    # saved r11
    code.extend(b"\x9f\x0f\x90\xc0\x0f\xb7\xc0")
    relative(b"\x48\x89\x05", "spill", 16)   # packed arithmetic flags
    relative(b"\x48\x8b\x05", "spill")
    code.extend(address.lea())
    relative(b"\x4c\x3b\x1d", "low")
    low_fail = relative(b"\x0f\x82", "fail")
    code.extend(b"\x49\xc1\xeb\x38")
    high_fail = relative(b"\x0f\x85", "fail")
    relative(b"\x48\x8b\x05", "spill", 16)
    code.extend(b"\x04\x7f\x9e")
    relative(b"\x48\x8b\x05", "spill")
    relative(b"\x4c\x8b\x1d", "spill", 8)
    copy = len(code); code.extend(window)
    relative(b"\xe9", "return")
    fail = len(code)
    relative(b"\xe9", "rollback")
    for at in (low_fail, high_fail): struct.pack_into("<i", code, at, fail - at - 4)
    return bytes(code), tuple(r for r in relocations if r[1] != "fail"), copy


def instantiate_guard(address, window, pc, targets):
    code, relocations, copy = guard_template(address, window)
    code = bytearray(code)
    for offset, key, addend in relocations:
        relative = targets[key] - (pc + offset) + addend
        if not -(1 << 31) <= relative < (1 << 31): raise ValueError("fault stub rel32 out of reach")
        struct.pack_into("<i", code, offset, relative)
    return bytes(code), copy


def mark_input(section, decoder):
    # gtirb-rewriting's edit-aware offset map follows inserts and replacements.
    from gtirb_rewriting import _auxdata_offsetmap
    import gtirb
    comments = _auxdata_offsetmap.comments.get_or_insert(section.module)
    for block in sorted(section.code_blocks, key=lambda b: (b.offset, b.uuid.int)):
        offset = 0
        for insn in decoder.get_instructions(block):
            key = gtirb.Offset(block, offset); old = comments.get(key, "")
            comments[key] = old + ("\n" if old else "") + INPUT_TAG
            offset += insn.size
