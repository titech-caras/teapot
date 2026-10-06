"""Final-ELF validation for training-only fault tables, shared by both pipelines.

Addresses here are ELF virtual addresses (before a PIE's common load bias).
No rewrite-time ordering or section-permission assertion substitutes for this
check. Startup checks actual mapping permissions again before training.
"""
import struct
from bisect import bisect_right
from teapot.preprocess.fault_sites import MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE, TRAINING_ONLY

_HEADER = struct.Struct("<IHHIIII8q3Q")
_ENTRY = struct.Struct("<iiiHH")


def require(condition, message):
    if not condition: raise ValueError("fault metadata: " + message)


def resolve(anchor, offset):
    result = anchor + offset
    require(0 <= anchor <= 0xffffffffffffffff and 0 <= result <= 0xffffffffffffffff,
            "relative address overflow")
    return result


def extent(elf, start, end, flags, *, nobits=False):
    require(0 <= start < end <= 0xffffffffffffffff, "bad extent")
    sections = [s for s in elf.iter_sections() if s["sh_addr"] <= start and
                end <= s["sh_addr"] + s["sh_size"] and s["sh_flags"] & 7 == flags]
    require(len(sections) == 1, "extent/section permissions")
    section = sections[0]
    if nobits:
        require(section.name == "teapot_protected_bss" and section["sh_type"] == "SHT_NOBITS",
                "counter storage is not protected NOBITS")
    require(any(p["p_type"] == "PT_LOAD" and p["p_vaddr"] <= start and
                end <= p["p_vaddr"] + p["p_memsz"] and p["p_flags"] & 7 ==
                (6 if flags & 1 else 5 if flags & 4 else 4) for p in elf.iter_segments()),
            "extent/load permissions")
    return section


def access_bytes(elf, pc, length):
    section = extent(elf, pc, pc + length, 6)
    require(section["sh_type"] == "SHT_PROGBITS", "access is not file-backed code")
    offset = pc - section["sh_addr"]
    code = section.data()[offset:offset + length]
    require(len(code) == length, "truncated access")
    return code


def validate_access(machine, pc, code):
    """An exact copy is sound only for one non-PC-relative data instruction.

    Final backends must also prove the stub's full save/check/return sequence;
    this training-only validator deliberately does not approve a publisher.
    """
    import capstone as cs
    from capstone import x86_const, aarch64_const, riscv_const
    arch, mode, memory = {
        "EM_X86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64, x86_const.X86_OP_MEM),
        "EM_AARCH64": (cs.CS_ARCH_AARCH64, 0, aarch64_const.AARCH64_OP_MEM),
        "EM_RISCV": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64, riscv_const.RISCV_OP_MEM),
    }[machine]
    decoder = cs.Cs(arch, mode); decoder.detail = True
    instructions = list(decoder.disasm(code, pc, count=2))
    require(len(instructions) == 1 and instructions[0].size == len(code), "not one complete access instruction")
    insn = instructions[0]
    require(not any(group in insn.groups for group in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET,
                                                       cs.CS_GRP_INT, cs.CS_GRP_IRET)) and
            insn.mnemonic not in ("lea", "leaq", "leal"), "not a data access")
    operands = [operand for operand in insn.operands if operand.type == memory]
    require(len(operands) == 1, "needs one explicit memory operand")
    mem = operands[0].mem
    excluded = {"rip", "eip", "rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "s0", "fp", "pc"}
    require(mem.base and insn.reg_name(mem.base) not in excluded and
            (not getattr(mem, "index", 0) or insn.reg_name(mem.index) not in excluded) and
            not getattr(mem, "segment", 0), "PC/SP/FP-relative or segmented access is not supported")


def validate_table(elf, address):
    require(elf.elfclass == 64 and elf.little_endian, "requires little-endian ELF64")
    require(address % 8 == 0, "misaligned table")
    section = extent(elf, address, address + HEADER_SIZE, 2)
    require(section["sh_type"] == "SHT_PROGBITS", "table is not file-backed")
    data = section.data(); offset = address - section["sh_addr"]
    require(offset + HEADER_SIZE <= len(data), "truncated header")
    fields = _HEADER.unpack_from(data, offset)
    magic, version, header, entry_size, count, flags, threshold = fields[:7]
    if version == 3:
        from teapot.fault_window_validation import validate_windows
        return validate_windows(elf, address)
    require((magic, version, header, entry_size, flags) ==
            (MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE, TRAINING_ONLY), "unsupported table format")
    require(count > 0 and threshold <= 255 and not any(fields[15:]), "count/threshold/reserved")
    total = HEADER_SIZE + count * ENTRY_SIZE
    extent(elf, address, address + total, 2)
    require(offset + total <= len(data), "truncated entries")
    ranges = [resolve(address + 24 + 8 * i, value) for i, value in enumerate(fields[7:15])]
    start, end, ss, se, cs, ce, ps, pe = ranges
    require(start <= ss < se <= end, "stub/text extent")
    extent(elf, start, end, 6); extent(elf, ss, se, 6)
    storage = (count + 7) & ~7
    require(cs % 8 == ps % 8 == 0 and ce - cs == pe - ps == storage and
            (ce <= ps or pe <= cs), "counter/pending extent or overlap")
    extent(elf, cs, ce, 3, nobits=True); extent(elf, ps, pe, 3, nobits=True)
    entries = []; previous_end = start
    for i in range(count):
        here = address + HEADER_SIZE + i * ENTRY_SIZE
        pc_relative, stub_relative, copy_relative, length, reserved = _ENTRY.unpack_from(
            data, offset + HEADER_SIZE + i * ENTRY_SIZE)
        pc, stub, copy = resolve(here, pc_relative), resolve(here + 4, stub_relative), resolve(here + 8, copy_relative)
        require(not reserved and length > 0, "entry length/reserved")
        require(start <= pc < pc + length <= end and ss <= stub < se and ss <= copy < copy + length <= se,
                "entry outside text/stub extent")
        require(pc >= previous_end, "fault PCs not sorted, unique and non-overlapping")
        previous_end = pc + length
        machine = elf["e_machine"]
        distance = stub - pc
        if machine == "EM_AARCH64":
            require(length == 4 and pc % 4 == stub % 4 == copy % 4 == 0 and
                    -(1 << 27) <= distance < (1 << 27), "AArch64 length/alignment/reach")
        elif machine == "EM_RISCV":
            require(length == 4 and pc % 4 == stub % 4 == copy % 4 == 0 and
                    -(1 << 20) <= distance < (1 << 20), "RISC-V length/alignment/reach")
        elif machine == "EM_X86_64":
            require(5 <= length <= 15 and -(1 << 31) <= distance - 5 < (1 << 31), "x64 length/reach")
        else:
            require(False, "unsupported ISA")
        original = access_bytes(elf, pc, length)
        copied = access_bytes(elf, copy, length)
        require(original == copied, "copied access bytes differ")
        validate_access(machine, pc, original); validate_access(machine, copy, copied)
        entries.append((pc, stub, copy, length))
    pcs = [entry[0] for entry in entries]
    copies = sorted((copy, length) for _, _, copy, length in entries)
    for i, (copy, length) in enumerate(copies):
        require(not i or copies[i - 1][0] + copies[i - 1][1] <= copy,
                "duplicate or overlapping copied access PCs")
        j = bisect_right(pcs, copy + length - 1) - 1
        require(j < 0 or entries[j][0] + entries[j][3] <= copy, "copy overlaps original access")
    return dict(address=address, version=version, count=count, threshold=threshold, flags=flags,
                text=(start, end), counters=(cs, ce), pending=(ps, pe), entries=entries)


def validate_module_tables(elf, modules):
    """Module record dictionaries from the final-link contract parser."""
    from teapot.runtime_contract import capability_bits
    tables = []
    for record in modules:
        pointer = record["fault_sites"]
        required = bool(record["capabilities"] & capability_bits({"fault_training"}))
        policy = record["contract"].get("policy", {}).get("fault_training", False)
        require(type(policy) is bool and required == bool(pointer) == policy,
                "table/capability/policy disagreement")
        if pointer: tables.append(validate_table(elf, pointer))
        publishing = bool(record["capabilities"] & capability_bits({"fault_publishing"}))
        publisher_policy = record["contract"].get("policy", {}).get("fault_publishing", False)
        require(type(publisher_policy) is bool and publishing == publisher_policy and
                publishing == bool(pointer and tables[-1]["version"] == 3), "publisher format/capability/policy disagreement")
    tables.sort(key=lambda t: t["text"][0])
    for i, table in enumerate(tables):
        if i: require(tables[i - 1]["text"][1] <= table["text"][0], "overlapping module text ranges")
        for other in tables[:i]:
            for a in (table["counters"], table["pending"]):
                for b in (other["counters"], other["pending"]):
                    require(a[1] <= b[0] or b[1] <= a[0], "modules share training storage")
    return tables
