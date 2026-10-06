"""Publisher validation on the final linked ELF, before execution."""
import struct
from bisect import bisect_right

from teapot.fault_x64 import (Address, decoder, scalar_access, movable, instantiate_guard,
                              WINDOW_VERSION, WINDOW_ENTRY_SIZE, WINDOW_FLAGS)
from teapot.preprocess.fault_sites import MAGIC, HEADER_SIZE


def require_isolated_copy_pages(elf, start, end):
    """No PLT, runtime code or other allocated section may share a patch page."""
    from teapot.fault_sites import require
    first, last = start & ~4095, (end + 4095) & ~4095
    for section in elf.iter_sections():
        if not section["sh_flags"] & 2 or not section["sh_size"]:
            continue
        begin, finish = section["sh_addr"], section["sh_addr"] + section["sh_size"]
        if section.name == ".teapot_transient":
            require((begin, finish) == (start, end), "publisher range differs from its transient section")
        else:
            require(finish <= first or last <= begin,
                    "allocated section shares a patchable page: " + section.name)
    require(start % 4096 == end % 4096 == 0, "publisher copy text is not page-isolated")


def validate_windows(elf, address):
    from teapot.fault_sites import require, resolve, extent, access_reader
    read_access = access_reader(elf)
    require(elf["e_machine"] == "EM_X86_64" and elf.elfclass == 64 and elf.little_endian,
            "window publisher requires little-endian x64")
    require(address % 8 == 0, "misaligned window table")
    section = extent(elf, address, address + HEADER_SIZE, 2)
    data = section.data(); at = address - section["sh_addr"]
    header = struct.unpack_from("<IHHIIII8q3Q", data, at)
    require(header[:4] == (MAGIC, WINDOW_VERSION, HEADER_SIZE, WINDOW_ENTRY_SIZE) and
            header[5] == WINDOW_FLAGS and header[4] > 0 and header[6] <= 255 and not any(header[15:]),
            "unsupported window header")
    count = header[4]; total = HEADER_SIZE + count * WINDOW_ENTRY_SIZE
    extent(elf, address, address + total, 2)
    require(at + total <= len(data), "truncated window table")
    start, end, ss, se, cs, ce, ps, pe = [resolve(address + 24 + 8 * i, v) for i, v in enumerate(header[7:15])]
    require(start <= ss < se <= end, "window text/stub ranges")
    require_isolated_copy_pages(elf, start, end)
    extent(elf, start, end, 6); extent(elf, ss, se, 6)
    storage = (count + 7) & ~7
    require(cs % 8 == ps % 8 == 0 and ce - cs == pe - ps == storage and (ce <= ps or pe <= cs),
            "window counter/pending storage")
    extent(elf, cs, ce, 3, nobits=True); extent(elf, ps, pe, 3, nobits=True)
    symtab = elf.get_section_by_name(".symtab")
    require(symtab is not None, "window validation requires the unstripped final ELF")
    symbols = list(symtab.iter_symbols())
    def owned(name):
        values = {s["st_value"] for s in symbols if s.name == name and s["st_shndx"] != "SHN_UNDEF"}
        require(len(values) == 1, "runtime-owned symbol missing or ambiguous: " + name)
        return next(iter(values))
    low, rollback = owned("teapot_fault_low_bound"), owned("restore_checkpoint_SIGSEGV")
    entries = []; block_extents = set(); previous_end = start; previous_spill = 0; dec = decoder()
    for i in range(count):
        offset = at + HEADER_SIZE + i * WINDOW_ENTRY_SIZE
        here = address + HEADER_SIZE + i * WINDOW_ENTRY_SIZE
        pc, stub, copy = [resolve(here + j * 4, v) for j, v in enumerate(struct.unpack_from("<iii", data, offset))]
        length, flags = struct.unpack_from("<HH", data, offset + 12)
        targets = [resolve(here + 16 + j * 4, v) for j, v in enumerate(struct.unpack_from("<7i", data, offset + 16))]
        ret, copy_end, bs, be, spill, entry_low, entry_rollback = targets
        access_length, width, base, index, scale, origin, rip_offset, rip_end = data[offset + 44:offset + 52]
        displacement, = struct.unpack_from("<q", data, offset + 56)
        require(5 <= length <= 19 and not flags and origin in (1, 2) and
                not any(data[offset + 52:offset + 56]) and not any(data[offset + 64 + length:offset + 88]) and
                not any(data[offset + 92:offset + 128]),
                "window length, flags, origin or reserved bytes")
        require(start <= bs <= pc < ret <= be <= end and ret == pc + length and pc >= previous_end and
                ss <= stub < copy < copy_end <= se and copy_end == copy + length and
                -(1 << 31) <= stub - pc - 5 < (1 << 31), "window bounds/order/reach")
        require((entry_low, entry_rollback) == (low, rollback), "wrong runtime guard targets")
        require(spill % 8 == 0 and spill >= previous_spill and
                not (cs < spill + 24 and spill < ce) and not (ps < spill + 24 and spill < pe),
                "private spill overlaps another site's state")
        extent(elf, spill, spill + 24, 3, nobits=True)
        recorded = bytearray(data[offset + 64:offset + 64 + length])
        rip_target_relative, = struct.unpack_from("<i",data,offset + 88)
        if rip_offset:
            require(access_length <= rip_offset and rip_offset + 4 <= rip_end <= length and
                    not any(recorded[rip_offset:rip_offset+4]), "bad recorded RIP operand")
            rip_target = resolve(here + 88,rip_target_relative)
            require(-(1 << 31) <= rip_target - pc - rip_end < (1 << 31), "original RIP target out of reach")
            struct.pack_into("<i",recorded,rip_offset,rip_target - pc - rip_end)
        else:
            require(not rip_target_relative, "unexpected RIP target")
        original = read_access(pc, length)
        require(original == recorded, "window differs from recorded original bytes")
        instructions = list(dec.disasm(original, pc))
        require(instructions and sum(insn.size for insn in instructions) == length,
                "window is not whole instructions")
        addr = Address(base, index, scale, displacement, width)
        require(instructions[0].size == access_length and scalar_access(instructions[0]) == addr,
                "guard does not recompute the covered dereference")
        require(all(movable(insn) for insn in instructions[1:]), "window crosses a control/report/unsafe instruction")
        from capstone import x86_const as x
        rips = [insn for insn in instructions if any(op.type == x.X86_OP_MEM and op.mem.base == x.X86_REG_RIP
                                                    for op in insn.operands)]
        require(len(rips) <= 1 and (not rips and not rip_offset and not rip_end or
                len(rips) == 1 and rips[0].address - pc + rips[0].disp_offset == rip_offset and
                rips[0].address - pc + rips[0].size == rip_end and rips[0].disp_size == 4),
                "unproved RIP-relative tail")
        copied = bytearray(original)
        if rip_offset:
            target = pc + rip_end + struct.unpack_from("<i", original, rip_offset)[0]
            require(-(1 << 31) <= target - copy - rip_end < (1 << 31), "copied RIP target out of reach")
            struct.pack_into("<i", copied, rip_offset, target - copy - rip_end)
        expected, copy_offset = instantiate_guard(addr, bytes(copied), stub,
            dict(spill=spill, low=low, rollback=rollback, **{"return": ret}))
        require(copy == stub + copy_offset and stub + len(expected) <= se and
                read_access(stub, len(expected)) == expected, "guard/copy/continuation template differs")
        entries.append((pc, stub, copy, length))
        block_extents.add((bs,be))
        previous_end, previous_spill = ret, spill + 24
    pcs = [e[0] for e in entries]
    def interior(target):
        i = bisect_right(pcs, target) - 1
        return i >= 0 and pcs[i] < target < pcs[i] + entries[i][3]
    # Preserve every input or ordinary generated label. Our own field anchors
    # necessarily label displacement bytes; they are not incoming landings.
    for symbol in symbols:
        if symbol["st_shndx"] == "SHN_UNDEF" or symbol.name.startswith((".L__teapot_fault_", "__teapot_fault_")): continue
        require(not interior(symbol["st_value"]), "referenced label lies inside a patch window: " + symbol.name)
    # A complete final block directory is emitted before raw partitioning. It
    # lets validation decode incoming direct transfers even through raw windows.
    starts = {s.name[len("__teapot_fault_bb_"):]: s["st_value"] for s in symbols
              if s.name.startswith("__teapot_fault_bb_")}
    ends = {s.name[len("__teapot_fault_be_"):]: s["st_value"] for s in symbols
            if s.name.startswith("__teapot_fault_be_")}
    require(bool(starts) and starts.keys() == ends.keys(), "missing final block directory")
    require(block_extents <= {(begin,ends[key]) for key,begin in starts.items()},
            "patch window has no final block directory entry")
    import capstone as cap
    def check_incoming(begin, finish):
        if begin == finish: return
        instructions = list(dec.disasm(read_access(begin, finish - begin), begin))
        require(sum(insn.size for insn in instructions) == finish - begin, "final block not completely decoded")
        for insn in instructions:
            if cap.CS_GRP_JUMP in insn.groups or cap.CS_GRP_CALL in insn.groups:
                for operand in insn.operands:
                    if operand.type == x.X86_OP_IMM:
                        require(not interior(operand.imm), "incoming direct transfer inside a patch window")

    for key, begin in starts.items():
        finish = ends[key]
        require(start <= begin <= finish <= end, "bad final block directory extent")
        check_incoming(begin, finish)
    # .L targets vanish from the ELF symtab. Inspect trampoline instructions
    # too, so a direct entry into a displaced window cannot hide behind one.
    trampolines = elf.get_section_by_name(".teapot_trampolines")
    if trampolines is not None and trampolines["sh_size"]:
        require(trampolines["sh_flags"] & 6 == 6, "trampolines are not allocated executable code")
        check_incoming(trampolines["sh_addr"], trampolines["sh_addr"] + trampolines["sh_size"])
    copies = sorted((copy, length) for _, _, copy, length in entries)
    for i, (copy, length) in enumerate(copies):
        require(not i or copies[i - 1][0] + copies[i - 1][1] <= copy, "copied windows overlap")
        j = bisect_right(pcs, copy + length - 1) - 1
        require(j < 0 or pcs[j] + entries[j][3] <= copy, "copied window overlaps an original")
    return dict(address=address, version=WINDOW_VERSION, count=count, threshold=header[6], flags=WINDOW_FLAGS,
                text=(start,end), counters=(cs,ce), pending=(ps,pe), entries=entries)
