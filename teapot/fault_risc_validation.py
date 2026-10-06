"""Read-only v4 final-ELF validation; never fixes or finalizes executable bytes."""
from bisect import bisect_right
import struct

from teapot.fault_risc import (VERSION, ENTRY_SIZE, FLAGS, ISOLATION, ORIG, DEAD, Recipe,
                              branch, choose_recipe, decode_load, guard_template, resolve_template)
from teapot.preprocess.fault_sites import MAGIC, HEADER_SIZE


def validate_risc_windows(elf, address):
    from teapot.fault_sites import require, resolve, extent, access_bytes
    import capstone as cap
    require(elf.elfclass == 64 and elf.little_endian and
            elf["e_machine"] in ("EM_AARCH64", "EM_RISCV"), "v4 requires supported little-endian RISC ELF64")
    isa = "aarch64" if elf["e_machine"] == "EM_AARCH64" else "riscv64"
    alignment, spill_size = (4, 24) if isa == "aarch64" else (2, 16)
    if isa == "riscv64":
        require(elf["e_flags"] & 1, "halfword RV publisher requires the RVC ELF contract")
    require(address % 8 == 0, "misaligned RISC table")
    section = extent(elf, address, address + HEADER_SIZE, 2)
    require(section["sh_type"] == "SHT_PROGBITS", "RISC table is not file-backed")
    data, at = section.data(), address - section["sh_addr"]
    require(at + HEADER_SIZE <= len(data), "truncated RISC header")
    header = struct.unpack_from("<IHHIIII8q3Q", data, at)
    require(header[:4] == (MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE) and header[4] > 0 and
            header[5] == FLAGS and header[6] <= 255 and not any(header[15:]), "unsupported RISC header")
    count = header[4]
    require(count <= 1048576, "RISC fault site capacity")
    total = HEADER_SIZE + count * ENTRY_SIZE
    extent(elf, address, address + total, 2)
    require(at + total <= len(data), "truncated RISC records")
    start, end, ss, se, cs, ce, ps, pe = [resolve(address + 24 + 8 * i, value)
                                        for i, value in enumerate(header[7:15])]
    require(start == ss < se == end and start % ISOLATION == end % ISOLATION == 0,
            "RISC copy text is not isolated at both 64-KiB ends")
    extent(elf, start, end, 6); extent(elf, ss, se, 6)
    found_copy = False
    for candidate in elf.iter_sections():
        if not candidate["sh_flags"] & 2 or not candidate["sh_size"]:
            continue
        first, last = candidate["sh_addr"], candidate["sh_addr"] + candidate["sh_size"]
        if candidate.name == ".teapot_transient":
            require((first, last) == (start, end), "RISC publisher range differs from transient section")
            found_copy = True
        else:
            require(last <= start or end <= first, "allocated section shares a RISC patch page: " + candidate.name)
    require(found_copy, "missing RISC transient section")
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        first, last = segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"]
        if first < end and start < last:
            require(segment["p_flags"] & 7 == 5, "incompatible overlapping RISC text load mapping")
    storage = (count + 7) & ~7
    require(cs % 8 == ps % 8 == 0 and ce - cs == pe - ps == storage and ce == ps,
            "RISC counter/pending extent or overlap")
    extent(elf, cs, ce, 3, nobits=True); extent(elf, ps, pe, 3, nobits=True)
    symtab = elf.get_section_by_name(".symtab")
    require(symtab is not None, "RISC validation requires an unstripped final ELF")
    symbols = tuple(symtab.iter_symbols())
    def owned(name):
        definitions = [s for s in symbols if s.name == name and s["st_shndx"] != "SHN_UNDEF"]
        require(len(definitions) == 1 and definitions[0]["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"),
                "missing or ambiguous RISC runtime symbol: " + name)
        return definitions[0]["st_value"]
    policy, rollback = owned("teapot_fault_risc_policy"), owned("restore_checkpoint_SIGSEGV")
    extent(elf, rollback, rollback + 4, 6)
    require(not start <= rollback < end, "RISC rollback wrapper lies on a patchable page")
    require(policy % 8 == 0, "misaligned RISC policy")
    extent(elf, policy, policy + 16, 3)
    protected = [(policy, policy + 16)]
    # Runtime-private scratch and immutable registry ranges are never spill or
    # counter storage. Include backend14's now-NOBITS startup scratch too.
    for symbol in symbols:
        if symbol.name in ("startup_maps", "proc_buffer", "fault_registry_pool", "fault_copy_pool"):
            require(symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_size"] > 0,
                    "unproved runtime-private storage extent")
            protected.append((symbol["st_value"], symbol["st_value"] + symbol["st_size"]))
    def disjoint(begin, finish, ranges):
        return all(last <= begin or finish <= first for first, last in ranges)
    require(disjoint(cs, ce, protected) and disjoint(ps, pe, protected), "RISC counters alias runtime storage")
    entries, stubs, block_extents = [], [], set()
    previous_pc, previous_spill = start, pe
    for i in range(count):
        offset, here = at + HEADER_SIZE + i * ENTRY_SIZE, address + HEADER_SIZE + i * ENTRY_SIZE
        pc, stub, copy = [resolve(here + j * 4, v) for j, v in enumerate(struct.unpack_from("<iii", data, offset))]
        length, flags = struct.unpack_from("<HH", data, offset + 12)
        ret, copy_end, bs, be, spill, entry_policy, entry_rollback, stub_end = [
            resolve(here + 16 + j * 4, v) for j, v in enumerate(struct.unpack_from("<8i", data, offset + 16))]
        original_word, = struct.unpack_from("<I", data, offset + 48)
        origin, width, base, index, extension, shift, destination, bootstrap, temp0, temp1, kind, reserved = \
            data[offset + 52:offset + 64]
        displacement, recorded_spill_size, template_id = struct.unpack_from("<qHH", data, offset + 64)
        require(length == 4 and not flags and not reserved and not any(data[offset + 76:offset + ENTRY_SIZE]) and
                recorded_spill_size == spill_size, "RISC length/flags/reserved/spill size")
        require(start <= bs <= pc < ret <= be <= end and ret == pc + 4 and pc >= previous_pc and
                ss <= stub < copy < copy_end <= stub_end <= se and copy_end == copy + 4 and
                all(value % alignment == 0 for value in (pc, stub, copy, copy_end, ret, stub_end)),
                "RISC site/stub/block bounds, order or alignment")
        branch(isa, pc, stub)                    # original -> island final-link reach
        require((entry_policy, entry_rollback) == (policy, rollback), "wrong RISC runtime targets")
        require(spill % 8 == 0 and spill == previous_spill and
                disjoint(spill, spill + spill_size, protected + [(cs, ce), (ps, pe)]),
                "RISC private spill overlaps another state range")
        extent(elf, spill, spill + spill_size, 3, nobits=True)
        code = struct.pack("<I", original_word)
        require(access_bytes(elf, pc, 4) == code and access_bytes(elf, copy, 4) == code,
                "RISC original/copy differs from recorded whole instruction")
        load = decode_load(isa, code)
        require(load is not None and (load.width, load.base, load.index, load.extension, load.shift,
                                      load.destination, load.kind, load.displacement) ==
                (width, base, index, extension, shift, destination, kind, displacement),
                "RISC guard does not recompute the exact covered EA")
        recipe = Recipe(bootstrap, temp0, temp1, template_id)
        require(recipe == choose_recipe(load, origin, {bootstrap} if template_id == DEAD else set()) and
                (template_id != DEAD or origin == ORIG), "RISC template/register/origin mismatch")
        template = guard_template(load, recipe)
        expected = resolve_template(template, stub,
            dict(spill=spill, policy=policy, rollback=rollback, **{"return": ret}))
        require(copy == stub + template.copy_offset and stub_end == stub + len(expected) and
                access_bytes(elf, stub, len(expected)) == expected, "RISC template or relaxation drift")
        # The encoder above checks the copied-access continuation branch's
        # independent reach; it is not implied by the original->island check.
        entries.append((pc, stub, copy, 4)); stubs.append((stub, stub_end))
        block_extents.add((bs, be))
        previous_pc, previous_spill = ret, spill + spill_size
    stubs.sort()
    require(all(left[1] <= right[0] for left, right in zip(stubs, stubs[1:])), "overlapping RISC stubs")
    islands = []
    for first, last in stubs:
        if islands and islands[-1][1] == first:
            islands[-1] = (islands[-1][0], last)
        else:
            islands.append((first, last))
    stub_starts = [s[0] for s in stubs]
    def in_stub(target):
        i = bisect_right(stub_starts, target) - 1
        return i >= 0 and target < stubs[i][1]
    pcs = [entry[0] for entry in entries]
    def interior(target):
        i = bisect_right(pcs, target) - 1
        return i >= 0 and pcs[i] < target < pcs[i] + 4
    for first, last in stubs:
        i = bisect_right(pcs, last - 1) - 1
        require(i < 0 or pcs[i] + 4 <= first, "RISC stub overlaps original access")
    for symbol in symbols:
        if symbol["st_shndx"] == "SHN_UNDEF":
            continue
        local = symbol["st_info"]["bind"] == "STB_LOCAL"
        generated = local and symbol.name.startswith((".L__teapot_fault_", "__teapot_fault_"))
        # Only LOCAL NOTYPE mapping symbols describe raw/data/code boundaries;
        # a similarly named external symbol is still an incoming entry.
        mapping = local and symbol["st_info"]["type"] == "STT_NOTYPE" and symbol.name.startswith(("$x", "$d"))
        if not generated:
            require(not interior(symbol["st_value"]), "label enters a RISC instruction halfword")
            if not mapping:
                require(not in_stub(symbol["st_value"]), "external label enters a RISC cold island")
    def directory(prefix):
        import re
        result = {}
        for symbol in symbols:
            if not symbol.name.startswith(prefix):
                continue
            key = symbol.name[len(prefix):]
            require(re.fullmatch(r"[0-9a-f]{32}", key) is not None and key not in result and
                    symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_info"]["bind"] == "STB_LOCAL",
                    "malformed/duplicate/nonlocal RISC directory symbol")
            result[key] = symbol["st_value"]
        return result
    starts = directory("__teapot_fault_bb_")
    ends = directory("__teapot_fault_be_")
    require(bool(starts) and starts.keys() == ends.keys() and
            block_extents <= {(begin, ends[key]) for key, begin in starts.items()}, "missing RISC block directory")
    if isa == "riscv64":
        scope_starts = directory("__teapot_fault_rv_scope_begin_")
        scope_ends = directory("__teapot_fault_rv_scope_end_")
        require(bool(scope_starts) and scope_starts.keys() == scope_ends.keys(), "missing RV scope directory")
        require(sorted((begin, scope_ends[key]) for key, begin in scope_starts.items()) == islands,
                "RV scope does not bind exactly the owned cold islands")
    # Residual ELF address relocations may not introduce an incoming interior
    # entry that disappeared from direct-code disassembly. Metadata rel32s have
    # already resolved at link time and are not residual dynamic relocations.
    from elftools.elf.relocation import RelocationSection
    absolute, relative = (257, 1027) if isa == "aarch64" else (2, 3)
    for relocations in elf.iter_sections():
        if not isinstance(relocations, RelocationSection):
            continue
        linked_symbols = elf.get_section(relocations["sh_link"])
        for relocation in relocations.iter_relocations():
            where = relocation["r_offset"]
            near = bisect_right(pcs, where + 7) - 1
            site_overlap = near >= 0 and pcs[near] + 4 > where
            require(not site_overlap and not in_stub(where) and not in_stub(where + 7),
                    "residual relocation alters a RISC owned instruction")
            if relocation["r_info_type"] not in (absolute, relative) or not relocation.is_RELA():
                continue
            target = relocation["r_addend"]
            if relocation["r_info_type"] == absolute:
                target += linked_symbols.get_symbol(relocation["r_info_sym"])["st_value"]
            require(not interior(target) and not in_stub(target), "address relocation enters a RISC instruction/island")
    from teapot.arch.decoders import aarch64_decoder, riscv64_decoder
    # The same RV64GC/detail configuration as rewriting also decodes existing
    # compressed F/D save/restore instructions surrounding covered scalar loads.
    # This does not change the closed covered-load vocabulary above.
    decoder = aarch64_decoder() if isa == "aarch64" else riscv64_decoder()
    def incoming(begin, finish):
        if begin == finish: return None
        instructions = tuple(decoder.disasm(access_bytes(elf, begin, finish - begin), begin))
        require(sum(i.size for i in instructions) == finish - begin, "RISC final block not completely decoded")
        for insn in instructions:
            if isa == "riscv64":
                raw = int.from_bytes(insn.bytes, "little")
                direct = raw & 127 in (0x63, 0x6f) if insn.size == 4 else \
                         raw & 3 == 1 and raw >> 13 in (5, 6, 7)
            else:
                direct = cap.CS_GRP_JUMP in insn.groups or cap.CS_GRP_CALL in insn.groups
            immediate = [op.imm for op in insn.operands if op.type == cap.CS_OP_IMM]
            if direct and immediate:
                # Capstone RV immediates are relative; A64 branch operands are absolute.
                target = immediate[-1] + (insn.address if isa == "riscv64" else 0)
                require(not interior(target) and not in_stub(target), "incoming transfer enters a RISC instruction/island")
        return instructions[-1]
    terminals = set()
    from teapot.preprocess.fault_risc_windows import terminal
    for key, begin in starts.items():
        require(start <= begin <= ends[key] <= end, "bad RISC block directory extent")
        last = incoming(begin, ends[key])
        if last is not None and terminal(isa, last):
            terminals.add(ends[key])
    require(all(first in terminals for first, _ in islands), "unproved fallthrough into a RISC cold island")
    trampolines = elf.get_section_by_name(".teapot_trampolines")
    if trampolines is not None and trampolines["sh_size"]:
        incoming(trampolines["sh_addr"], trampolines["sh_addr"] + trampolines["sh_size"])
    return dict(address=address, version=VERSION, count=count, threshold=header[6], flags=FLAGS,
                text=(start, end), counters=(cs, ce), pending=(ps, pe), state=(cs, previous_spill), entries=entries)
