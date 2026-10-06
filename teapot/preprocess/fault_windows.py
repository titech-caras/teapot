"""Last-stage x64 window emission. No pass may edit the result afterwards.

Original windows and cold stubs are executable raw data, with explicit
symbolic relocation words. That prevents either printer or assembler from
shortening an encoding that startup will overwrite. All ordinary hot bytes
are retained; only a refused short window gets a disp32 fallback.
"""
from dataclasses import dataclass
from bisect import bisect_left, bisect_right
import struct
import uuid
import gtirb

from teapot.fault_x64 import (Address, Boundaries, interior_boundary, decoder, scalar_access, select_window, guard_template,
                              INPUT_TAG, MEMLOG_PREFIX, ORIG, MEMLOG, WINDOW_VERSION,
                              WINDOW_ENTRY_SIZE, WINDOW_FLAGS)
from teapot.preprocess.contract_record import _new_interval
from teapot.preprocess.copy_section import set_elf_section_properties
from teapot.preprocess.fault_sites import MAGIC, HEADER_SIZE, TABLE_SECTION, PROTECTED_SECTION
from teapot.utils.layout import settle_layout


@dataclass
class Site:
    block: object
    offset: int
    instructions: tuple
    code: bytes
    address: Address
    origin: int
    widen: bool = False
    rip: object = None


def wide_access(insn):
    """Force mod=10/disp32 without changing the dereferenced address."""
    if scalar_access(insn) is None or insn.size >= 5: return None
    code = bytearray(insn.bytes)
    modrm = insn.modrm_offset
    if not modrm or modrm >= len(code): return None
    mode = code[modrm] >> 6
    if mode not in (0, 1): return None
    at = insn.disp_offset if insn.disp_size else modrm + 1 + (code[modrm] % 8 == 4)
    code[modrm] = (code[modrm] & 63) | 128
    code[at:at + insn.disp_size] = struct.pack("<i", scalar_access(insn).displacement)
    if len(code) > 15: return None
    decoded = list(decoder().disasm(bytes(code), insn.address))
    if len(decoded) != 1 or _instruction_effect(decoded[0]) != _instruction_effect(insn):
        raise ValueError("disp32 fallback changed its instruction semantics")
    return bytes(code)


def _instruction_effect(insn):
    """Ignore encoding width, not opcode, prefixes or operand semantics."""
    from capstone import x86_const as x
    operands = []
    for operand in insn.operands:
        if operand.type == x.X86_OP_MEM:
            memory = operand.mem
            value = (memory.segment, memory.base, memory.index, memory.scale, memory.disp)
        elif operand.type == x.X86_OP_REG:
            value = operand.reg
        elif operand.type == x.X86_OP_IMM:
            value = operand.imm
        else:
            raise ValueError("disp32 fallback has an unknown operand")
        operands.append((operand.type, operand.size, operand.access, value))
    return (insn.id, insn.mnemonic, tuple(insn.prefix), insn.rex, insn.addr_size,
            insn.eflags, tuple(operands), tuple(map(tuple, insn.regs_access())))


def _relative(module, interval, offset, width, target, addend=0, *, anchor=None):
    field = gtirb.DataBlock(size=width, offset=offset, byte_interval=interval)
    if anchor is None:
        anchor = _label(module, field, f"field_{interval.uuid.hex}_{offset:x}")
    interval.symbolic_expressions[offset] = gtirb.SymAddrAddr(1, addend, target, anchor)
    module.aux_data.setdefault("symbolicExpressionSizes", gtirb.AuxData({}, "mapping<Offset,uint64_t>")) \
          .data[gtirb.Offset(interval, offset)] = width
    return field, anchor


def _label(module, block, role, at_end=False):
    # The block directory must survive assembly in .symtab for final-link
    # incoming-transfer checks. GNU as deliberately discards .L locals.
    name = ("__teapot_fault_" if role.startswith(("bb_", "be_")) else ".L__teapot_fault_") + role
    if tuple(module.symbols_named(name)): raise ValueError("duplicate adaptive-fault label")
    symbol = gtirb.Symbol(name=name, payload=block, at_end=at_end, module=module,
                          uuid=uuid.uuid5(module.uuid, name))
    module.aux_data.setdefault("elfSymbolInfo", gtirb.AuxData({},
        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")) \
        .data[symbol] = (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
    return symbol


def _external(module, name):
    values = tuple(module.symbols_named(name))
    if len(values) > 1 or values and not isinstance(values[0].referent, gtirb.ProxyBlock):
        raise ValueError("runtime-owned fault symbol is ambiguous or input-defined: " + name)
    if values: return values[0]
    symbol = gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module,
                          uuid=uuid.uuid5(module.uuid, "fault-import:" + name))
    module.aux_data.setdefault("elfSymbolInfo", gtirb.AuxData({},
        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")) \
        .data[symbol] = (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)
    return symbol


def _split_raw(module, block, ranges):
    """Preserve entry identity/CFG and put only selected windows in raw data.

    Function and instruction-offset metadata belongs to code pieces, never to
    raw relocation words. This is the final transformation, not input to a
    later instruction-rewriting round.
    """
    from gtirb_rewriting import _auxdata_offsetmap
    interval, start, size = block.byte_interval, block.offset, block.size
    old_edges = tuple(block.outgoing_edges)
    old_end_symbols = tuple(s for s in block.references if s.at_end)
    code_pieces = []; windows = []; cursor = 0
    for begin, length in ranges:
        part = block if not code_pieces else gtirb.CodeBlock(byte_interval=interval)
        part.offset, part.size = start + cursor, begin - cursor
        code_pieces.append(part)
        raw = gtirb.DataBlock(size=length, offset=start + begin, byte_interval=interval)
        windows.append(raw); cursor = begin + length
    suffix = gtirb.CodeBlock(size=size - cursor, offset=start + cursor, byte_interval=interval)
    code_pieces.append(suffix)
    for edge in old_edges:
        module.ir.cfg.discard(edge)
        module.ir.cfg.add(gtirb.Edge(suffix, edge.target, edge.label))
    for a, b in zip(code_pieces, code_pieces[1:]):
        module.ir.cfg.add(gtirb.Edge(a, b, gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough)))
    for symbol in old_end_symbols: symbol.referent = suffix
    for fn, blocks in module.aux_data.get("functionBlocks", gtirb.AuxData({}, "mapping<UUID,set<UUID>>")).data.items():
        if block in blocks: blocks.update(code_pieces)
    for definition in _auxdata_offsetmap.OFFSETMAP_AUX_DATA_TABLES:
        table = definition.get(module)
        if table is None or block not in table: continue
        entries = dict(table[block]); del table[block]
        for displacement, value in entries.items():
            for piece in code_pieces:
                begin = piece.offset - start
                if begin <= displacement < begin + piece.size:
                    table[gtirb.Offset(piece, displacement - begin)] = value; break
    return windows, code_pieces[0], suffix


def _splice_batch(module, interval, edits, *, left=()):
    """Apply disjoint edits in the original interval's coordinates once.

    Repeated whole-interval splices were quadratic in the number of sites and
    islands: each moved every later GTIRB block and relocation again. Build
    bytes and translate existing nodes/fixups once instead. ``left`` contains
    zero-size island anchors which stay before their own insertion, but still
    move past earlier insertions. Returns the final start of each edit.
    """
    edits = sorted(edits, key=lambda item: item[0])
    if not edits:
        return {}
    starts, ends, shifts, inserted = [], [], [0], {}
    replacements = {}
    payload = []; cursor = 0
    for offset, old_size, code in edits:
        end = offset + old_size
        if offset < cursor or offset in inserted or old_size < 0 or end > interval.size:
            raise ValueError("overlapping or out-of-range adaptive-fault edits")
        starts.append(offset); ends.append(end)
        payload.extend((interval.contents[cursor:offset], code))
        shifts.append(shifts[-1] + len(code) - old_size)
        inserted[offset] = len(code) if old_size == 0 else 0
        if old_size:
            replacements[(offset, old_size)] = len(code)
        cursor = end
    payload.append(interval.contents[cursor:])

    def translated(position, before_insert=False):
        at = bisect_right(ends, position)
        return position + shifts[at] - (inserted.get(position, 0) if before_insert else 0)

    # Validate everything before mutating the interval. A referenced interior
    # node/word must not be silently left behind inside a replaced access.
    moved = []
    for block in tuple(interval.blocks):
        size = replacements.get((block.offset, block.size), block.size)
        at = bisect_right(starts, block.offset)
        inside_previous = at and starts[at - 1] < block.offset < ends[at - 1]
        partial_replacement = at and starts[at - 1] == block.offset and ends[at - 1] > block.offset and \
                              block.size and (block.offset, block.size) not in replacements
        splits_block = at < len(starts) and starts[at] < block.offset + block.size
        if inside_previous or partial_replacement or splits_block:
            raise ValueError("fault insertion splits an unsplit block")
        moved.append((block, translated(block.offset, block in left), size))
    expressions = []
    for position, expression in interval.symbolic_expressions.items():
        at = bisect_right(starts, position)
        if at and position < ends[at - 1]:
            raise ValueError("fault widening overwrites a relocation")
        expressions.append((translated(position), expression))
    sizes = module.aux_data.get("symbolicExpressionSizes")
    moved_sizes = [] if sizes is None else [
        (key, gtirb.Offset(interval, translated(key.displacement)), value)
        for key, value in sizes.data.items() if key.element_id is interval]

    interval.contents = b"".join(payload)
    interval.size += shifts[-1]
    for block, offset, size in moved:
        block.offset, block.size = offset, size
    interval.symbolic_expressions.clear()
    interval.symbolic_expressions.update(expressions)
    if sizes is not None:
        for old, _, _ in moved_sizes:
            del sizes.data[old]
        for _, new, value in moved_sizes:
            sizes.data[new] = value
    return {offset: translated(offset, before_insert=True) for offset in starts}


def add_fault_windows(module, section, text_bounds, *, threshold=2, marker=b""):
    from gtirb_rewriting import _auxdata_offsetmap
    from capstone import x86_const as x
    if module.isa != gtirb.Module.ISA.X64: raise ValueError("adaptive prechecks currently require x64")
    if type(threshold) is not int or not 0 <= threshold <= 255: raise ValueError("invalid fault threshold")
    intervals = tuple(section.byte_intervals)
    if len(intervals) != 1: raise ValueError("adaptive windows require one final copy interval")
    interval = intervals[0]; decode = decoder()
    module.aux_data.setdefault("symbolicExpressionSizes", gtirb.AuxData({}, "mapping<Offset,uint64_t>"))
    comments = _auxdata_offsetmap.comments.get(module)
    original = set() if comments is None else {
        (key.element_id, key.displacement) for key, value in comments.items() if INPUT_TAG in value.split("\n")}
    memlog = {s.referent.address for s in module.symbols if s.name.startswith(MEMLOG_PREFIX)
              and isinstance(s.referent, gtirb.CodeBlock) and s.referent.section is section and not s.at_end}
    boundaries = {s.referent.address + (s.referent.size if s.at_end else 0)
                  for s in module.symbols if isinstance(s.referent, gtirb.ByteBlock) and s.referent.section is section}
    if marker:
        at = interval.contents.find(marker)
        while at >= 0:
            boundaries.update(range(interval.address + at, interval.address + at + len(marker)))
            at = interval.contents.find(marker, at + 1)
    boundaries = Boundaries(boundaries)
    expression_offsets = tuple(sorted(interval.symbolic_expressions))
    # A per-function island is legal only past a proved terminal instruction.
    # Indirect-transfer helpers can be lexically last and end in padding; use
    # the last safe terminal instead of dropping the entire function. Inserting
    # there relocates the later helper blocks, never adds a hot-path branch.
    owners = {}; islands = {}
    for fn, blocks in sorted(module.aux_data["functionBlocks"].data.items(), key=lambda p: p[0].int):
        local = sorted((b for b in blocks if isinstance(b, gtirb.CodeBlock) and b.section is section and b.size),
                       key=lambda b: (b.offset, b.uuid.int))
        if not local: continue
        last = None
        for candidate in reversed(local):
            instructions = list(decode.disasm(bytes(candidate.contents), candidate.address))
            if instructions and sum(i.size for i in instructions) == candidate.size and \
                    instructions[-1].mnemonic in ("jmp", "ret", "retf", "ud2") and \
                    not any(e.label.type == gtirb.Edge.Type.Fallthrough for e in candidate.outgoing_edges):
                last = candidate
                break
        if last is None: continue
        islands[fn] = gtirb.CodeBlock(size=0, offset=last.offset + last.size, byte_interval=interval)
        for block in local: owners.setdefault(block, fn)
    candidates = []; refused = 0
    basic_blocks = {}
    for block in sorted(section.code_blocks, key=lambda b: (b.offset, b.uuid.int)):
        if not block.size: continue
        basic_blocks[block] = (_label(module, block, f"bb_{block.uuid.hex}"),
                               _label(module, block, f"be_{block.uuid.hex}", True))
        instructions = list(decode.disasm(bytes(block.contents), block.address))
        if sum(i.size for i in instructions) != block.size: raise ValueError("undecodable final x64 block")
        previous_end = block.address
        for index, insn in enumerate(instructions):
            origin = ORIG if (block, insn.address - block.address) in original else \
                     MEMLOG if insn.address in memlog else 0
            if not origin or insn.address < previous_end or scalar_access(insn) is None: continue
            if block not in owners: refused += 1; continue
            # Widening is not a licence to consume a marker or an interior
            # referent. It may replace only this complete, unreferenced access.
            if interior_boundary(boundaries, insn.address, insn.address + insn.size):
                refused += 1; continue
            selected = select_window(instructions, index, boundaries)
            widen = False
            if not selected:
                code = wide_access(insn)
                if code is None: refused += 1; continue
                selected = (insn,); widen = True
            else: code = b"".join(bytes(i.bytes) for i in selected)
            rip = None; legal = True
            for instruction in selected:
                relative = instruction.address - block.address
                begin = block.offset + relative
                expressions = [(pos, interval.symbolic_expressions[pos]) for pos in expression_offsets[
                    bisect_left(expression_offsets, begin):bisect_left(expression_offsets, begin + instruction.size)]]
                memory = [op for op in instruction.operands if op.type == x.X86_OP_MEM and op.mem.base == x.X86_REG_RIP]
                if memory:
                    at = block.offset + relative + instruction.disp_offset
                    expr = interval.symbolic_expressions.get(at)
                    if rip is not None or instruction is insn or instruction.disp_size != 4 or \
                            len(expressions) != 1 or not isinstance(expr, gtirb.SymAddrConst) or expr.attributes:
                        legal = False; break
                    rip = (instruction.address - insn.address + instruction.disp_offset,
                           instruction.address - insn.address + instruction.size, expr)
                elif expressions: legal = False; break
            if not legal: refused += 1; continue
            candidates.append(Site(block, insn.address - block.address, selected, code,
                                   scalar_access(insn), origin, widen, rip))
            previous_end = insn.address + sum(i.size for i in selected)
    if not candidates: raise ValueError("adaptive prechecks selected no proved scalar sites")
    if any(s.name == TABLE_SECTION for s in module.sections): raise ValueError("duplicate fault table")
    protected = next((s for s in module.sections if s.name == PROTECTED_SECTION), None)
    if protected is None:
        protected = gtirb.Section(name=PROTECTED_SECTION, module=module,
            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, gtirb.Section.Flag.Loaded})
        set_elf_section_properties(protected, 8, 3)
    elif module.aux_data["sectionProperties"].data[protected] != (8, 3):
        raise ValueError("fault private state is not protected NOBITS")
    storage = (len(candidates) + 7) & ~7
    state = _new_interval(module, protected, b""); state.size = storage * 2 + 24 * len(candidates)
    counters = gtirb.DataBlock(size=storage, offset=0, byte_interval=state)
    pending = gtirb.DataBlock(size=storage, offset=storage, byte_interval=state)
    cs, ce = _label(module, counters, "counters"), _label(module, counters, "counters_end", True)
    ps, pe = _label(module, pending, "pending"), _label(module, pending, "pending_end", True)
    align = module.aux_data.setdefault("alignment", gtirb.AuxData({}, "mapping<UUID,uint64_t>"))
    align.data[counters] = align.data[pending] = 8
    # Linux x64 base pages are 4 KiB. Both ends must be isolated: a partial
    # last page can share .plt, not only ordinary/runtime .text.
    align.data[interval] = 4096
    low, rollback = _external(module, "teapot_fault_low_bound"), _external(module, "restore_checkpoint_SIGSEGV")
    by_block = {}
    for index, site in enumerate(candidates): by_block.setdefault(site.block, []).append((index, site))
    records = [None] * len(candidates)
    left = set(islands.values())
    for block, group in by_block.items():
        old_start, old_size = block.offset, block.size
        ranges = [(site.offset, sum(i.size for i in site.instructions)) for _, site in group]
        raw, leading, trailing = _split_raw(module, block, ranges)
        bs = _label(module, leading, f"block_{block.uuid.hex}")
        be = _label(module, trailing, f"block_end_{block.uuid.hex}", True)
        for (index, site), access in zip(group, raw):
            spill = gtirb.DataBlock(size=24, offset=storage * 2 + 24 * index, byte_interval=state)
            spill_symbol = _label(module, spill, f"spill_{index}"); align.data[spill] = 8
            pc = _label(module, access, f"site_{index}")
            # A zero-size code anchor remains at the full window end when
            # relocation words split its data block into multiple pieces.
            end_anchor = gtirb.CodeBlock(size=0, offset=access.offset + access.size, byte_interval=interval)
            ret = _label(module, end_anchor, f"return_{index}")
            records[index] = dict(site=site, pc=pc, ret=ret, bs=bs, be=be, spill=spill_symbol,
                                  island=islands[owners[block]], block=access)
    # Move symbols and fixups once for all disp32 fallbacks.
    _splice_batch(module, interval, [(record["block"].offset, record["block"].size, record["site"].code)
                                    for record in records if record["site"].widen])
    # Turn a raw window's RIP operand into an explicit relative data word.
    for index, record in enumerate(records):
        site, block = record["site"], record["block"]
        if site.rip:
            displacement, end, expr = site.rip
            at = block.offset + displacement
            # Split the raw bytes around the word: no overlapping data blocks.
            before, after = displacement, block.size - displacement - 4
            block.size = before
            word = gtirb.DataBlock(size=4, offset=at, byte_interval=interval)
            anchor = _label(module, word, f"original_rip_{index}")
            if after: gtirb.DataBlock(size=after, offset=at + 4, byte_interval=interval)
            interval.symbolic_expressions[at] = gtirb.SymAddrAddr(1, expr.offset - end + displacement,
                                                                             expr.symbol, anchor)
            module.aux_data.setdefault("symbolicExpressionSizes", gtirb.AuxData({}, "mapping<Offset,uint64_t>")) \
                  .data[gtirb.Offset(interval, at)] = 4
            # The return must stay at the window's end, not the shortened block.
            record["original_rip"] = anchor
    grouped = {}
    for index, record in enumerate(records): grouped.setdefault(record["island"], []).append((index, record))
    # Gather all islands before moving any existing blocks. Equal-position
    # aliases share one insertion, preserving the old reverse-insertion order.
    island_plans = {}
    for island, group in sorted(grouped.items(), key=lambda p: p[0].offset, reverse=True):
        at = island.offset; payload = bytearray(); plans = []
        for index, record in group:
            code, relocations, copy = guard_template(record["site"].address, record["site"].code)
            plans.append((index, record, len(payload), code, relocations, copy)); payload.extend(code)
        if at in island_plans:
            old_code, old_plans = island_plans[at]
            old_plans = [(i, r, local + len(payload), code, relocations, copy)
                         for i, r, local, code, relocations, copy in old_plans]
            island_plans[at] = (bytes(payload) + old_code, plans + old_plans)
        else:
            island_plans[at] = (bytes(payload), plans)
    positions = _splice_batch(module, interval, [(at, 0, code) for at, (code, _) in island_plans.items()], left=left)
    for original_at, (_, plans) in sorted(island_plans.items(), reverse=True):
        at = positions[original_at]
        for index, record, local, code, relocations, copy in plans:
            offsets = {0, len(code), copy, copy + len(record["site"].code)}
            fields = {pos: (key, addend) for pos, key, addend in relocations}
            offsets.update(fields); offsets.update(pos + 4 for pos in fields)
            if record["site"].rip:
                disp, end, expr = record["site"].rip
                fields[copy + disp] = ("copy_rip", 0); offsets.update((copy + disp, copy + disp + 4))
            chunks = {}
            for begin, end in zip(sorted(offsets), sorted(offsets)[1:]):
                chunks[begin] = gtirb.DataBlock(size=end - begin, offset=at + local + begin, byte_interval=interval)
            record["stub"] = _label(module, chunks[0], f"stub_{index}")
            record["copy"] = _label(module, chunks[copy], f"copy_{index}")
            record["copy_end"] = _label(module, chunks[copy + len(record["site"].code)], f"copy_end_{index}")
            targets = dict(spill=record["spill"], low=low, rollback=rollback, **{"return": record["ret"]})
            for pos, (key, addend) in fields.items():
                anchor = _label(module, chunks[pos], f"stub_field_{index}_{pos}")
                if key == "copy_rip":
                    disp, end, expr = record["site"].rip
                    target, addend = expr.symbol, expr.offset - end + disp
                else: target = targets[key]
                interval.symbolic_expressions[at + local + pos] = gtirb.SymAddrAddr(1, addend, target, anchor)
                module.aux_data["symbolicExpressionSizes"].data[gtirb.Offset(interval, at + local + pos)] = 4
    settle_layout(module)
    padding = -interval.size % 4096
    if padding:
        begin = interval.size
        interval.contents = bytes(interval.contents).ljust(begin, b"\xcc") + b"\xcc" * padding
        interval.size = begin + padding
        # Uncovered tail bytes need not survive printing. An explicit raw
        # block keeps this padding in the ELF; accidental fallthrough traps.
        gtirb.DataBlock(size=padding, offset=begin, byte_interval=interval)
    text_bounds[1].referent.offset = interval.size
    # The printer/assembler may shorten non-window instructions. IR-size
    # padding alone then ceases to end at a page boundary. An explicit end
    # anchor requirement emits alignment after every printed instruction and
    # before the table's end label, so the final ELF remains page-isolated.
    align.data[text_bounds[1].referent] = 4096
    section_table = gtirb.Section(name=TABLE_SECTION, module=module,
        flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
    set_elf_section_properties(section_table, 1, 2)
    contents = bytearray(struct.pack("<IHHIIII", MAGIC, WINDOW_VERSION, HEADER_SIZE, WINDOW_ENTRY_SIZE,
                                    len(records), WINDOW_FLAGS, threshold))
    contents.extend(bytes(HEADER_SIZE - len(contents) + WINDOW_ENTRY_SIZE * len(records)))
    table_interval = _new_interval(module, section_table, bytes(contents))
    header = gtirb.DataBlock(size=24, offset=0, byte_interval=table_interval)
    table = _label(module, header, "sites"); align.data[header] = 8
    gtirb.DataBlock(size=24, offset=88, byte_interval=table_interval)
    for offset, symbol in zip(range(24, 88, 8), (*text_bounds, *text_bounds, cs, ce, ps, pe)):
        _relative(module, table_interval, offset, 8, symbol)
    for index, record in enumerate(records):
        site = record["site"]; begin = HEADER_SIZE + WINDOW_ENTRY_SIZE * index
        for offset, key in ((0,"pc"), (4,"stub"), (8,"copy"), (16,"ret"), (20,"copy_end"),
                            (24,"bs"), (28,"be"), (32,"spill")):
            _relative(module, table_interval, begin + offset, 4, record[key])
        _relative(module, table_interval, begin + 36, 4, low)
        _relative(module, table_interval, begin + 40, 4, rollback)
        struct.pack_into("<HH", contents, begin + 12, len(site.code), 0)
        access_length = len(site.code) if site.widen else site.instructions[0].size
        contents[begin + 44:begin + 52] = bytes((access_length, site.address.width, site.address.base,
            site.address.index, site.address.scale, site.origin,
            site.rip[0] if site.rip else 0, site.rip[1] if site.rip else 0))
        struct.pack_into("<q", contents, begin + 56, site.address.displacement)
        contents[begin + 64:begin + 64 + len(site.code)] = site.code
        for offset, size in ((12,4), (44,20), (64,24), (92,36)):
            gtirb.DataBlock(size=size, offset=begin + offset, byte_interval=table_interval)
        if site.rip:
            disp, end, expr = site.rip
            # ELF cannot encode target-original_pc in a third section. Keep
            # the operand zero in the byte record and carry its self-relative
            # target separately. Both validators rebuild the original disp32.
            contents[begin + 64 + disp:begin + 64 + disp + 4] = bytes(4)
            _relative(module, table_interval, begin + 88, 4, expr.symbol, expr.offset)
        else:
            gtirb.DataBlock(size=4, offset=begin + 88, byte_interval=table_interval)
    table_interval.contents = bytes(contents)
    # These tags have served their purpose and should not leak into output.
    if comments is not None:
        for key, value in tuple(comments.items()):
            if INPUT_TAG not in value.split("\n"): continue
            rest = "\n".join(v for v in value.split("\n") if v != INPUT_TAG)
            if rest: comments[key] = rest
            else: del comments[key]
    print(f"[teapot] adaptive x64 sites: {len(records)} ({sum(s.widen for s in candidates)} widened), "
          f"{refused} unproved sites skipped", flush=True)
    return table
