"""Last-stage v4 RISC emission; no rewriting pass may follow this transform."""
from bisect import bisect_left
from dataclasses import dataclass
import struct
import uuid

import gtirb

from teapot.fault_risc import (VERSION, ENTRY_SIZE, FLAGS, ISOLATION, ORIG, MEMLOG, SHADOW,
                              MEMLOG_PREFIX, SHADOW_PREFIX, BoundaryMasks, decode_load,
                              choose_recipe, guard_template)
from teapot.fault_risc_assembly import AUX, SCHEMA, PREFIX
from teapot.fault_x64 import INPUT_TAG, Boundaries
from teapot.preprocess.contract_record import _new_interval
from teapot.preprocess.copy_section import set_elf_section_properties
from teapot.preprocess.fault_sites import MAGIC, HEADER_SIZE, TABLE_SECTION, PROTECTED_SECTION
from teapot.preprocess.fault_windows import _external, _label, _relative, _splice_batch, _split_raw


@dataclass
class Site:
    block: object
    offset: int
    load: object
    recipe: object
    origin: int


def terminal(isa, instruction):
    word = int.from_bytes(instruction.bytes, "little")
    if isa == "aarch64":
        return (word & 0xfc000000 == 0x14000000 or
                word & 0xfffffc1f in (0xd61f0000, 0xd65f0000) or
                word & 0xffe0001f in (0xd4200000, 0xd4400000))
    if instruction.size == 2:
        return (word & 0xe003 == 0xa001 or word == 0x9002 or
                word & 0xf07f == 0x8002 and (word >> 7) & 31 != 0)
    return word & 0xfff in (0x6f, 0x67) or word == 0x00100073


def _scope(module, begin, end, index):
    token = uuid.uuid5(module.uuid, f"risc-fault-stub:{index}").hex
    symbols = []
    info = module.aux_data["elfSymbolInfo"].data
    for kind, block in (("begin", begin), ("end", end)):
        name = PREFIX + kind + "_" + token
        if tuple(module.symbols_named(name)):
            raise ValueError("duplicate RV cold-stub scope identity")
        symbol = gtirb.Symbol(name, payload=block, module=module,
                              uuid=uuid.uuid5(module.uuid, name))
        info[symbol] = (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
        symbols.append(symbol)
    module.aux_data.setdefault(AUX, gtirb.AuxData({}, SCHEMA)).data[symbols[0]] = symbols[1]


def add_risc_fault_windows(module, section, text_bounds, reg_manager, isa, *, threshold=2, marker=b""):
    from gtirb_rewriting import _auxdata_offsetmap
    if isa not in ("aarch64", "riscv64") or type(threshold) is not int or not 0 <= threshold <= 255:
        raise ValueError("unsupported RISC fault ISA/threshold")
    intervals = tuple(section.byte_intervals)
    if len(intervals) != 1 or intervals[0].address is None:
        raise ValueError("RISC fault windows require one final addressed interval")
    if AUX in module.aux_data or any(s.name.startswith(PREFIX) for s in module.symbols):
        raise ValueError("input contains reserved RISC cold-stub scope metadata")
    interval = intervals[0]
    original_blocks = set(interval.blocks)
    comments = _auxdata_offsetmap.comments.get(module)
    original = set() if comments is None else {
        (key.element_id, key.displacement) for key, value in comments.items() if INPUT_TAG in value.split("\n")}
    generated = {}
    for symbol in module.symbols:
        block = symbol.referent
        if not isinstance(block, gtirb.CodeBlock) or block.section is not section or symbol.at_end:
            continue
        for prefix, origin in ((MEMLOG_PREFIX, MEMLOG), (SHADOW_PREFIX, SHADOW)):
            if symbol.name.startswith(prefix):
                if block.address in generated:
                    raise ValueError("ambiguous generated RISC load origin")
                generated[block.address] = origin
    boundaries = {s.referent.address + (s.referent.size if s.at_end else 0)
                  for s in module.symbols if isinstance(s.referent, gtirb.ByteBlock) and s.referent.section is section}
    if marker:
        at = interval.contents.find(marker)
        while at >= 0:
            boundaries.update(range(interval.address + at, interval.address + at + len(marker)))
            at = interval.contents.find(marker, at + 1)
    boundaries = Boundaries(boundaries)
    offsets = tuple(sorted(interval.symbolic_expressions))
    blocks = sorted((b for b in section.code_blocks if b.size), key=lambda b: (b.offset, b.uuid.int))
    # Validate/snapshot before adding or splitting any block. The dictionary
    # consumed below is final-boundary proof, not masks queried after raw edits.
    masks = BoundaryMasks(reg_manager, blocks, isa)
    decoded = {block: tuple(reg_manager.decoder.get_instructions(block)) for block in blocks}
    if any(sum(i.size for i in instructions) != block.size for block, instructions in decoded.items()):
        raise ValueError("undecodable final RISC block")
    owners, islands = {}, {}
    for fn, members in sorted(module.aux_data["functionBlocks"].data.items(), key=lambda pair: pair[0].int):
        local = sorted((b for b in members if b in decoded), key=lambda b: (b.offset, b.uuid.int))
        last = next((b for b in reversed(local) if decoded[b] and terminal(isa, decoded[b][-1]) and
                     not any(e.label.type == gtirb.Edge.Type.Fallthrough for e in b.outgoing_edges)), None)
        if last is None:
            continue
        islands[fn] = gtirb.CodeBlock(size=0, offset=last.offset + last.size, byte_interval=interval)
        for block in local:
            owners.setdefault(block, fn)
    candidates, refusals = [], {}
    def refuse(reason):
        refusals[reason] = refusals.get(reason, 0) + 1
    for block in blocks:
        _label(module, block, f"bb_{block.uuid.hex}")
        _label(module, block, f"be_{block.uuid.hex}", True)
        dead_at = masks.block_proofs(block)
        for insn in decoded[block]:
            displacement = insn.address - block.address
            origin = ORIG if (block, displacement) in original else generated.get(insn.address, 0)
            if not origin:
                continue
            load = decode_load(isa, bytes(insn.bytes))
            if load is None:
                refuse("form-or-register"); continue
            recipe = choose_recipe(load, origin, dead_at.get(displacement, frozenset()))
            if recipe is None:
                refuse("destination-alias-without-original-dead-proof"); continue
            if block not in owners:
                refuse("no-terminal-island"); continue
            if boundaries.interior(insn.address, insn.address + insn.size):
                refuse("interior-reference-or-marker"); continue
            begin = block.offset + displacement
            if bisect_left(offsets, begin) != bisect_left(offsets, begin + insn.size):
                refuse("symbolic-access"); continue
            candidates.append(Site(block, displacement, load, recipe, origin))
    if not candidates:
        raise ValueError("RISC fault prechecks selected no proved scalar loads")
    if any(s.name == TABLE_SECTION for s in module.sections):
        raise ValueError("duplicate fault table")
    protected = next((s for s in module.sections if s.name == PROTECTED_SECTION), None)
    if protected is None:
        protected = gtirb.Section(name=PROTECTED_SECTION, module=module, flags={
            gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, gtirb.Section.Flag.Loaded})
        set_elf_section_properties(protected, 8, 3)
    elif module.aux_data["sectionProperties"].data.get(protected) != (8, 3):
        raise ValueError("RISC fault state is not protected NOBITS")
    storage, spill_size = (len(candidates) + 7) & ~7, 24 if isa == "aarch64" else 16
    state = _new_interval(module, protected, b"")
    state.size = 2 * storage + spill_size * len(candidates)
    counters = gtirb.DataBlock(size=storage, byte_interval=state)
    pending = gtirb.DataBlock(size=storage, offset=storage, byte_interval=state)
    cs, ce = _label(module, counters, "counters"), _label(module, counters, "counters_end", True)
    ps, pe = _label(module, pending, "pending"), _label(module, pending, "pending_end", True)
    align = module.aux_data.setdefault("alignment", gtirb.AuxData({}, "mapping<UUID,uint64_t>"))
    align.data[counters] = align.data[pending] = 8
    align.data[interval] = ISOLATION
    instruction_alignment = 4 if isa == "aarch64" else 2
    policy, rollback = _external(module, "teapot_fault_risc_policy"), _external(module, "restore_checkpoint_SIGSEGV")
    by_block = {}
    for index, site in enumerate(candidates):
        by_block.setdefault(site.block, []).append((index, site))
    records = [None] * len(candidates)
    for block, group in by_block.items():
        raw, leading, trailing = _split_raw(module, block, [(s.offset, s.load.input_size) for _, s in group])
        bs, be = _label(module, leading, f"block_{block.uuid.hex}"), _label(module, trailing, f"block_end_{block.uuid.hex}", True)
        for (index, site), access in zip(group, raw):
            align.data[access] = instruction_alignment
            spill = gtirb.DataBlock(size=spill_size, offset=2 * storage + spill_size * index, byte_interval=state)
            align.data[spill] = 8
            end = gtirb.CodeBlock(size=0, offset=access.offset + access.size, byte_interval=interval)
            records[index] = dict(site=site, block=access, pc=_label(module, access, f"site_{index}"),
                ret=_label(module, end, f"return_{index}"), bs=bs, be=be,
                spill=_label(module, spill, f"spill_{index}"), island=islands[owners[block]])
    for block in interval.blocks:
        if block not in original_blocks and isinstance(block, gtirb.CodeBlock):
            # New partition/return/island anchors must not infer stronger
            # instruction alignment from a provisional address.
            align.data[block] = instruction_alignment
    _splice_batch(module, interval, [(r["block"].offset, 2, r["site"].load.code)
                                    for r in records if r["site"].load.input_size == 2])
    plans = {}
    for index, record in enumerate(records):
        at = record["island"].offset
        payload, group = plans.setdefault(at, (bytearray(), []))
        template = guard_template(record["site"].load, record["site"].recipe)
        group.append((index, record, len(payload), template)); payload.extend(template.code)
    positions = _splice_batch(module, interval, [(at, 0, bytes(data)) for at, (data, _) in plans.items()],
                              left=set(islands.values()))
    attrs = gtirb.SymbolicExpression.Attribute
    for original_at, (_, group) in sorted(plans.items()):
        scope_begin, scope_end = None, None
        for index, record, local, template in group:
            at = positions[original_at] + local
            relocations = {r.offset: r for r in template.relocations}
            boundaries = sorted({0, len(template.code), template.copy_offset, template.copy_offset + 4} |
                                set(relocations) | {p + 4 for p in relocations})
            chunks = {begin: (gtirb.CodeBlock if begin in relocations else gtirb.DataBlock)(
                size=end - begin, offset=at + begin, byte_interval=interval)
                for begin, end in zip(boundaries, boundaries[1:])}
            for chunk in chunks.values():
                align.data[chunk] = instruction_alignment
            end = gtirb.CodeBlock(size=0, offset=at + len(template.code), byte_interval=interval)
            align.data[end] = instruction_alignment
            record.update(stub=_label(module, chunks[0], f"stub_{index}"),
                          copy=_label(module, chunks[template.copy_offset], f"copy_{index}"),
                          copy_end=_label(module, chunks[template.copy_offset + 4], f"copy_end_{index}"),
                          stub_end=_label(module, end, f"stub_end_{index}"))
            if scope_begin is None:
                scope_begin = chunks[0]
            scope_end = end
            targets = dict(spill=record["spill"], policy=policy, rollback=rollback, **{"return": record["ret"]})
            anchors = {}
            for relocation in template.relocations:
                flags = {"page": {attrs.PAGE}, "lo12": {attrs.LO12}, "hi": {attrs.HI, attrs.PCREL},
                         "lo": {attrs.LO, attrs.PCREL}, "branch": set()}[relocation.kind]
                target = targets[relocation.target]
                if relocation.kind == "hi":
                    anchors[relocation.offset] = _label(module, chunks[relocation.offset], f"auipc_{index}_{relocation.offset}")
                if relocation.kind == "lo":
                    target = anchors[relocation.anchor]
                interval.symbolic_expressions[at + relocation.offset] = gtirb.SymAddrConst(0, target, flags)
        if isa == "riscv64":
            # Adjacent stubs share one owned island scope. Independent end and
            # next-begin labels at the same address have no printer ordering
            # guarantee; a single pair avoids accidental nesting entirely.
            _scope(module, scope_begin, scope_end, group[0][0])
    # This is after the architecture's raw branch relaxer: unrelated intervals
    # can intentionally retain interior alignment residues which only the
    # printer resolves. Do not run global layout or modify their metadata here.
    # All new cross-block references are symbolic; the printer/linker establish
    # their final addresses and the read-only ELF validator checks both ends.
    padding = -interval.size % ISOLATION
    if padding:
        begin = interval.size
        interval.contents = bytes(interval.contents).ljust(begin, b"\0") + bytes(padding)
        interval.size += padding
        gtirb.DataBlock(size=padding, offset=begin, byte_interval=interval)
    text_bounds[1].referent.offset = interval.size
    align.data[text_bounds[1].referent] = ISOLATION  # after printed compression/relaxation too
    table_section = gtirb.Section(name=TABLE_SECTION, module=module, flags={
        gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
    set_elf_section_properties(table_section, 1, 2)
    contents = bytearray(struct.pack("<IHHIIII", MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE,
                                    len(records), FLAGS, threshold))
    contents.extend(bytes(HEADER_SIZE - len(contents) + ENTRY_SIZE * len(records)))
    table_interval = _new_interval(module, table_section, bytes(contents))
    header = gtirb.DataBlock(size=24, byte_interval=table_interval)
    table = _label(module, header, "sites"); align.data[header] = 8
    gtirb.DataBlock(size=24, offset=88, byte_interval=table_interval)
    for offset, symbol in zip(range(24, 88, 8), (*text_bounds, *text_bounds, cs, ce, ps, pe)):
        _relative(module, table_interval, offset, 8, symbol)
    for index, record in enumerate(records):
        site, begin = record["site"], HEADER_SIZE + ENTRY_SIZE * index
        for offset, key in ((0, "pc"), (4, "stub"), (8, "copy"), (16, "ret"), (20, "copy_end"),
                            (24, "bs"), (28, "be"), (32, "spill"), (44, "stub_end")):
            _relative(module, table_interval, begin + offset, 4, record[key])
        _relative(module, table_interval, begin + 36, 4, policy)
        _relative(module, table_interval, begin + 40, 4, rollback)
        struct.pack_into("<HH", contents, begin + 12, 4, 0)
        load, recipe = site.load, site.recipe
        struct.pack_into("<I12BqHH", contents, begin + 48, load.word, site.origin, load.width,
            load.base, load.index, load.extension, load.shift, load.destination, recipe.bootstrap,
            recipe.temp0, recipe.temp1, load.kind, 0, load.displacement, spill_size, recipe.template)
        for offset, size in ((12, 4), (48, 80)):
            gtirb.DataBlock(size=size, offset=begin + offset, byte_interval=table_interval)
    table_interval.contents = bytes(contents)
    if comments is not None:
        for key, value in tuple(comments.items()):
            if INPUT_TAG in value.split("\n"):
                remaining = "\n".join(v for v in value.split("\n") if v != INPUT_TAG)
                if remaining: comments[key] = remaining
                else: del comments[key]
    widened = sum(s.load.input_size == 2 for s in candidates)
    print(f"[teapot] adaptive {isa}: {len(records)} sites; {widened} widened loads/+{2 * widened} raw bytes; "
          f"rejections={refusals}; actual linked growth requires final ELF measurement", flush=True)
    return table
