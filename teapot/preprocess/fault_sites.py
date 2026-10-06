"""Training-only fault metadata. No executable instructions are emitted here.

The final ELF, not GTIRB's provisional layout, is authoritative: a final-link
validator and the runtime reject reordering, relative overflow or bad bounds.
Every relative value is anchored at its own field; entries need no dynamic
relocations. The descriptor is retained through the module contract pointer.
"""
import struct
import gtirb

from teapot.preprocess.contract_record import _new_interval
from teapot.preprocess.copy_section import SHF_ALLOC, SHF_WRITE, SHT_PROGBITS, set_elf_section_properties

MAGIC = 0x53465054
VERSION = 2
HEADER_SIZE = 112
ENTRY_SIZE = 16
TRAINING_ONLY = 1
TABLE_SECTION = "teapot_fault_sites"
PROTECTED_SECTION = "teapot_protected_bss"


def symbol_address(symbol):
    if not isinstance(symbol, gtirb.Symbol) or not isinstance(symbol.referent, gtirb.CodeBlock):
        raise ValueError("fault metadata needs defined code symbols")
    if symbol.referent.address is None:
        raise ValueError("fault metadata needs a completed layout")
    return symbol.referent.address + (symbol.referent.size if symbol.at_end else 0)


def add_fault_site_table(module, sites, threshold, text_start, text_end):
    """Internal API: (patch-PC, stub, copied-access-PC, instruction length).

    No NOP slots: a later backend overwrites the access itself. This format
    describes originals and exact copies, but remains training-only. Final
    validation proves one patchable memory instruction at each PC.
    """
    if type(threshold) is not int or not 0 <= threshold <= 255:
        raise ValueError("fault threshold must be an integer in 0..255")
    pairs = tuple(sites)
    if any(len(site) != 4 for site in pairs):
        raise ValueError("fault site needs patch-PC, stub, copy-PC and length")
    pairs = sorted(pairs, key=lambda pair: symbol_address(pair[0]))
    if not pairs or len(pairs) > 0xffffffff:
        raise ValueError("fault metadata needs 1..UINT32_MAX sites")
    if any(s.name == TABLE_SECTION for s in module.sections):
        raise ValueError("module already has a fault table")
    start, end = symbol_address(text_start), symbol_address(text_end)
    pcs = [symbol_address(pair[0]) for pair in pairs]
    if len(set(pcs)) != len(pcs):
        raise ValueError("duplicate fault PCs")
    previous_end = start
    for pc, stub, copy, length in pairs:
        if type(length) is not int or not (5 <= length <= 15 if module.isa == gtirb.Module.ISA.X64 else length == 4):
            raise ValueError("fault access is not branch-sized")
        if any(s.module is not module for s in (pc, stub, copy)) or pc.at_end or copy.at_end or not (
                previous_end <= symbol_address(pc) and symbol_address(pc) + length <= end and
                start <= symbol_address(stub) < end and start <= symbol_address(copy) and
                symbol_address(copy) + length <= end):
            raise ValueError("fault access/stub/copy is outside its module's copy text or overlaps")
        previous_end = symbol_address(pc) + length
    copies = sorted((symbol_address(copy), length) for _, _, copy, length in pairs)
    original = [(symbol_address(pc), length) for pc, _, _, length in pairs]
    from bisect import bisect_right
    for i, (copy, length) in enumerate(copies):
        if i and copies[i - 1][0] + copies[i - 1][1] > copy:
            raise ValueError("duplicate or overlapping copied-access PCs")
        j = bisect_right(pcs, copy + length - 1) - 1
        if j >= 0 and original[j][0] + original[j][1] > copy:
            raise ValueError("copied access overlaps an original")
    section = gtirb.Section(name=TABLE_SECTION, module=module,
        flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
    set_elf_section_properties(section, SHT_PROGBITS, SHF_ALLOC)
    header = struct.pack("<IHHIIII", MAGIC, VERSION, HEADER_SIZE, ENTRY_SIZE, len(pairs), TRAINING_ONLY, threshold)
    interval = _new_interval(module, section, header + bytes(HEADER_SIZE - len(header) + len(pairs) * ENTRY_SIZE))
    first = gtirb.DataBlock(size=24, offset=0, byte_interval=interval)
    table = gtirb.Symbol(name=".L__teapot_fault_sites", payload=first, module=module)
    gtirb.DataBlock(size=24, offset=88, byte_interval=interval)

    storage_size = (len(pairs) + 7) & ~7
    protected = next((s for s in module.sections if s.name == PROTECTED_SECTION), None)
    if protected is None:
        protected = gtirb.Section(name=PROTECTED_SECTION, module=module,
            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, gtirb.Section.Flag.Loaded})
        set_elf_section_properties(protected, 8, SHF_ALLOC | SHF_WRITE)  # SHT_NOBITS
    elif module.aux_data["sectionProperties"].data.get(protected) != (8, SHF_ALLOC | SHF_WRITE):
        raise ValueError("fault counters require protected NOBITS storage")
    counter_interval = _new_interval(module, protected, b"")
    counter_interval.size = 2 * storage_size
    counters = gtirb.DataBlock(size=storage_size, offset=0, byte_interval=counter_interval)
    pending = gtirb.DataBlock(size=storage_size, offset=storage_size, byte_interval=counter_interval)
    def label(name, block, at_end=False):
        return gtirb.Symbol(name=".L__teapot_fault_" + name, payload=block, at_end=at_end, module=module)
    cs, ce = label("counters", counters), label("counters_end", counters, True)
    ps, pe = label("pending", pending), label("pending_end", pending, True)
    sizes = module.aux_data.setdefault("symbolicExpressionSizes", gtirb.AuxData({}, "mapping<Offset,uint64_t>"))
    align = module.aux_data.setdefault("alignment", gtirb.AuxData({}, "mapping<UUID,uint64_t>"))
    for block in (first, counters, pending): align.data[block] = 8
    def relative(offset, width, target):
        field = gtirb.DataBlock(size=width, offset=offset, byte_interval=interval)
        anchor = label(f"relative_{offset}", field)
        interval.symbolic_expressions[offset] = gtirb.SymAddrAddr(1, 0, target, anchor)
        sizes.data[gtirb.Offset(interval, offset)] = width
    for offset, target in zip(range(24, 88, 8), (text_start, text_end, text_start, text_end, cs, ce, ps, pe)):
        relative(offset, 8, target)
    contents = bytearray(interval.contents)
    for index, (pc, stub, copy, length) in enumerate(pairs):
        relative(HEADER_SIZE + ENTRY_SIZE * index, 4, pc)
        relative(HEADER_SIZE + ENTRY_SIZE * index + 4, 4, stub)
        relative(HEADER_SIZE + ENTRY_SIZE * index + 8, 4, copy)
        offset = HEADER_SIZE + ENTRY_SIZE * index + 12
        struct.pack_into("<HH", contents, offset, length, 0)
        gtirb.DataBlock(size=4, offset=offset, byte_interval=interval)
    interval.contents = bytes(contents)
    return table
