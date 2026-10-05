"""The module record of the rewrite/runtime contract (libcheckpoint's runtime_contract.h).

Every rewritten module carries one record in section teapot_contract: the
runtime's contract version and ABI fingerprint, the capabilities the rewrite
needs and the address of the runtime record's anchor symbol, followed by a
JSON copy of the ABI, the requirements, the rewrite's policy (with whether it
pushes speculative coverage) and, for a component, its identity. The anchor
reference makes linking an archive with another ABI fail and pulls the runtime
record into every link; the runtime checks the records at start-up. A note in
.note.teapot.contract refers to the record: linkers keep allocated notes under
--gc-sections, and with it the record, which nothing else refers to but the
runtime's __start_/__stop_ walk.
"""
from dataclasses import asdict
import json
import struct

import gtirb

from teapot.configs.runtime import ROB_LEN
from teapot.preprocess.copy_section import SHF_ALLOC, SHT_PROGBITS, set_elf_section_properties
from teapot.runtime_contract import CAPABILITIES

RECORD_SECTION = "teapot_contract"
NOTE_SECTION = ".note.teapot.contract"
RECORD_AUX_DATA = "teapotRuntimeContract"
SHT_NOTE = 7
# The keeper note: owner name, type, and a descriptor holding the record's address.
NOTE_OWNER = b"TeapotABI\0"
NOTE_TYPE_RECORD = 1
RECORD_MAGIC = 0x54435054
RECORD_KIND_MODULE = 2
# magic, version, kind, header size, JSON size, fingerprint, capabilities; then
# the anchor's address at ANCHOR_OFFSET.
_HEADER = struct.Struct("<IHHIIQQ")
ANCHOR_OFFSET = _HEADER.size
RECORD_HEADER_SIZE = ANCHOR_OFFSET + 8


def module_contract(contract, required_bits: int, options, component_id=None) -> dict:
    record = {
        "schema": "teapot-module-contract",
        "version": contract.version,
        "fingerprint": contract.fingerprint,
        "anchor": contract.anchor,
        "requirements": [name for bit, name in enumerate(CAPABILITIES) if required_bits >> bit & 1],
        "abi": dict(contract.abi),
        # coverage: whether this module pushes the speculative coverage guards.
        "policy": {"rob_len": ROB_LEN, "options": asdict(options), "coverage": contract.emits_coverage(options)},
    }
    if component_id is not None:
        record["component"] = component_id
    return record


def _new_interval(module, section, contents):
    # Added after the last rewrite round, so no layout places it: give it an
    # address past every other interval, as later stages (debug lines) need one.
    ends = [interval.address + interval.size for interval in module.byte_intervals
            if interval.address is not None]
    return gtirb.ByteInterval(section=section, address=(max(ends, default=0) + 7) & ~7,
                              contents=contents, size=len(contents))


def add_contract_record(module: gtirb.Module, contract, required_bits: int, options,
                        component_id=None) -> gtirb.DataBlock:
    anchor = next(module.symbols_named(contract.anchor), None)
    if anchor is None:
        raise ValueError(f"the runtime anchor {contract.anchor} was not imported")
    text = json.dumps(module_contract(contract, required_bits, options, component_id), sort_keys=True,
                      separators=(",", ":"))
    payload = text.encode()
    header = _HEADER.pack(RECORD_MAGIC, contract.version, RECORD_KIND_MODULE, RECORD_HEADER_SIZE,
                          len(payload), int(contract.fingerprint, 16), required_bits)
    contents = header + bytes(8) + payload
    contents += bytes(-len(contents) % 8)

    section = gtirb.Section(
        name=RECORD_SECTION, module=module,
        flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
    set_elf_section_properties(section, SHT_PROGBITS, SHF_ALLOC)
    interval = _new_interval(module, section, contents)
    block = gtirb.DataBlock(offset=0, size=len(contents), byte_interval=interval)
    interval.symbolic_expressions[ANCHOR_OFFSET] = gtirb.SymAddrConst(0, anchor)
    record = gtirb.Symbol(name=".L__teapot_contract_record", payload=block, module=module)

    # The assembler types a .note section as a note from its name.
    note_section = gtirb.Section(name=NOTE_SECTION, module=module, flags=set(section.flags))
    set_elf_section_properties(note_section, SHT_NOTE, SHF_ALLOC)
    owner = NOTE_OWNER + bytes(-len(NOTE_OWNER) % 4)
    note_header = struct.pack("<III", len(NOTE_OWNER), 8, NOTE_TYPE_RECORD) + owner
    note_interval = _new_interval(module, note_section, note_header + bytes(8))
    note = gtirb.DataBlock(offset=0, size=note_interval.size, byte_interval=note_interval)
    note_interval.symbolic_expressions[len(note_header)] = gtirb.SymAddrConst(0, record)

    sizes = module.aux_data.setdefault(
        "symbolicExpressionSizes", gtirb.AuxData(type_name="mapping<Offset,uint64_t>", data={}))
    sizes.data[gtirb.Offset(interval, ANCHOR_OFFSET)] = 8
    sizes.data[gtirb.Offset(note_interval, len(note_header))] = 8
    alignment = module.aux_data.setdefault(
        "alignment", gtirb.AuxData(type_name="mapping<UUID,uint64_t>", data={}))
    alignment.data[block] = 8
    alignment.data[note] = 8
    module.aux_data[RECORD_AUX_DATA] = gtirb.AuxData(text, "string")
    return block
