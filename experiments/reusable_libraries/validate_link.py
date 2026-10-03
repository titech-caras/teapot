#!/usr/bin/env python3
"""Fail-closed structural checks on the final experimental component link."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

# The repository root holds the teapot, experiments and tools packages imported below. Put it
# first on the path, so the script imports its own checkout and runs by its file path from any
# directory.
_ROOT = str(Path(__file__).resolve().parents[2])
sys.path[:] = [_ROOT] + [entry for entry in sys.path if entry != _ROOT]

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from experiments.reusable_libraries.targets import (
    TARGETS, MODES, TARGET_IDENTIFICATIONS, mode_for, mode_metadata, target_for)
from teapot.preprocess.contract_record import RECORD_HEADER_SIZE, RECORD_KIND_MODULE, RECORD_MAGIC
from teapot.runtime_contract import CAPABILITIES

RUNTIME_RECORD_KIND = 1
# libcheckpoint's runtime_contract.h: magic, version, kind, header size, JSON
# size, fingerprint, capabilities, anchor.
_RECORD = struct.Struct("<IHHIIQQQ")


def require(condition, *message):
    """A fail-closed check that, unlike assert, survives python -O."""
    if not condition:
        raise ValueError(*message)


def validate_dynamic_symbol_names(elf):
    table = elf.get_section_by_name('.dynsym')
    if table is None:
        return
    strings = elf.get_section(table['sh_link']).data()
    for symbol in table.iter_symbols():
        offset = symbol['st_name']
        require(0 <= offset < len(strings) and strings.find(b'\0', offset) != -1, (
            'dynamic symbol name is outside its string table', offset, len(strings)))


def validate_mode_contract(manifest, *, isa=None, mode=None, target_identification=None):
    """Derive the build contract and refuse requests or components that differ."""
    fields = ('isa', 'mode', 'dift_layout', 'tag_storage', 'target_identification')
    if any(field not in manifest for field in fields):
        raise ValueError('component manifest has no complete build mode; rebuild it with the current driver')
    actual_isa, actual_mode = manifest['isa'], manifest['mode']
    if actual_isa not in TARGETS or actual_mode not in MODES:
        raise ValueError(f'unsupported manifest ISA/mode: {actual_isa}/{actual_mode}')
    expected = mode_metadata(actual_isa, actual_mode, manifest['target_identification'])
    if any(manifest[field] != expected[field] for field in fields):
        raise ValueError('manifest DIFT layout or tag storage does not match its build mode')
    if isa is not None and isa != actual_isa:
        raise ValueError(f'ISA mismatch: built {actual_isa}, requested {isa}')
    if mode is not None and mode != actual_mode:
        raise ValueError(f'mode mismatch: built {actual_mode}, requested {mode}')
    if target_identification is not None and target_identification != manifest['target_identification']:
        raise ValueError('target identification mismatch: built ' + manifest['target_identification'] +
                         ', requested ' + target_identification)
    for component in manifest['components']:
        if any(component.get(field) != expected[field] for field in fields):
            raise ValueError('component build mode mismatch: ' + component.get('component_id', '<unknown>'))
    return actual_isa, actual_mode


def contract_records(elf, section_name, kind):
    """Parse the contract records the link concatenated in one section."""
    section = elf.get_section_by_name(section_name)
    if section is None:
        return []
    data, base, records, offset = section.data(), section["sh_addr"], [], 0
    # As the runtime's start-up walk does: from an 8-byte-aligned start, every
    # record's extent rounded to 8 bytes must lie inside the section.
    require(base % 8 == 0, ("misaligned contract record section", section_name, base))
    while offset < len(data):
        if data[offset:offset + 8] == bytes(8):
            offset += 8  # alignment padding between two objects' records
            continue
        require(offset + RECORD_HEADER_SIZE <= len(data), ("truncated contract record", section_name, offset))
        magic, version, record_kind, header_size, json_size, fingerprint, capabilities, anchor = \
            _RECORD.unpack_from(data, offset)
        require(magic == RECORD_MAGIC and record_kind == kind and header_size == RECORD_HEADER_SIZE,
                ("malformed contract record", section_name, offset))
        end = offset + header_size + json_size
        size = (header_size + json_size + 7) & ~7
        require(offset + size <= len(data), ("truncated contract record", section_name, offset))
        try:
            contract = json.loads(data[offset + header_size:end]) if json_size else {}
        except ValueError as error:
            raise ValueError(("unreadable contract record JSON", section_name, offset, str(error))) from None
        records.append(dict(address=base + offset, version=version, fingerprint=f"{fingerprint:016x}",
                            capabilities=capabilities, anchor=anchor, contract=contract))
        offset += size
    return records


def capability_names(bits):
    return [name for index, name in enumerate(CAPABILITIES) if bits >> index & 1] + (
        [f"unknown 0x{bits >> len(CAPABILITIES) << len(CAPABILITIES):x}"] if bits >> len(CAPABILITIES) else [])


def validate_contract_records(elf, address, manifest):
    """Compare every component's record with the runtime record the link actually holds."""
    runtimes = contract_records(elf, "libcheckpoint_contract", RUNTIME_RECORD_KIND)
    require(len(runtimes) == 1, ("the link holds one libcheckpoint runtime record", len(runtimes)))
    runtime = runtimes[0]
    require(runtime["address"] == address("libcheckpoint_runtime_contract"),
            "libcheckpoint_runtime_contract is not the runtime record")
    abi = runtime["contract"].get("abi", {})
    modules = contract_records(elf, "teapot_contract", RECORD_KIND_MODULE)
    # Each component's record names it, so another object's record cannot
    # stand in for a component that has none.
    owners = sorted(str(record["contract"].get("component")) for record in modules)
    require(owners == sorted(component["component_id"] for component in manifest["components"]),
            ("one module contract record per component", owners,
             sorted(component["component_id"] for component in manifest["components"])))
    for record in modules:
        module_abi = record["contract"].get("abi", {})
        differences = [f"{key}: component {module_abi.get(key)!r}, runtime {abi.get(key)!r}"
                       for key in sorted(set(module_abi) | set(abi)) if module_abi.get(key) != abi.get(key)]
        require((record["version"], record["fingerprint"]) == (runtime["version"], runtime["fingerprint"])
                and not differences,
                ("a component was rewritten for a runtime with another ABI", record["fingerprint"],
                 runtime["fingerprint"], differences))
        require(record["anchor"] == runtime["address"], "a component record does not refer to the linked runtime")
        missing = record["capabilities"] & ~runtime["capabilities"]
        require(not missing, ("a component needs runtime capabilities the linked archive lacks",
                              capability_names(missing)))
    recorded = manifest.get("runtime_contract")
    require(recorded is not None, "component manifest has no runtime contract; rebuild it with the current driver")
    require((recorded["version"], recorded["fingerprint"]) == (runtime["version"], runtime["fingerprint"]),
            ("the components were built for another runtime contract", recorded, runtime["fingerprint"]))
    return {"version": runtime["version"], "fingerprint": runtime["fingerprint"],
            "runtime_capabilities": capability_names(runtime["capabilities"]),
            "module_records": len(modules)}


def validate_bti_layout(elf, address, ranges, target_identification='aarch64-bti-pac'):
    """Verify the mapping that runtime activation will scan and guard.

    The probe/padding is guarded but is deliberately not an application target.
    No runtime code, writable data or native-landing detour may share its pages.
    """
    normal = elf.get_section_by_name('.teapot_bti_normal')
    lo, hi = address('__teapot_bti_guard_start'), address('__teapot_bti_guard_end')
    require(lo % 65536 == hi % 65536 == 0 and lo < hi, 'BTI guard must isolate 64 KiB pages')
    require((lo, hi) == (normal['sh_addr'], normal['sh_addr'] + normal['sh_size']),
            "check failed: (lo, hi) == (normal['sh_addr'], normal['sh_addr'] + normal['sh_size'])")
    require(ranges['normal'][0] == lo and ranges['normal'][1] <= hi - 8,
            "check failed: ranges['normal'][0] == lo and ranges['normal'][1] <= hi - 8")
    for kind, prefix in (('normal', 'text'), ('transient', 'transient')):
        require(ranges[kind] == (address('__teapot_bti_' + prefix + '_start'),
                                address('__teapot_bti_' + prefix + '_end')), 'BTI/application bounds disagree')
    require(ranges['transient'][0] >= ranges['normal'][1], 'BTI copy must follow normal text')
    require(ranges['transient'][1] <= hi - 8, 'BTI copy must stay inside the guard')
    for section in elf.iter_sections():
        if section.name != '.teapot_bti_normal' and section['sh_flags'] & 2 and section['sh_size']:
            start, end = section['sh_addr'], section['sh_addr'] + section['sh_size']
            require(end <= lo or start >= hi, ('BTI guard overlaps another section', section.name))
    mappings = [segment for segment in elf.iter_segments()
                if segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= lo and
                segment['p_vaddr'] + segment['p_memsz'] >= hi]
    require(len(mappings) == 1 and mappings[0]['p_flags'] & 7 == 5, 'BTI guard must have one RX mapping')
    data = normal.data()
    marker = target_for('ARM64', 'aarch64-bti-pac')['marker']
    backends = (0xd50324df, 0xd503245f, 0xd503249f, 0xd503233f, 0xd503237f)
    # The runtime scans both sub-ranges of the guarded section; mirror it, so a
    # stray native landing in the copied text refuses the link here too.
    for kind in ('normal', 'transient'):
        start, end = ranges[kind]
        for offset in range(start - lo, end - lo, 4):
            word = int.from_bytes(data[offset:offset + 4], 'little')
            if word in backends:
                require(data[offset:offset + 8] == marker, 'unmatched native BTI/PAC landing in ' + kind + ' text')
    for name in ('valid', 'invalid', 'brk', 'hlt'):
        probe = address('teapot_bti_probe_' + name)
        require(ranges['transient'][1] <= probe <= hi - 4 and probe % 4 == 0, 'BTI probe enters application targets')
    prepare_symbol = ('libcheckpoint_prepare_aarch64_bti_pac_components'
                      if target_identification == 'aarch64-bti-pac'
                      else 'libcheckpoint_prepare_aarch64_bti_components')
    prepare = address(prepare_symbol)
    require(not lo <= prepare < hi, 'BTI initializer is guarded')
    callback = address('__teapot_bti_component_preinit')
    preinit = elf.get_section_by_name('.preinit_array')
    require(preinit is not None and
            preinit['sh_addr'] <= callback <= preinit['sh_addr'] + preinit['sh_size'] - 8,
            'missing BTI component preinit adapter')
    offset = callback - preinit['sh_addr']
    require(int.from_bytes(preinit.data()[offset:offset + 8], 'little') == prepare, 'wrong BTI preinit target')
    return (lo, hi)


def validate(binary, objects, *, isa=None, mode=None, target_identification=None):
    manifest = json.loads((objects / "components.json").read_text())
    isa, mode = validate_mode_contract(manifest, isa=isa, mode=mode,
                                       target_identification=target_identification)
    target_identification = manifest['target_identification']
    target = target_for(isa, target_identification)
    _, mode_spec = mode_for(isa, mode)
    asan = mode_spec['asan']
    inputs = json.loads((objects / "inputs.json").read_text())
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        if elf['e_machine'] != target['machine']:
            raise ValueError(f"binary ISA mismatch: built {target['machine']}, found {elf['e_machine']}")
        require(elf["e_type"] == "ET_EXEC", 'check failed: elf["e_type"] == "ET_EXEC"')
        require(elf.elfclass == 64 and elf.little_endian,
                'check failed: elf.elfclass == 64 and elf.little_endian')
        validate_dynamic_symbol_names(elf)
        symbols = {}
        for symbol in elf.get_section_by_name(".symtab").iter_symbols():
            if symbol["st_shndx"] != "SHN_UNDEF":
                symbols.setdefault(symbol.name, []).append(symbol)

        def address(name):
            matches = symbols.get(name, [])
            if len(matches) > 1:
                # A same-named LOCAL definition in another component takes no part in
                # symbol resolution (e.g. libssl's internal WPACKET_* copy next to the
                # export-all libcrypto's global WPACKET_* exports).
                matches = [s for s in matches if s["st_info"]["bind"] != "STB_LOCAL"]
            require(len(matches) == 1, ("symbol is not a unique definition", name))
            return matches[0]["st_value"]

        needed = [tag.needed for tag in elf.get_section_by_name(".dynamic").iter_tags()
                  if tag.entry.d_tag == "DT_NEEDED"]
        if asan is None:
            require(not any(name.startswith('libasan.so') for name in needed), needed)
        else:
            require(needed[0] == asan and needed.count(asan) == 1, needed)
        require(not {item["soname"] for item in inputs["selected"]}.intersection(needed), needed)
        ranges = {}
        for kind, name in (("normal", target['text_section']), ("transient", ".teapot_transient")):
            section = elf.get_section_by_name(name)
            start = address("__teapot_linked_" + kind + "_start")
            end = address("__teapot_linked_" + kind + "_end")
            if section is None:
                # The BTI mode merges the copy into the one guarded section.
                require(target_identification == 'aarch64-bti-pac' and
                        kind == 'transient', name)
            else:
                require(section["sh_flags"] & 7 == 6, 'check failed: section["sh_flags"] & 7 == 6')
                if kind == 'normal' and target_identification == 'aarch64-bti-pac':
                    require(start == section['sh_addr'] and end <= start + section['sh_size'],
                            "check failed: start == section['sh_addr'] and end <= start + section['sh_size']")
                else:
                    require((start, end) == (section["sh_addr"], section["sh_addr"] + section["sh_size"]),
                            'check failed: (start, end) is not the extent of the section')
            require(start < end, 'check failed: start < end')
            ranges[kind] = (start, end)
        require(ranges["normal"][1] <= ranges["transient"][0],
                'check failed: ranges["normal"][1] <= ranges["transient"][0]')
        require(not any(ranges["normal"][1] < section["sh_addr"] < ranges["transient"][0]
                        for section in elf.iter_sections()
                        if section["sh_flags"] & 2 and section["sh_size"]),
                'a section lies between the two application copies')
        for name in (target['checkpoint'], "restore_checkpoint", "report_gadget_KASPER_MDS"):
            entry = address(name)
            require(all(not start <= entry < end for start, end in ranges.values()), name)
        for section in elf.iter_sections():
            if section["sh_flags"] & 4 and section.name not in (target['text_section'], ".teapot_transient"):
                start, end = section["sh_addr"], section["sh_addr"] + section["sh_size"]
                require(all(end <= lower or start >= upper for lower, upper in ranges.values()), section.name)
        bti_guard = (validate_bti_layout(elf, address, ranges, target_identification)
                     if target_identification == 'aarch64-bti-pac' else None)
        runtime_contract = validate_contract_records(elf, address, manifest)
        guard_section = elf.get_section_by_name(".teapot_component_guards")
        guard_start, guard_end = address("__guard_start__teapot__"), address("__guard_end__teapot__")
        require((guard_start, guard_end) ==
                (guard_section["sh_addr"], guard_section["sh_addr"] + guard_section["sh_size"]),
                'check failed: the guard bounds are not the extent of .teapot_component_guards')
        require(guard_start % 4 == guard_end % 4 == 0, 'check failed: guard_start % 4 == guard_end % 4 == 0')
        require(0 <= (guard_end - guard_start) // 4 < 0x80000000,
                'check failed: 0 <= (guard_end - guard_start) // 4 < 0x80000000')
        guard_ranges = []
        for component in manifest["components"]:
            key = component["component_id"]
            start, end = (address("__guard_" + kind + "__teapot___" + key) for kind in ("start", "end"))
            require(guard_start <= start <= end <= guard_end,
                    'check failed: guard_start <= start <= end <= guard_end')
            require(start % 4 == 0 and end - start == component["guard_count"] * 4,
                    'check failed: start % 4 == 0 and end - start == component["guard_count"] * 4')
            index = address("__teapot_component_guard_base_" + key)
            require(index == (start - guard_start) // 4, ("guard-base alignment mismatch", key, index, start))
            guard_ranges.append((start, end))
            normal = elf.get_section_by_name(target['text_section'])
            for name in component["exports"]:
                entry = address(name)
                require(ranges["normal"][0] <= entry < ranges["normal"][1], name)
                offset = entry - normal["sh_addr"]
                require(normal.data()[offset:offset + len(target['marker'])] == target['marker'], name)
            for name in component.get("linked_exports", ()):
                address(name)
        for (left_start, left_end), (right_start, right_end) in zip(sorted(guard_ranges), sorted(guard_ranges)[1:]):
            require(left_end <= right_start, "overlapping component guard storage")
        # New manifests include version-resolved function AND data exports.
        # Retain the original check for historical unversioned manifests.
        for item in ([] if all("linked_exports" in c for c in manifest["components"])
                     else inputs["selected"]):
            for symbol in item["symbols"]:
                if (symbol["section"] != "SHN_UNDEF" and symbol["binding"] == "STB_GLOBAL"
                        and symbol["visibility"] == "STV_DEFAULT"):
                    address(symbol["name"])
        fdes = [entry for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry, FDE)]
        require(len(fdes) >= sum(len(item["application_fdes"])
                                 for item in [inputs["executable"]] + inputs["selected"]),
                'check failed: the link has fewer FDEs than its inputs')
    return {"status": "structural_checks_passed_behavior_still_required", "needed": needed, 'isa': isa,
            'mode': mode, 'target_identification': target_identification, 'bti_guard': bti_guard,
            "runtime_contract": runtime_contract,
            "target_ranges": ranges, "guard_ranges": guard_ranges,
            "guard_slots_including_alignment": (guard_end - guard_start) // 4,
            "guard_slots_used": sum(c["guard_count"] for c in manifest["components"]),
            "fde_count": len(fdes), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objects", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument('--isa', choices=tuple(TARGETS), help='optional assertion against the recorded build ISA')
    parser.add_argument('--mode', choices=tuple(MODES))
    parser.add_argument('--target-identification', choices=TARGET_IDENTIFICATIONS,
                        help='optional assertion against the recorded target-identification contract')
    args = parser.parse_args()
    result = validate(args.binary, args.objects, isa=args.isa, mode=args.mode,
                      target_identification=args.target_identification)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
