#!/usr/bin/env python3
"""Fail-closed structural checks on the final experimental component link."""
import argparse
import hashlib
import json
from pathlib import Path

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from experiments.reusable_libraries.targets import (
    TARGETS, MODES, TARGET_IDENTIFICATIONS, mode_for, mode_metadata, target_for)


def validate_dynamic_symbol_names(elf):
    table = elf.get_section_by_name('.dynsym')
    if table is None:
        return
    strings = elf.get_section(table['sh_link']).data()
    for symbol in table.iter_symbols():
        offset = symbol['st_name']
        assert 0 <= offset < len(strings) and strings.find(b'\0', offset) != -1, (
            'dynamic symbol name is outside its string table', offset, len(strings))


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


def validate_bti_layout(elf, address, ranges, target_identification='aarch64-bti-pac'):
    """Verify the mapping that runtime activation will scan and guard.

    The probe/padding is guarded but is deliberately not an application target.
    No runtime code, writable data or native-landing detour may share its pages.
    """
    normal = elf.get_section_by_name('.teapot_bti_normal')
    lo, hi = address('__teapot_bti_guard_start'), address('__teapot_bti_guard_end')
    assert lo % 65536 == hi % 65536 == 0 and lo < hi, 'BTI guard must isolate 64 KiB pages'
    assert (lo, hi) == (normal['sh_addr'], normal['sh_addr'] + normal['sh_size'])
    assert ranges['normal'][0] == lo and ranges['normal'][1] <= hi - 8
    for kind, prefix in (('normal', 'text'), ('transient', 'transient')):
        assert ranges[kind] == (address('__teapot_bti_' + prefix + '_start'),
                                address('__teapot_bti_' + prefix + '_end')), 'BTI/application bounds disagree'
    assert ranges['transient'][0] >= ranges['normal'][1], 'BTI copy must follow normal text'
    assert ranges['transient'][1] <= hi - 8, 'BTI copy must stay inside the guard'
    for section in elf.iter_sections():
        if section.name != '.teapot_bti_normal' and section['sh_flags'] & 2 and section['sh_size']:
            start, end = section['sh_addr'], section['sh_addr'] + section['sh_size']
            assert end <= lo or start >= hi, ('BTI guard overlaps another section', section.name)
    mappings = [segment for segment in elf.iter_segments()
                if segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= lo and
                segment['p_vaddr'] + segment['p_memsz'] >= hi]
    assert len(mappings) == 1 and mappings[0]['p_flags'] & 7 == 5, 'BTI guard must have one RX mapping'
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
                assert data[offset:offset + 8] == marker, (
                    'unmatched native BTI/PAC landing in ' + kind + ' text')
    for name in ('valid', 'invalid', 'brk', 'hlt'):
        probe = address('teapot_bti_probe_' + name)
        assert ranges['transient'][1] <= probe <= hi - 4 and probe % 4 == 0, (
            'BTI probe enters application targets')
    prepare_symbol = ('libcheckpoint_prepare_aarch64_bti_pac_components'
                      if target_identification == 'aarch64-bti-pac'
                      else 'libcheckpoint_prepare_aarch64_bti_components')
    prepare = address(prepare_symbol)
    assert not lo <= prepare < hi, 'BTI initializer is guarded'
    callback = address('__teapot_bti_component_preinit')
    preinit = elf.get_section_by_name('.preinit_array')
    assert preinit is not None and preinit['sh_addr'] <= callback <= preinit['sh_addr'] + preinit['sh_size'] - 8, (
        'missing BTI component preinit adapter')
    offset = callback - preinit['sh_addr']
    assert int.from_bytes(preinit.data()[offset:offset + 8], 'little') == prepare, 'wrong BTI preinit target'
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
        assert elf["e_type"] == "ET_EXEC"
        assert elf.elfclass == 64 and elf.little_endian
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
            assert len(matches) == 1, ("symbol is not a unique definition", name)
            return matches[0]["st_value"]

        needed = [tag.needed for tag in elf.get_section_by_name(".dynamic").iter_tags()
                  if tag.entry.d_tag == "DT_NEEDED"]
        if asan is None:
            assert not any(name.startswith('libasan.so') for name in needed), needed
        else:
            assert needed[0] == asan and needed.count(asan) == 1, needed
        assert not {item["soname"] for item in inputs["selected"]}.intersection(needed), needed
        ranges = {}
        for kind, name in (("normal", target['text_section']), ("transient", ".teapot_transient")):
            section = elf.get_section_by_name(name)
            start = address("__teapot_linked_" + kind + "_start")
            end = address("__teapot_linked_" + kind + "_end")
            if section is None:
                # The BTI mode merges the copy into the one guarded section.
                assert (target_identification == 'aarch64-bti-pac' and
                        kind == 'transient'), name
            else:
                assert section["sh_flags"] & 7 == 6
                if kind == 'normal' and target_identification == 'aarch64-bti-pac':
                    assert start == section['sh_addr'] and end <= start + section['sh_size']
                else:
                    assert (start, end) == (section["sh_addr"], section["sh_addr"] + section["sh_size"])
            assert start < end
            ranges[kind] = (start, end)
        assert ranges["normal"][1] <= ranges["transient"][0]
        assert not any(ranges["normal"][1] < section["sh_addr"] < ranges["transient"][0]
                       for section in elf.iter_sections()
                       if section["sh_flags"] & 2 and section["sh_size"]), \
            'a section lies between the two application copies'
        for name in (target['checkpoint'], "restore_checkpoint", "report_gadget_KASPER_MDS"):
            entry = address(name)
            assert all(not start <= entry < end for start, end in ranges.values()), name
        for section in elf.iter_sections():
            if section["sh_flags"] & 4 and section.name not in (target['text_section'], ".teapot_transient"):
                start, end = section["sh_addr"], section["sh_addr"] + section["sh_size"]
                assert all(end <= lower or start >= upper for lower, upper in ranges.values()), section.name
        bti_guard = (validate_bti_layout(elf, address, ranges, target_identification)
                     if target_identification == 'aarch64-bti-pac' else None)
        guard_section = elf.get_section_by_name(".teapot_component_guards")
        guard_start, guard_end = address("__guard_start__teapot__"), address("__guard_end__teapot__")
        assert (guard_start, guard_end) == (guard_section["sh_addr"], guard_section["sh_addr"] + guard_section["sh_size"])
        assert guard_start % 4 == guard_end % 4 == 0
        assert 0 <= (guard_end - guard_start) // 4 < 0x80000000
        guard_ranges = []
        for component in manifest["components"]:
            key = component["component_id"]
            start, end = (address("__guard_" + kind + "__teapot___" + key) for kind in ("start", "end"))
            assert guard_start <= start <= end <= guard_end
            assert start % 4 == 0 and end - start == component["guard_count"] * 4
            index = address("__teapot_component_guard_base_" + key)
            assert index == (start - guard_start) // 4, ("guard-base alignment mismatch", key, index, start)
            guard_ranges.append((start, end))
            normal = elf.get_section_by_name(target['text_section'])
            for name in component["exports"]:
                entry = address(name)
                assert ranges["normal"][0] <= entry < ranges["normal"][1], name
                offset = entry - normal["sh_addr"]
                assert normal.data()[offset:offset + len(target['marker'])] == target['marker'], name
            for name in component.get("linked_exports", ()):
                address(name)
        for (left_start, left_end), (right_start, right_end) in zip(sorted(guard_ranges), sorted(guard_ranges)[1:]):
            assert left_end <= right_start, "overlapping component guard storage"
        # New manifests include version-resolved function AND data exports.
        # Retain the original check for historical unversioned manifests.
        for item in ([] if all("linked_exports" in c for c in manifest["components"])
                     else inputs["selected"]):
            for symbol in item["symbols"]:
                if (symbol["section"] != "SHN_UNDEF" and symbol["binding"] == "STB_GLOBAL"
                        and symbol["visibility"] == "STV_DEFAULT"):
                    address(symbol["name"])
        fdes = [entry for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry, FDE)]
        assert len(fdes) >= sum(len(item["application_fdes"]) for item in [inputs["executable"]] + inputs["selected"])
    return {"status": "structural_checks_passed_behavior_still_required", "needed": needed, 'isa': isa,
            'mode': mode, 'target_identification': target_identification, 'bti_guard': bti_guard,
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
