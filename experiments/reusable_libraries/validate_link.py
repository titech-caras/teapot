#!/usr/bin/env python3
"""Fail-closed structural checks on the final experimental component link."""
import argparse
import hashlib
import json
from pathlib import Path

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile


def validate(binary, objects):
    manifest = json.loads((objects / "components.json").read_text())
    inputs = json.loads((objects / "inputs.json").read_text())
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        assert elf["e_type"] == "ET_EXEC" and elf["e_machine"] == "EM_X86_64"
        symbols = {}
        for symbol in elf.get_section_by_name(".symtab").iter_symbols():
            if symbol["st_shndx"] != "SHN_UNDEF":
                symbols.setdefault(symbol.name, []).append(symbol)

        def address(name):
            matches = symbols.get(name, [])
            assert len(matches) == 1, ("symbol is not a unique definition", name)
            return matches[0]["st_value"]

        needed = [tag.needed for tag in elf.get_section_by_name(".dynamic").iter_tags()
                  if tag.entry.d_tag == "DT_NEEDED"]
        assert needed[0] == "libasan.so.8" and needed.count("libasan.so.8") == 1, needed
        assert not {item["soname"] for item in inputs["selected"]}.intersection(needed), needed
        ranges = {}
        for kind, name in (("normal", ".teapot_component_text"), ("transient", ".teapot_transient")):
            section = elf.get_section_by_name(name)
            start = address("__teapot_linked_" + kind + "_start")
            end = address("__teapot_linked_" + kind + "_end")
            assert section["sh_flags"] & 7 == 6
            assert (start, end) == (section["sh_addr"], section["sh_addr"] + section["sh_size"])
            assert start < end
            ranges[kind] = (start, end)
        assert ranges["normal"][1] <= ranges["transient"][0]
        for name in ("make_checkpoint_x64", "restore_checkpoint", "report_gadget_KASPER_MDS"):
            entry = address(name)
            assert all(not start <= entry < end for start, end in ranges.values()), name
        for section in elf.iter_sections():
            if section["sh_flags"] & 4 and section.name not in (".teapot_component_text", ".teapot_transient"):
                start, end = section["sh_addr"], section["sh_addr"] + section["sh_size"]
                assert all(end <= lower or start >= upper for lower, upper in ranges.values()), section.name
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
            normal = elf.get_section_by_name(".teapot_component_text")
            for name in component["exports"]:
                entry = address(name)
                assert ranges["normal"][0] <= entry < ranges["normal"][1], name
                offset = entry - normal["sh_addr"]
                assert normal.data()[offset:offset + 8] == bytes.fromhex("4887db904887d290"), name
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
    return {"status": "structural_checks_passed_behavior_still_required", "needed": needed,
            "target_ranges": ranges, "guard_ranges": guard_ranges,
            "guard_slots_including_alignment": (guard_end - guard_start) // 4,
            "guard_slots_used": sum(c["guard_count"] for c in manifest["components"]),
            "fde_count": len(fdes), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--objects", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.binary, args.objects)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
