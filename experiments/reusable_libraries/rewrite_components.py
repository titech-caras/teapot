#!/usr/bin/env python3
"""Binary-only x64 component rewriting with validated, content-addressed reuse.

An experimental link driver, not support for executing independently loaded
instrumented DSOs. Only the selected-library converter's supported ELF subset
is accepted. All components must be linked together with the generated layout
and one matching runtime. No instrumentation is disabled.
"""
import argparse
from dataclasses import asdict
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import gtirb
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

from teapot.configs.blacklist import is_blacklisted_function_name
from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.datacls.linked_component import LinkedComponent
from teapot.pipeline import InstrumentationOptions, TeapotPipeline


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def tree_hash(root):
    root = Path(root)
    return {str(path.relative_to(root)): sha(path)
            for path in sorted(root.rglob("*.py")) if path.is_file()}


def run(root, name, command):
    directory = root / name
    directory.mkdir()
    argv = [str(arg) for arg in command]
    dump(directory / "command.json", argv)
    start = time.monotonic()
    with (directory / "stdout").open("wb") as stdout, (directory / "stderr").open("wb") as stderr:
        completed = subprocess.run(argv, stdout=stdout, stderr=stderr)
    dump(directory / "result.json", {"status": completed.returncode,
                                    "seconds": time.monotonic() - start})
    completed.check_returncode()
    return directory


def exports(item):
    return frozenset(symbol["name"] for symbol in item["symbols"]
                     if symbol["section"] != "SHN_UNDEF" and symbol["type"] == "STT_FUNC"
                     and symbol["binding"] == "STB_GLOBAL" and symbol["visibility"] == "STV_DEFAULT")


def validate_object(path, component_id, expected_exports, expected_fdes):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        assert elf["e_type"] == "ET_REL" and elf["e_machine"] == "EM_X86_64"
        table = elf.get_section_by_name(".symtab")
        symbols = {s.name: s for s in table.iter_symbols() if s.name}
        for name in expected_exports:
            symbol = symbols[name]
            assert isinstance(symbol["st_shndx"], int), name
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"]
            assert section.name == ".teapot_component_text", (name, section.name)
            assert section.data()[offset:offset + 8] == bytes.fromhex("4887db904887d290"), (
                "export is missing its full normal-to-transient marker", name)
        for name, flags in ((".teapot_component_text", 6), (".teapot_transient", 6),
                            (".teapot_component_guards." + component_id, 3)):
            section = elf.get_section_by_name(name)
            assert section is not None and section["sh_flags"] & 7 == flags, (name, section)
        fdes = [entry for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry, FDE)]
        assert len(fdes) >= expected_fdes, "original unwind ranges were not reconstructed"


def build_component(args, converter, item, key_data, component_id, selected_symbols, priority, directory):
    dump(directory / "key.json", key_data)
    lifted = directory / "lift.gtirb"
    run(directory, "lift", [args.ddisasm, item["path"], "--ir", lifted, "-j", str(args.jobs)])
    for line in (directory / "lift/stderr").read_text().splitlines():
        if "WARNING" in line or "ERROR" in line:
            if item["role"] == "selected" and item["entry"] == 0 and "WARNING: Failed to set module entry point." in line:
                continue
            raise RuntimeError("frontend diagnostic: " + line)
    ir = gtirb.IR.load_protobuf(lifted)
    assert len(ir.modules) == 1
    module = ir.modules[0]
    assert "liveRegisterSets" in module.aux_data and "liveRegisterNames" in module.aux_data
    cfi = module.aux_data.get("cfiDirectives")
    cfi_starts = {offset.element_id.address + offset.displacement
                  for offset, directives in (cfi.data.items() if cfi else ())
                  if any(directive[0] == ".cfi_startproc" for directive in directives)}
    for fde in item["application_fdes"]:
        assert fde["start"] in cfi_starts, ("unrecovered original unwind range", fde)
    for symbol in module.symbols:
        if SYMBOL_SUFFIX in symbol.name or symbol.name.startswith(("__teapot_linked_", "__teapot_component_")):
            raise RuntimeError("reserved instrumentation symbol in original input: " + symbol.name)
    own_exports = exports(item)
    for name in own_exports:
        definitions = [symbol for symbol in module.symbols_named(name)
                       if isinstance(symbol.referent, gtirb.CodeBlock)]
        if len(definitions) != 1 or definitions[0].referent.section.name != ".text":
            raise RuntimeError("selected export is not a uniquely recovered .text entry: " + name)
    context = LinkedComponent(component_id, selected_symbols, own_exports)
    pipeline = TeapotPipeline(ir, "x64-la48-asan-new", linked_component=context)
    started = time.monotonic()
    pipeline.run()
    rewrite_seconds = time.monotonic() - started
    if pipeline.reg_manager.analysis_source != "ddisasm":
        raise RuntimeError("component liveness unexpectedly fell back to Python")
    # Section names are changed only after all passes have run. Final linker
    # bounds include these application sections, never the runtime's .text.
    pipeline.text_section.name = ".teapot_component_text"
    pipeline.guard_section.name = ".teapot_component_guards." + component_id
    guard_count = sum(interval.size for interval in pipeline.guard_section.byte_intervals) // 4
    for label in ("__guard_start" + SYMBOL_SUFFIX, "__guard_end" + SYMBOL_SUFFIX):
        matches = list(module.symbols_named(label))
        assert len(matches) == 1
        matches[0].name = label + "_" + component_id
    if item["role"] == "selected":
        for section in module.sections:
            if section.name in (".init_array", ".fini_array"):
                section.name += ".{:05d}".format(priority)
        module.aux_data.pop("elfDynamicInit", None)
        module.aux_data.pop("elfDynamicFini", None)
    instrumented = directory / "instrumented.gtirb"
    ir.save_protobuf(instrumented)
    printer = [args.pprinter, "--ir", instrumented, "--asm", directory / "raw.S",
               "--policy", "complete", "--shared", "no"]
    if item["role"] == "selected":
        printer += ["--skip-section", ".init", ".fini"]
    run(directory, "print", printer)
    fixed = run(directory, "section-flags", ["sed", "-f", args.teapot / "scripts/fix_asm.sed",
                                            directory / "raw.S"])
    shutil.copyfile(fixed / "stdout", directory / "fixed.S")
    run(directory, "assemble", [args.cc, "-c", directory / "fixed.S", "-o", directory / "component.o"])
    validate_object(directory / "component.o", component_id, own_exports, len(item["application_fdes"]))
    result = {"component_id": component_id, "role": item["role"], "input_sha256": item["sha256"],
              "exports": sorted(own_exports), "guard_count": guard_count,
              "rewrite_seconds": rewrite_seconds, "liveness": "ddisasm",
              "liveness_contract": "all tracked registers and flags live; original metadata retained in lift.gtirb",
              "files": {name: sha(directory / name) for name in (
                  "key.json", "lift.gtirb", "instrumented.gtirb", "raw.S", "fixed.S", "component.o")}}
    dump(directory / "component.json", result)
    return result


def cached_component(args, converter, item, context, selected_symbols, priority):
    # Provider names/types and dependency bytes affect the binding decision.
    # The executable's own bytes are deliberately not in a *library* key: a
    # different main with the same binding contract can reuse this exact object.
    key_data = {"format": "teapot-x64-components-v1", "input_sha256": item["sha256"],
                "role": item["role"], "priority": priority, "context": context}
    key_data = json.loads(json.dumps(key_data, sort_keys=True))
    key = hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    entry = args.cache / key
    with (args.cache / (key + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        hit = entry.exists()
        if hit:
            assert json.loads((entry / "key.json").read_text()) == key_data, "cache key mismatch"
            result = json.loads((entry / "component.json").read_text())
            for name, expected in result["files"].items():
                assert sha(entry / name) == expected, "cached artifact hash mismatch: " + name
            validate_object(entry / "component.o", key, exports(item), len(item["application_fdes"]))
        else:
            # Containers often reuse PID 1; preserve failed attempts without
            # preventing an unchanged recipe from being retried.
            temporary = Path(tempfile.mkdtemp(prefix=key + ".building-", dir=args.cache))
            result = build_component(args, converter, item, key_data, key,
                                     selected_symbols, priority, temporary)
            temporary.rename(entry)
    return {**result, "cache_hit": hit, "cache_path": str(entry), "input_path": item["path"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--select", action="append", default=[], type=Path)
    parser.add_argument("--external", action="append", default=[], type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--converter", required=True, type=Path)
    parser.add_argument("--teapot", required=True, type=Path)
    parser.add_argument("--rewriting", required=True, type=Path)
    parser.add_argument("--lra", required=True, type=Path)
    parser.add_argument("--runtime-contract", required=True, type=Path)
    parser.add_argument("--ddisasm", required=True)
    parser.add_argument("--pprinter", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    assert 1 <= args.jobs <= 8
    args.out.mkdir(parents=True, exist_ok=False)
    args.cache.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("selected_converter", args.converter)
    converter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(converter)
    executable = converter.inspect(args.executable, "executable")
    selected = [converter.inspect(path, "selected") for path in args.select]
    external = [converter.inspect(path, "external") for path in args.external]
    order = converter.validate_closure(executable, selected, external)
    items = [executable] + selected
    bindings = [(name, item["soname"] or "executable") for item in items for name in exports(item)]
    selected_symbols = frozenset(name for name, owner in bindings)
    if any(is_blacklisted_function_name(name) for name in selected_symbols):
        raise RuntimeError("selected exports include an uninstrumented/trusted startup entry")
    context = {"converter_sha256": sha(args.converter), "driver_sha256": sha(__file__),
               "assembly_fix_sha256": sha(args.teapot / "scripts/fix_asm.sed"),
               "teapot": tree_hash(args.teapot / "teapot"), "rewriting": tree_hash(args.rewriting),
               "lra": tree_hash(args.lra), "bindings": sorted(bindings),
               "selected_libraries": sorted((item["soname"], item["sha256"]) for item in selected),
               "external_libraries": sorted((item["soname"], item["sha256"]) for item in external),
               "frontend": {"ddisasm": sha(args.ddisasm), "pprinter": sha(args.pprinter)},
               "assembler": sha(shutil.which(args.cc)),
               "runtime_contract": json.loads(args.runtime_contract.read_text()),
               "options": asdict(InstrumentationOptions()), "ROB_LEN": ROB_LEN,
               "liveness_contract": "caller-independent-all-live-v1",
               "dift_layout": "x64-la48-asan-new"}
    dump(args.out / "inputs.json", {"executable": executable, "selected": selected, "external": external})
    components = [cached_component(args, converter, item, context, selected_symbols,
                                  100 + order.index(item["soname"]) if item["role"] == "selected" else 0)
                  for item in items]
    layout = ["SECTIONS {", "  .teapot_component_text : ALIGN(16) {",
              "    __teapot_linked_normal_start = .; KEEP(*(.teapot_component_text))",
              "    __teapot_linked_normal_end = .; }",
              "  .teapot_transient : ALIGN(16) {",
              "    __teapot_linked_transient_start = .; KEEP(*(.teapot_transient))",
              "    __teapot_linked_transient_end = .; }",
              "} INSERT AFTER .text;", "SECTIONS {", "  .teapot_component_guards : ALIGN(4) {",
              "    __guard_start__teapot__ = .;"]
    total_guards = 0
    for component in components:
        key = component["component_id"]
        # Refer to the actual start symbol, after input-section alignment.
        # Using '.' before KEEP would miss linker-inserted padding and alias
        # another component's coverage index. Final-link validation checks it.
        layout += ["    __teapot_component_guard_base_" + key +
                   " = ABSOLUTE((__guard_start__teapot___" + key + " - __guard_start__teapot__) / 4);",
                   "    KEEP(*(.teapot_component_guards." + key + "))"]
        total_guards += component["guard_count"]
    assert total_guards < 0x80000000, "coverage index relocation would overflow"
    layout += ["    __guard_end__teapot__ = .; }", "} INSERT AFTER .data;"]
    (args.out / "layout.ld").write_text("\n".join(layout) + "\n")
    for index, component in enumerate(components):
        shutil.copyfile(Path(component["cache_path"]) / "component.o",
                        args.out / ("component-{:03d}.o".format(index)))
    dump(args.out / "components.json", {"components": components, "total_guards": total_guards,
                                       "status": "objects_ready_final_link_and_behavior_not_yet_verified"})
    print(json.dumps({"components": len(components), "cache_hits": sum(c["cache_hit"] for c in components),
                      "total_guards": total_guards}), flush=True)


if __name__ == "__main__":
    main()
