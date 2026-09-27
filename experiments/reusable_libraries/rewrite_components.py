#!/usr/bin/env python3
"""Binary-only component rewriting with validated, content-addressed reuse.

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
from uuid import UUID

import gtirb
import gtirb_rewriting
import gtirb_live_register_analysis
import teapot
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

from teapot.configs.blacklist import is_blacklisted_function_name
from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.configs.slots import AArch64ShadowStackSlots, _aarch64_shadow_stack_config_path
from teapot.datacls.linked_component import LinkedComponent
from teapot.datacls.dift_layout import LAYOUTS, _layout_data_path
from teapot.arch import module_isa_name
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.utils.serialization import compact_for_pprinter
from experiments.reusable_libraries.targets import for_machine, mode_for, mode_metadata, MODES


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


def imported_package_hash(package, declared_root):
    """Hash the code actually imported, and reject a contradictory CLI pin.

    Both a checkout root and a site-packages/package directory are accepted.
    Paths are provenance checks, not key material: equal code remains portable.
    """
    origin = Path(package.__file__).resolve()
    root = Path(declared_root).resolve()
    try:
        origin.relative_to(root)
    except ValueError:
        raise RuntimeError(f'{package.__name__} imported from {origin}, '
                           f'outside declared source {root}; correct PYTHONPATH or the source option')
    return tree_hash(origin.parent)


def configuration_identity():
    # Names alone do not identify overrides. Include the actual loaded values
    # as well, so changing an override after import cannot alias a fresh process.
    return {
        'dift_layout_file': sha(_layout_data_path()),
        'aarch64_shadow_stack_file': sha(_aarch64_shadow_stack_config_path()),
        'dift_layouts': {name: asdict(layout) for name, layout in LAYOUTS.items()},
        'aarch64_shadow_stack': {name: value for name, value in vars(AArch64ShadowStackSlots).items()
                                 if name.isupper()},
    }


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


def exports(item, converter, functions_only=True):
    names = set()
    for symbol in item["symbols"]:
        if (symbol["section"] == "SHN_UNDEF" or (functions_only and symbol["type"] != "STT_FUNC")
                or converter.version_node_symbol(item, symbol)
                or symbol["binding"] != "STB_GLOBAL" or symbol["visibility"] != "STV_DEFAULT"):
            continue
        names.add(converter.reconstructed_symbol_name(symbol, item))
        if symbol.get("version_default"):
            names.add(symbol["name"])
    return frozenset(names)


def component_bindings(item, converter, context):
    """Keep only providers which this ELF can name, plus its own entries.

    In particular, unrelated executable exports do not change a library's
    call policy. Versioned imports use the same identities as the converter.
    """
    names = set(exports(item, converter))
    selected_sonames = {name for name, _ in context['selected_libraries']}
    for symbol in item['symbols']:
        if symbol['section'] != 'SHN_UNDEF':
            continue
        library = symbol.get('version_library')
        if (item.get('resolve_selected_versions') and symbol.get('version')
                and library in selected_sonames):
            names.add(converter.selected_version_name(library, symbol['name'], symbol['version']))
        else:
            names.add(converter.reconstructed_symbol_name(symbol, item))
    return sorted((name, owner) for name, owner in context['bindings'] if name in names)


def validate_object(path, component_id, expected_exports, expected_fdes,
                    machine='EM_X86_64', cfi_reader=None):
    isa, target = for_machine(machine)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        assert elf["e_type"] == "ET_REL" and elf["e_machine"] == machine
        assert elf.elfclass == 64 and elf.little_endian
        if isa == 'RISCV64':
            assert elf['e_flags'] & 6 == 4 and not elf['e_flags'] & ~5, 'RV64 LP64D required'
        table = elf.get_section_by_name(".symtab")
        symbols = {s.name: s for s in table.iter_symbols() if s.name}
        for name in expected_exports:
            symbol = symbols[name]
            assert isinstance(symbol["st_shndx"], int), name
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"]
            assert section.name == ".teapot_component_text", (name, section.name)
            assert section.data()[offset:offset + len(target['marker'])] == target['marker'], (
                "export is missing its full normal-to-transient marker", name)
        for name, flags in ((".teapot_component_text", 6), (".teapot_transient", 6),
                            (".teapot_component_guards." + component_id, 3)):
            section = elf.get_section_by_name(name)
            assert section is not None and section["sh_flags"] & 7 == flags, (name, section)
        entries = cfi_reader(elf, path) if cfi_reader else elf.get_dwarf_info().EH_CFI_entries()
        fdes = [entry for entry in entries if isinstance(entry, FDE)]
        assert len(fdes) >= expected_fdes, "original unwind ranges were not reconstructed"


def build_component(args, converter, item, key_data, component_id, selected_symbols, priority, directory):
    dump(directory / "key.json", key_data)
    lifted = directory / "lift.gtirb"
    run(directory, "lift", [args.ddisasm, item["path"], "--ir", lifted, "-j", str(args.jobs)])
    ir = gtirb.IR.load_protobuf(lifted)
    assert len(ir.modules) == 1
    module = ir.modules[0]
    isa, target = for_machine(item['machine'])
    assert module_isa_name(module) == isa
    dump(directory / "proven-data-decoder-warnings.json", converter.validate_frontend_diagnostics(
        module, item, (directory / "lift/stderr").read_text()))
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
    if isa == 'ARM64':
        # Bind proved pointer returns directly to the untouched standalone IR.
        # No ordinary link/re-lift, origin records or UUID correspondence needed.
        from tools.sharedlib.aarch64_return_abi import produce
        from teapot.utils.return_abi import POINTER_RETURNS, SCHEMA, function_fingerprint
        evidence = produce(item['path'], lifted)
        assert POINTER_RETURNS not in module.aux_data
        module.aux_data[POINTER_RETURNS] = gtirb.AuxData({
            UUID(row['function_uuid']): (function_fingerprint(module, UUID(row['function_uuid'])), row['id'])
            for row in evidence['records']}, SCHEMA)
        dump(directory / 'pointer-return-contracts.json', evidence)
    if item["role"] == "selected":
        converter.localize_private_library_definitions(module, item)
    version_bindings = (converter.resolve_selected_symbol_versions(module, item, args.selected_sonames)
                        if args.resolve_selected_versions else [])
    dump(directory / "selected-version-bindings.json", version_bindings)
    if args.preserve_selected_lifecycle:
        dump(directory / "lifecycle.json", converter.preserve_selected_lifecycle(module, item, priority))
    own_exports = exports(item, converter)
    for name in own_exports:
        definitions = [symbol for symbol in module.symbols_named(name)
                       if isinstance(symbol.referent, gtirb.CodeBlock)]
        if len(definitions) != 1 or definitions[0].referent.section.name != ".text":
            raise RuntimeError("selected export is not a uniquely recovered .text entry: " + name)
    context = LinkedComponent(component_id, selected_symbols, own_exports)
    pipeline = TeapotPipeline(ir, args.mode_layout, args.instrumentation_options, linked_component=context)
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
    if item["role"] == "selected" and not args.preserve_selected_lifecycle:
        for section in module.sections:
            if section.name in (".init_array", ".fini_array"):
                section.name += ".{:05d}".format(priority)
        module.aux_data.pop("elfDynamicInit", None)
        module.aux_data.pop("elfDynamicFini", None)
    instrumented = directory / "instrumented.gtirb"
    # Match --compact-output on the whole-program path. Analysis-only CFG and
    # code-width metadata can otherwise push a large component past protobuf's
    # message-size limit before the pretty-printer ever sees it.
    compact_stats = compact_for_pprinter(ir)
    dump(directory / "compaction.json", asdict(compact_stats))
    print("[teapot] compact component output " + json.dumps(asdict(compact_stats)), flush=True)
    ir.save_protobuf(instrumented)
    # --layout: rewritten intervals keep their original addresses while growing, so they can
    # overlap; the pprinter finds function aliases by address and would otherwise print a
    # normal function's .size inside a transient function that shares its address.
    printer = [args.pprinter, "--ir", instrumented, "--asm", directory / "raw.S",
               "--policy", "complete", "--shared", "no", "--layout"]
    if item["role"] == "selected" and not args.preserve_selected_lifecycle:
        printer += ["--skip-section", ".init", ".fini"]
    run(directory, "print", printer)
    fixed = run(directory, "section-flags", ["sed", "-f", args.teapot / "scripts/fix_asm.sed",
                                            directory / "raw.S"])
    shutil.copyfile(fixed / "stdout", directory / "fixed.S")
    run(directory, "assemble", [args.cc, "-c", directory / "fixed.S", "-o", directory / "component.o",
                                *(['-mno-relax', '-Wa,-mno-relax'] if isa == 'RISCV64' else []),
                                *(['-march=armv8.5-a+memtag'] if args.mode_tag_storage == 'mte' else [])])
    validate_object(directory / "component.o", component_id, own_exports, len(item["application_fdes"]),
                    item['machine'], converter.eh_cfi_entries)
    recorded = ["key.json", "lift.gtirb", "instrumented.gtirb", "raw.S", "fixed.S", "component.o",
                "proven-data-decoder-warnings.json", "selected-version-bindings.json", "compaction.json"]
    if args.preserve_selected_lifecycle:
        recorded.append("lifecycle.json")
    if isa == 'ARM64':
        recorded.append('pointer-return-contracts.json')
    result = {"component_id": component_id, "role": item["role"], "input_sha256": item["sha256"],
              **mode_metadata(isa, args.mode),
              "exports": sorted(own_exports), "linked_exports": sorted(exports(item, converter, False)),
              "guard_count": guard_count,
              "rewrite_seconds": rewrite_seconds, "liveness": "ddisasm",
              "liveness_contract": "standalone-ddisasm-abi-v1; missing instruction masks all-live",
              "files": {name: sha(directory / name) for name in recorded}}
    dump(directory / "component.json", result)
    return result


def cached_component(args, converter, item, context, selected_symbols, priority):
    # Provider names/types and dependency bytes affect the binding decision.
    # The executable's own bytes are deliberately not in a *library* key: a
    # different main with the same binding contract can reuse this exact object.
    bindings = component_bindings(item, converter, context)
    context = dict(context, bindings=bindings)
    # Use exactly the contract in the key; never instrument with the larger
    # caller-specific export set and then cache under a narrowed identity.
    selected_symbols = frozenset(name for name, _ in bindings)
    key_data = {"format": "teapot-components-v2", "input_sha256": item["sha256"],
                "role": item["role"], "priority": priority, "context": context}
    key_data = json.loads(json.dumps(key_data, sort_keys=True))
    key = hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    entry = args.cache / key
    with (args.cache / (key + ".lock")).open("a") as lock:
        # Immutable published entries may be verified by many readers at once.
        # Upgrade only for a miss, then recheck: another writer may have won
        # while flock released the shared lock during the upgrade.
        fcntl.flock(lock, fcntl.LOCK_SH)
        if not entry.exists():
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not entry.exists():
                # Preserve failed attempts, including reused container PIDs.
                temporary = Path(tempfile.mkdtemp(prefix=key + ".building-", dir=args.cache))
                result = build_component(args, converter, item, key_data, key,
                                         selected_symbols, priority, temporary)
                temporary.rename(entry)
                return {**result, "cache_hit": False, "cache_path": str(entry), "input_path": item["path"]}
            fcntl.flock(lock, fcntl.LOCK_SH)
        assert json.loads((entry / "key.json").read_text()) == key_data, "cache key mismatch"
        result = json.loads((entry / "component.json").read_text())
        for name, expected in result["files"].items():
            assert sha(entry / name) == expected, "cached artifact hash mismatch: " + name
        validate_object(entry / "component.o", key, exports(item, converter), len(item["application_fdes"]),
                        item['machine'], converter.eh_cfi_entries)
    return {**result, "cache_hit": True, "cache_path": str(entry), "input_path": item["path"]}


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
    parser.add_argument("--mode", choices=tuple(MODES),
                        help="instrumentation mode; defaults to the ISA's historical component mode")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--resolve-selected-versions", action="store_true")
    parser.add_argument("--preserve-selected-lifecycle", action="store_true")
    parser.add_argument("--preserve-nonlocal-jumps", action="store_true")
    parser.add_argument("--preserve-weak-imports", action="store_true")
    args = parser.parse_args()
    assert 1 <= args.jobs <= 8
    source_hashes = {
        'teapot': imported_package_hash(teapot, args.teapot / 'teapot'),
        'rewriting': imported_package_hash(gtirb_rewriting, args.rewriting),
        'lra': imported_package_hash(gtirb_live_register_analysis, args.lra),
    }
    args.out.mkdir(parents=True, exist_ok=False)
    args.cache.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("selected_converter", args.converter)
    converter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(converter)
    conversion_options = {name: getattr(args, name) for name in (
        "resolve_selected_versions", "preserve_selected_lifecycle",
        "preserve_nonlocal_jumps", "preserve_weak_imports")}
    executable = converter.inspect(args.executable, "executable", **conversion_options)
    isa, target = for_machine(executable['machine'])
    args.mode, mode = mode_for(isa, args.mode)
    args.mode_layout, args.mode_tag_storage = mode['layout'], mode['tag_storage']
    args.instrumentation_options = InstrumentationOptions(aarch64_tag_storage=mode['tag_storage'])
    selected = [converter.inspect(path, "selected", **conversion_options) for path in args.select]
    external = [converter.inspect(path, "external") for path in args.external]
    order = converter.validate_closure(executable, selected, external)
    args.selected_sonames = {item["soname"] for item in selected}
    items = [executable] + selected
    bindings = [(name, item["soname"] or "executable") for item in items for name in exports(item, converter)]
    selected_symbols = frozenset(name for name, owner in bindings)
    if any(is_blacklisted_function_name(name) for name in selected_symbols):
        raise RuntimeError("selected exports include an uninstrumented/trusted startup entry")
    context = {"converter_sha256": sha(args.converter), "driver_sha256": sha(__file__),
               "assembly_fix_sha256": sha(args.teapot / "scripts/fix_asm.sed"),
               **source_hashes, "bindings": sorted(bindings),
               "selected_libraries": sorted((item["soname"], item["sha256"]) for item in selected),
               "external_libraries": sorted((item["soname"], item["sha256"]) for item in external),
               "frontend": {"ddisasm": sha(args.ddisasm), "pprinter": sha(args.pprinter)},
               "assembler": sha(shutil.which(args.cc)),
               "runtime_contract": json.loads(args.runtime_contract.read_text()),
               "options": asdict(args.instrumentation_options), "ROB_LEN": ROB_LEN,
               "configuration": configuration_identity(),
               "mode": args.mode,
               "liveness_contract": "standalone-ddisasm-abi-v1",
               "conversion_options": conversion_options,
               "dift_layout": args.mode_layout, 'isa': isa,
               'component_targets_sha256': sha(args.teapot / 'experiments/reusable_libraries/targets.py'),
               'pointer_contract_producer_sha256': sha(args.teapot / 'tools/sharedlib/aarch64_return_abi.py')}
    dump(args.out / "inputs.json", {"executable": executable, "selected": selected, "external": external})
    # Do the expensive reusable library work first. Keep final link order main,
    # then selected libraries, independently of the order of cache population.
    libraries = [cached_component(args, converter, item, context, selected_symbols,
                                  100 + order.index(item["soname"])) for item in selected]
    components = [cached_component(args, converter, executable, context, selected_symbols, 0)] + libraries
    link_support = []
    if args.preserve_selected_lifecycle:
        objects = [Path(component["cache_path"]) / "component.o" for component in components]
        link_support.append(converter.build_lifecycle_dispatcher(args, objects[0], objects[1:], order).name)
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
                                       **mode_metadata(isa, args.mode),
                                       "link_support": link_support,
                                       "status": "objects_ready_final_link_and_behavior_not_yet_verified"})
    print(json.dumps({"components": len(components), "cache_hits": sum(c["cache_hit"] for c in components),
                      "total_guards": total_guards}), flush=True)


if __name__ == "__main__":
    main()
