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
import sys
import tempfile
import time
from uuid import UUID

# The repository root holds the teapot, experiments and tools packages imported below. Put it
# first on the path, so the script imports its own checkout and runs by its file path from any
# directory.
_ROOT = str(Path(__file__).resolve().parents[2])
sys.path[:] = [_ROOT] + [entry for entry in sys.path if entry != _ROOT]

import gtirb
import gtirb_rewriting
import gtirb_live_register_analysis
import teapot
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile

from teapot.configs.blacklist import is_blacklisted_function_name
from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.datacls.linked_component import LinkedComponent
from teapot.arch import get_arch, module_isa_name
from teapot.pipeline import InstrumentationOptions, TeapotPipeline, refuse_reserved_names
from teapot.runtime_contract import RuntimeContractError, load_runtime_contract
from teapot.utils.serialization import compact_for_pprinter, save_protobuf_ordered
from experiments.reusable_libraries.targets import (
    for_machine, mode_for, mode_metadata, target_for, MODES, TARGET_IDENTIFICATIONS)


def require(condition, *message):
    """A fail-closed check that, unlike assert, survives python -O."""
    if not condition:
        raise ValueError(*message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def component_assembler_argv(module, compiler, assembly, output, isa, tag_storage):
    from teapot.fault_risc_assembly import fault_risc_assembler_flags
    return [compiler, "-c", assembly, "-o", output,
            *(['-mno-relax', '-Wa,-mno-relax'] if isa == 'RISCV64' else []),
            *(['-march=armv8.5-a+memtag'] if tag_storage == 'mte' else []),
            *fault_risc_assembler_flags(module)]


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
                           f'outside declared source {root}; the driver imports teapot from its own '
                           'checkout, and the other packages through PYTHONPATH')
    return tree_hash(origin.parent)


# Python packages that shape the instrumented output, by distribution and import name.
OUTPUT_PACKAGES = (("llvmlite", "llvmlite"), ("mcasm", "mcasm"), ("capstone", "capstone"),
                   ("gtirb-capstone", "gtirb_capstone"), ("gtirb-functions", "gtirb_functions"),
                   ("gtirb-layout", "gtirb_layout"), ("leb128", "leb128"))


def dependency_versions():
    """What the installed Python packages contribute to the output.

    The packages that shape it are hashed file by file: llvmlite and mcasm carry
    LLVM, and capstone its decoder, as shared libraries inside the package. A
    package without distribution metadata, such as a checkout on PYTHONPATH, is
    hashed all the same. Their own dependencies, such as networkx and
    intervaltree under gtirb and gtirb-layout, enter by version, as every
    installed distribution does.
    """
    from importlib import metadata
    import importlib
    import llvmlite.binding as llvm
    packages = {}
    for distribution, name in OUTPUT_PACKAGES:
        try:
            directory = Path(importlib.import_module(name).__file__).resolve().parent
        except ImportError:
            packages[distribution] = None
            continue
        try:
            version = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            version = None
        files = {str(path.relative_to(directory)): sha(path) for path in sorted(directory.rglob("*"))
                 if path.is_file() and "__pycache__" not in path.parts}
        packages[distribution] = {"version": version, "files": hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()).hexdigest()}
    packages["llvm"] = ".".join(map(str, llvm.llvm_version_info))
    packages["installed"] = sorted({(item.metadata["Name"], item.version)
                                    for item in metadata.distributions() if item.metadata["Name"]})
    return packages


def toolchain_identity(converter, cc):
    """The compiler driver and the assembler and preprocessor it actually runs.

    A program the driver does not run as a separate file has no identity: clang
    prints a bare ``cc1`` because its compiler is built in.
    """
    identity = {"driver": converter.native_tool_identity(cc)}
    for program in ("as", "cc1"):
        path = subprocess.run([cc, "-print-prog-name=" + program], stdout=subprocess.PIPE,
                              text=True, check=True).stdout.strip()
        if "/" not in path and shutil.which(path) is None:
            identity[program] = None
        else:
            identity[program] = converter.native_tool_identity(path)
    return identity


def portable_identity(identity):
    """A native tool's identity without its paths, as cache key material.

    The same bytes at another mount (a host build, or a frontend under another
    prefix) then share components; ``tools.json`` keeps the paths.
    """
    if identity is None:
        return None
    return {"sha256": identity["sha256"],
            "libraries": sorted((Path(path).name, digest)
                                for path, digest in identity["libraries"].items())}


def contract_identity(contract):
    # What a component's code and record depend on: the runtime's ABI, by its
    # fingerprint. Archives that differ only in capabilities, provenance or the
    # runtime's own facts get the same objects (each record lists what it needs).
    # The coverage mode is in the fingerprint too, since it decides whether the
    # components push coverage guards (components always enable gadgets); it is
    # spelled out so that keys and manifests show it.
    return {"version": contract.version, "fingerprint": contract.fingerprint, "coverage": contract.coverage,
            "fault_sites_version": contract.abi["fault_sites.version"],
            "fault_training_capable": "fault_training" in contract.capabilities,
            "fault_publishing_capable": "fault_publishing" in contract.capabilities,
            "fault_windows_version": contract.abi["fault_windows.version"]}


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
                    machine='EM_X86_64', cfi_reader=None, target_identification='software'):
    isa, _ = for_machine(machine)
    target = target_for(isa, target_identification)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        require(elf["e_type"] == "ET_REL" and elf["e_machine"] == machine,
                'check failed: elf["e_type"] == "ET_REL" and elf["e_machine"] == machine')
        require(elf.elfclass == 64 and elf.little_endian,
                'check failed: elf.elfclass == 64 and elf.little_endian')
        if isa == 'RISCV64':
            require(elf['e_flags'] & 6 == 4 and not elf['e_flags'] & ~5, 'RV64 LP64D required')
        table = elf.get_section_by_name(".symtab")
        symbols = {s.name: s for s in table.iter_symbols() if s.name}
        for name in expected_exports:
            symbol = symbols[name]
            require(isinstance(symbol["st_shndx"], int), name)
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"]
            require(section.name == target['text_section'], (name, section.name))
            require(section.data()[offset:offset + len(target['marker'])] == target['marker'], (
                "export is missing its full normal-to-transient marker", name))
        for name, flags in ((target['text_section'], 6), (".teapot_transient", 6),
                            (".teapot_component_guards." + component_id, 3)):
            section = elf.get_section_by_name(name)
            require(section is not None and section["sh_flags"] & 7 == flags, (name, section))
        entries = cfi_reader(elf, path) if cfi_reader else elf.get_dwarf_info().EH_CFI_entries()
        fdes = [entry for entry in entries if isinstance(entry, FDE)]
        require(len(fdes) >= expected_fdes, "original unwind ranges were not reconstructed")


def build_component(args, converter, item, key_data, component_id, selected_symbols, priority, directory):
    dump(directory / "key.json", key_data)
    lifted = directory / "lift.gtirb"
    run(directory, "lift", [args.ddisasm, item["path"], "--ir", lifted, "-j", str(args.jobs)])
    ir = gtirb.IR.load_protobuf(lifted)
    require(len(ir.modules) == 1, 'check failed: len(ir.modules) == 1')
    module = ir.modules[0]
    isa, target = for_machine(item['machine'])
    require(module_isa_name(module) == isa, 'check failed: module_isa_name(module) == isa')
    dump(directory / "proven-data-decoder-warnings.json", converter.validate_frontend_diagnostics(
        module, item, (directory / "lift/stderr").read_text()))
    require("liveRegisterSets" in module.aux_data and "liveRegisterNames" in module.aux_data,
            'check failed: "liveRegisterSets" in module.aux_data and "liveRegisterNames" in module.aux_data')
    cfi = module.aux_data.get("cfiDirectives")
    cfi_starts = {offset.element_id.address + offset.displacement
                  for offset, directives in (cfi.data.items() if cfi else ())
                  if any(directive[0] == ".cfi_startproc" for directive in directives)}
    for fde in item["application_fdes"]:
        require(fde["start"] in cfi_starts, ("unrecovered original unwind range", fde))
    # The complete preflight of TeapotPipeline.run, on the untouched input: the runtime names of the selected mode,
    # the coverage hooks' import rule and the generated-name rule (teapot/pipeline.py: refuse_reserved_names). The
    # conversion below renames versioned symbols and imports from selected libraries to __teapot_selected_version_*
    # and localizes others, which would hide a runtime name from the rewrite's own check (which stays as well).
    refuse_reserved_names(ir, args.instrumentation_options, args.contract, component=True)
    if isa == 'ARM64':
        # Bind proved pointer returns directly to the untouched standalone IR.
        # No ordinary link/re-lift, origin records or UUID correspondence needed.
        from tools.sharedlib.aarch64_return_abi import produce
        from teapot.utils.return_abi import POINTER_RETURNS, SCHEMA, function_fingerprint
        evidence = produce(item['path'], lifted)
        require(POINTER_RETURNS not in module.aux_data,
                'check failed: POINTER_RETURNS not in module.aux_data')
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
    pipeline = TeapotPipeline(ir, args.mode_layout, args.instrumentation_options, linked_component=context,
                              runtime_contract=args.contract)
    started = time.monotonic()
    pipeline.run()
    rewrite_seconds = time.monotonic() - started
    if pipeline.reg_manager.analysis_source != "ddisasm":
        raise RuntimeError("component liveness unexpectedly fell back to Python")
    # Section names are changed only after all passes have run. Final linker
    # bounds include these application sections, never the runtime's .text.
    pipeline.text_section.name = target_for(isa, args.target_identification)['text_section']
    pipeline.guard_section.name = ".teapot_component_guards." + component_id
    guard_count = sum(interval.size for interval in pipeline.guard_section.byte_intervals) // 4
    coverage = args.contract.emits_coverage(args.instrumentation_options)
    require(coverage or guard_count == 0, "coverage guards for a runtime without speculative coverage")
    for label in ("__guard_start" + SYMBOL_SUFFIX, "__guard_end" + SYMBOL_SUFFIX):
        matches = list(module.symbols_named(label))
        require(len(matches) == 1, 'check failed: len(matches) == 1')
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
    save_protobuf_ordered(ir, instrumented)
    # --layout: rewritten intervals keep their original addresses while growing, so they can
    # overlap; the pprinter finds function aliases by address and would otherwise print a
    # normal function's .size inside a transient function that shares its address.
    printer = [args.pprinter, "--ir", instrumented, "--asm", directory / "raw.S",
               "--policy", "complete", "--shared", "no", "--layout"]
    if item["role"] == "selected" and not args.preserve_selected_lifecycle:
        printer += ["--skip-section", ".init", ".fini"]
    run(directory, "print", printer)
    # The printer emits Teapot's section flags and global guard bounds itself.
    from teapot.fault_risc_assembly import emit_fault_risc_scopes
    raw_assembly = (directory / "raw.S").read_text()
    scoped_assembly = emit_fault_risc_scopes(module, raw_assembly)
    assembly = directory / "raw.S"
    if scoped_assembly != raw_assembly:
        assembly = directory / "fault-scoped.S"
        assembly.write_text(scoped_assembly)
    run(directory, "assemble", component_assembler_argv(
        module, args.cc, assembly, directory / "component.o", isa, args.mode_tag_storage))
    validate_object(directory / "component.o", component_id, own_exports, len(item["application_fdes"]),
                    item['machine'], converter.eh_cfi_entries, args.target_identification)
    recorded = ["key.json", "lift.gtirb", "instrumented.gtirb", "raw.S", "component.o",
                "proven-data-decoder-warnings.json", "selected-version-bindings.json", "compaction.json"]
    if assembly.name != "raw.S":
        recorded.append(assembly.name)
    if args.preserve_selected_lifecycle:
        recorded.append("lifecycle.json")
    if isa == 'ARM64':
        recorded.append('pointer-return-contracts.json')
    result = {"component_id": component_id, "role": item["role"], "input_sha256": item["sha256"],
              **mode_metadata(isa, args.mode, args.target_identification),
              "exports": sorted(own_exports), "linked_exports": sorted(exports(item, converter, False)),
              "guard_count": guard_count, "coverage": coverage,
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
        require(json.loads((entry / "key.json").read_text()) == key_data, "cache key mismatch")
        result = json.loads((entry / "component.json").read_text())
        # Covered and uncovered objects are never interchangeable.
        require(result.get("coverage") == context["runtime_contract"]["coverage"],
                "cached component has another speculative coverage mode", result.get("coverage"))
        for name, expected in result["files"].items():
            require(sha(entry / name) == expected, "cached artifact hash mismatch: " + name)
        validate_object(entry / "component.o", key, exports(item, converter), len(item["application_fdes"]),
                        item['machine'], converter.eh_cfi_entries,
                        context.get('target_identification', 'software'))
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
    parser.add_argument("--runtime-contract", required=True, type=Path,
                        help="the lib<archive>.contract.json beside the libcheckpoint archive of the final link")
    parser.add_argument("--ddisasm", required=True)
    parser.add_argument("--pprinter", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--mode", choices=tuple(MODES),
                        help="instrumentation mode; defaults to the ISA's historical component mode")
    parser.add_argument('--target-identification', choices=TARGET_IDENTIFICATIONS, default='software',
                        help='BTI requires AArch64 and a matching experimental runtime')
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--resolve-selected-versions", action="store_true")
    parser.add_argument("--preserve-selected-lifecycle", action="store_true")
    parser.add_argument("--preserve-nonlocal-jumps", action="store_true")
    parser.add_argument("--preserve-weak-imports", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8:
        parser.error("--jobs must be 1..8")
    try:
        args.contract = load_runtime_contract(args.runtime_contract)
    except RuntimeContractError as error:
        parser.error(str(error))
    for option in ("ddisasm", "pprinter", "cc"):
        if shutil.which(getattr(args, option)) is None:
            parser.error(f"--{option}: {getattr(args, option)} is not an executable")
    source_hashes = {
        'teapot': imported_package_hash(teapot, args.teapot / 'teapot'),
        'rewriting': imported_package_hash(gtirb_rewriting, args.rewriting),
        'lra': imported_package_hash(gtirb_live_register_analysis, args.lra),
    }
    spec = importlib.util.spec_from_file_location("selected_converter", args.converter)
    converter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(converter)
    # Identify every tool and library that shapes the output, with its shared
    # libraries, before creating --out: an LLVM, assembler or frontend upgrade
    # must not reuse old components, and a failure here leaves nothing behind.
    tools = {"frontend": {"ddisasm": converter.native_tool_identity(args.ddisasm),
                          "pprinter": converter.native_tool_identity(args.pprinter)},
             "assembler": toolchain_identity(converter, args.cc)}
    tool_key = {"frontend": {name: portable_identity(identity)
                             for name, identity in tools["frontend"].items()},
                "assembler": {name: portable_identity(identity)
                              for name, identity in tools["assembler"].items()},
                "python": converter.python_identity(),
                "dependency_versions": dependency_versions()}
    args.out.mkdir(parents=True, exist_ok=False)
    args.cache.mkdir(parents=True, exist_ok=True)
    dump(args.out / "tools.json", tools)
    conversion_options = {name: getattr(args, name) for name in (
        "resolve_selected_versions", "preserve_selected_lifecycle",
        "preserve_nonlocal_jumps", "preserve_weak_imports")}
    executable = converter.inspect(args.executable, "executable", **conversion_options)
    isa, target = for_machine(executable['machine'])
    args.mode, mode = mode_for(isa, args.mode)
    args.mode_layout, args.mode_tag_storage = mode['layout'], mode['tag_storage']
    target_for(isa, args.target_identification)
    args.instrumentation_options = InstrumentationOptions(
        aarch64_tag_storage=mode['tag_storage'], target_identification=args.target_identification)
    # Once, before any cache lookup: a cached component skips the pipeline and
    # with it the rewrite-time check against this runtime.
    from gtirb_rewriting.abi import _ABIS
    probe = get_arch(gtirb.Module(name="contract-check", isa=getattr(gtirb.Module.ISA, isa)))
    try:
        args.contract.check(probe, probe.register_abi(_ABIS), args.instrumentation_options, args.mode_layout)
    except RuntimeContractError as error:
        parser.error(str(error))
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
               **source_hashes, "bindings": sorted(bindings),
               "selected_libraries": sorted((item["soname"], item["sha256"]) for item in selected),
               "external_libraries": sorted((item["soname"], item["sha256"]) for item in external),
               **tool_key,
               "runtime_contract": contract_identity(args.contract),
               "options": asdict(args.instrumentation_options), "ROB_LEN": ROB_LEN,
               "mode": args.mode,
               "target_identification": args.target_identification,
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
    if args.target_identification == 'aarch64-bti-pac':
        link_support.append(build_bti_startup(args).name)
    layout = component_layout(components, args.target_identification)
    (args.out / "layout.ld").write_text(layout)
    total_guards = sum(component['guard_count'] for component in components)
    for index, component in enumerate(components):
        shutil.copyfile(Path(component["cache_path"]) / "component.o",
                        args.out / ("component-{:03d}.o".format(index)))
    dump(args.out / "components.json", {"components": components, "total_guards": total_guards,
                                       **mode_metadata(isa, args.mode, args.target_identification),
                                       "runtime_contract": contract_identity(args.contract),
                                       "link_support": link_support,
                                       "status": "objects_ready_final_link_and_behavior_not_yet_verified"})
    print(json.dumps({"components": len(components), "cache_hits": sum(c["cache_hit"] for c in components),
                      "total_guards": total_guards}), flush=True)


def build_bti_startup(args):
    # Preinit runs before any selected-library constructors. This entry prepares
    # the signal/BTI machinery (and, in PAC mode, PAC activation) without
    # enabling speculation or tainting argv; main retains the existing
    # libcheckpoint_enable_aarch64_bti[_pac] call.
    prepare = ('libcheckpoint_prepare_aarch64_bti_pac_components'
               if args.target_identification == 'aarch64-bti-pac'
               else 'libcheckpoint_prepare_aarch64_bti_components')
    source = args.out / 'bti-startup.c'
    source.write_text(f'extern void {prepare}(void);\n'
                      '__attribute__((used, section(".preinit_array")))\n'
                      'void (*const __teapot_bti_component_preinit)(void) =\n'
                      f'    {prepare};\n')
    obj = args.out / 'bti-startup.o'
    run(args.out, 'compile-bti-startup', [args.cc, '-c', '-fno-pie', '-fno-pic', source, '-o', obj])
    return obj


def component_layout(components, target_identification='software'):
    if target_identification not in TARGET_IDENTIFICATIONS:
        raise ValueError('unsupported target identification: ' + target_identification)
    if target_identification == 'aarch64-bti-pac':
        layout = ["SECTIONS {", "  .teapot_bti_normal ALIGN(65536) : {",
                  "    __teapot_bti_guard_start = .;",
                  "    __teapot_linked_normal_start = .; __teapot_bti_text_start = .;",
                  "    KEEP(*(.teapot_bti_normal))",
                  "    __teapot_linked_normal_end = .; __teapot_bti_text_end = .;",
                  "    . = ALIGN(65536);",
                  "    __teapot_linked_transient_start = .; __teapot_bti_transient_start = .;",
                  "    KEEP(*(.teapot_transient))",
                  "    __teapot_linked_transient_end = .; __teapot_bti_transient_end = .;",
                  "    . = ALIGN(16); KEEP(*(.teapot_bti_probe))",
                  "    . = ALIGN(65536); __teapot_bti_guard_end = .; }"]
    else:
        layout = ["SECTIONS {", "  .teapot_component_text : ALIGN(16) {",
              "    __teapot_linked_normal_start = .; KEEP(*(.teapot_component_text))",
              "    __teapot_linked_normal_end = .; }",
              "  .teapot_transient : ALIGN(16) {",
              "    __teapot_linked_transient_start = .; KEEP(*(.teapot_transient))",
              "    __teapot_linked_transient_end = .; }"]
    layout += ["} INSERT AFTER .text;", "SECTIONS {", "  .teapot_component_guards : ALIGN(4) {",
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
    require(total_guards < 0x80000000, "coverage index relocation would overflow")
    # Keep every component's contract record under --gc-sections too: only the
    # runtime's __start_/__stop_ walk refers to them.
    layout += ["    __guard_end__teapot__ = .; }",
               "  teapot_contract : ALIGN(8) { KEEP(*(teapot_contract)) }", "} INSERT AFTER .data;"]
    return "\n".join(layout) + "\n"


if __name__ == "__main__":
    main()
