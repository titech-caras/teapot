"""A program that uses the names of the Teapot runtime is refused before anything is rewritten."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from contextlib import redirect_stdout
import importlib.util
import io
from types import SimpleNamespace

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import Assembler

from teapot.arch import AArch64Architecture
from teapot.configs.blacklist import wrapper_destinations
from teapot.configs.runtime import COVERAGE_HOOK_SYMBOLS, is_generated_name
from teapot.datacls.linked_component import LinkedComponent
from teapot.liveness import LiveRegisterManager
from teapot.passes.preprocessing import import_symbols_pass
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.preprocess.runtime_names import RuntimeNameError, WEAK_ANNOTATION_FUNCTIONS, refuse_runtime_names
from tools.sharedlib import convert as converter
from test_live_register_preservation import make_module
from test_rewrite_reproducibility import VARIANTS
from runtime_contract_support import fixture_contract, fixture_contract_path

ARCHITECTURES = {"x64": 0, "aarch64": 1, "riscv64": 2}  # index into VARIANTS
INFO_TYPE = "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"
VERSIONS_TYPE = ("tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,mapping<string,mapping<uint16_t,string>>,"
                 "mapping<UUID,tuple<uint16_t,bool>>>")


def program(isa, name=None, kind="static"):
    """A small function of the ISA, rewritable, and optionally a symbol called name (add_symbol)."""
    arch_type, module_isa, assembly, _, _ = VARIANTS[ARCHITECTURES[isa]]
    arch = arch_type()
    ir, module, block, abi, registers = make_module(arch, module_isa, b"")
    assembler = Assembler(module)
    assembler.assemble(assembly)
    code = assembler.finalize().text_section.data
    block.byte_interval.contents = code
    block.byte_interval.size = block.size = len(code)
    manager = LiveRegisterManager(module, abi)
    for inst in manager.decoder.get_instructions(block):
        module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, inst.address - block.address)] = 0
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData({}, INFO_TYPE)
    if name is not None:
        add_symbol(module, name, kind)
    return ir, module


def section(module, name, address, size, flags=()):
    found = next((section for section in module.sections if section.name == name), None)
    if found is None:
        found = gtirb.Section(name=name, module=module, flags={
            gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, *flags})
        gtirb.ByteInterval(address=address, size=size, section=found)
    return next(iter(found.byte_intervals))


def add_symbol(module, name, kind="static", version=None):
    """Add a symbol called name to the module, of one kind:

    static: a LOCAL OBJECT in .bss; function: a LOCAL FUNC in .text; global: a GLOBAL FUNC in .text; weak: a WEAK
    OBJECT in .data; weak_function: a WEAK DEFAULT FUNC in .text; tls: a GLOBAL TLS in .tbss;
    value: an absolute LOCAL NOTYPE; bare: a LOCAL OBJECT in .bss
    without an elfSymbolInfo entry; common: a COMMON definition, which DDisasm gives a proxy block; undefined: an
    import. version: the version (needed or defined) it carries.
    """
    text = next(iter(next(s for s in module.sections if s.name == ".text").byte_intervals))
    payload, value, entry = None, None, None
    if kind in ("static", "bare"):
        payload, entry = gtirb.DataBlock(size=8, byte_interval=section(module, ".bss", 0x404040, 8)), \
            (8, "OBJECT", "LOCAL", "DEFAULT", 0)
    elif kind in ("function", "global", "weak_function"):
        binding = {"function": "LOCAL", "global": "GLOBAL", "weak_function": "WEAK"}[kind]
        payload, entry = gtirb.CodeBlock(size=0, byte_interval=text), \
            (0, "FUNC", binding, "DEFAULT", 1 if kind == "weak_function" else 0)
    elif kind == "weak":
        payload, entry = gtirb.DataBlock(size=8, byte_interval=section(module, ".data", 0x405000, 8)), \
            (8, "OBJECT", "WEAK", "DEFAULT", 0)
    elif kind == "tls":
        interval = section(module, ".tbss", 0x406000, 8, (gtirb.Section.Flag.ThreadLocal,))
        payload, entry = gtirb.DataBlock(size=8, byte_interval=interval), (8, "TLS", "GLOBAL", "DEFAULT", 0)
    elif kind == "value":
        value, entry = 0x1234, (0, "NOTYPE", "LOCAL", "DEFAULT", 0)
    elif kind == "common":
        payload, entry = gtirb.ProxyBlock(module=module), (8, "OBJECT", "GLOBAL", "DEFAULT", 0xfff2)
    elif kind == "undefined":
        payload, entry = gtirb.ProxyBlock(module=module), (0, "FUNC", "GLOBAL", "DEFAULT", 0)
    else:
        raise ValueError(kind)
    symbol = gtirb.Symbol(name, payload=value if kind == "value" else payload, module=module)
    if kind != "bare":
        module.aux_data["elfSymbolInfo"].data[symbol] = entry
    if version is not None:
        if "elfSymbolVersions" not in module.aux_data:
            module.aux_data["elfSymbolVersions"] = gtirb.AuxData(({}, {}, {}), VERSIONS_TYPE)
        definitions, needed, entries = module.aux_data["elfSymbolVersions"].data
        number = 2 + len(entries)
        if kind == "undefined":
            needed.setdefault("libprovider.so", {})[number] = version
        else:
            definitions[number] = ([version], 0)
        entries[symbol] = (number, False)
    return symbol


def text_bytes(module):
    return bytes(next(iter(next(s for s in module.sections if s.name == ".text").byte_intervals)).contents)


def rewrite(ir, isa, **options):
    target = options.get("target_identification", "software")
    contract = fixture_contract(isa, nested=options.get("enable_nested_speculation", False),
                                target_identification=target)
    return TeapotPipeline(ir, options=InstrumentationOptions(**options), runtime_contract=contract)


def component(exported="provider"):
    """An AArch64 BTI-PAC component rewrite (as tests/test_aarch64_bti_backend.py runs one)."""
    arch = AArch64Architecture()
    ir, module, block, _, registers = make_module(arch, gtirb.Module.ISA.ARM64, bytes.fromhex("00008052c0035fd6"))
    next(module.symbols_named("test_function")).name = exported
    module.aux_data["liveRegisterSets"].data = {
        gtirb.Offset(block, inst.address - block.address): (1 << len(registers)) - 1
        for inst in GtirbInstructionDecoder(module.isa).get_instructions(block)}
    ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module), gtirb.Edge.Label(gtirb.Edge.Type.Return)))
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData({}, INFO_TYPE)
    context = LinkedComponent("a" * 64, frozenset({exported}), frozenset({exported}))
    pipeline = TeapotPipeline(ir, "aarch64-vma42", InstrumentationOptions(target_identification="aarch64-bti-pac"),
                              linked_component=context,
                              runtime_contract=fixture_contract("aarch64", target_identification="aarch64-bti-pac"))
    return ir, module, pipeline


# Names of each kind Teapot generates (teapot/configs/runtime.py: GENERATED_NAME_*).
GENERATED_EXAMPLES = (
    "counter__teapot__", "__guard_start__teapot__", ".__transient_start__teapot__",
    ".L__teapot_symbol_00000000_0000_0000_0000_000000000007__teapot__", ".L__teapot_contract_record",
    ".L__teapot_source_0", "__teapot_bti_text_start", "__teapot_linked_normal_start",
    "__teapot_component_guard_base_" + "a" * 64, "__libcheckpoint_contract_v1_0123456789abcdef",
    "open__dift_wrapper__", "raise__teapot_wrapper__", "teapot_aarch64_bti_pac_rewrite_marker",
)
# Names an input may have: functions Teapot leaves uninstrumented (teapot/configs/blacklist.py), the component
# converter's own names, which it guards itself (tools/sharedlib/convert.py), and others near the reserved ones.
ORDINARY_EXAMPLES = (
    "teapot_setup", "__teapot_specvariant_setup", "__teapot_selected_version_00", "__teapot_lifecycle_00",
    "__teapot_recovered_data_1000", "my__teapot_value", "teapot", "libcheckpoint_contract", "dift_wrapper",
)
# Labels of one patch, which gtirb-rewriting resolves inside that patch before the module and names with the
# patch's number or a UUID: those of LLVM-compiled DIFT bodies and its own RISC-V pc-relative anchors.
PATCH_LOCAL = re.compile(r"^\.L(tmp|func_end|BB|gtirb_riscv_|_gtirb_pcrel_)")


class RuntimeNameTests(unittest.TestCase):
    def test_only_the_four_public_weak_annotation_functions_are_accepted(self):
        self.assertEqual(WEAK_ANNOTATION_FUNCTIONS, {
            "dift_set_mem_tags", "dift_copy_mem_tags", "dift_move_mem_tags", "dift_taint_args"})
        for isa in ARCHITECTURES:
            for name in sorted(WEAK_ANNOTATION_FUNCTIONS):
                with self.subTest(isa=isa, name=name):
                    ir, module = program(isa, name, "weak_function")
                    with redirect_stdout(io.StringIO()):
                        rewrite(ir, isa).run()
                    symbol, = module.symbols_named(name)
                    self.assertEqual(module.aux_data["elfSymbolInfo"].data[symbol][1:4],
                                     ("FUNC", "WEAK", "DEFAULT"))

    def test_nonweak_annotation_definitions_and_other_weak_runtime_names_are_refused(self):
        for isa in ARCHITECTURES:
            for name in sorted(WEAK_ANNOTATION_FUNCTIONS):
                for kind in ("global", "function"):
                    with self.subTest(isa=isa, name=name, kind=kind):
                        ir, _ = program(isa, name, kind)
                        with self.assertRaisesRegex(RuntimeNameError, name):
                            rewrite(ir, isa).run()
            for name in ("scratchpad", "teapot_fault_low_bound"):
                with self.subTest(isa=isa, name=name):
                    ir, _ = program(isa, name, "weak_function")
                    with self.assertRaisesRegex(RuntimeNameError, name):
                        rewrite(ir, isa).run()

    def test_weak_annotation_near_misses_remain_ordinary_names(self):
        for name in ("dift_set_mem_tags_extra", "my_dift_taint_args", "dift_move_mem_tag"):
            with self.subTest(name=name):
                ir, _ = program("x64", name, "weak_function")
                with redirect_stdout(io.StringIO()):
                    rewrite(ir, "x64").run()

    def test_annotation_exception_requires_an_overridable_function_definition(self):
        for name in sorted(WEAK_ANNOTATION_FUNCTIONS):
            for case in ("weak object", "undefined", "HIDDEN", "PROTECTED", "version", "forwarded", "no entry"):
                with self.subTest(name=name, case=case):
                    ir, module = program("x64")
                    kind = "weak" if case == "weak object" else "undefined" if case == "undefined" else "weak_function"
                    symbol = add_symbol(module, name, kind, version="ANNOTATION_1" if case == "version" else None)
                    if case in ("HIDDEN", "PROTECTED"):
                        row = module.aux_data["elfSymbolInfo"].data[symbol]
                        module.aux_data["elfSymbolInfo"].data[symbol] = (*row[:3], case, row[4])
                    elif case == "forwarded":
                        other = add_symbol(module, "ordinary_function", "global")
                        module.aux_data["symbolForwarding"] = gtirb.AuxData({symbol: other}, "mapping<UUID,UUID>")
                    elif case == "no entry":
                        del module.aux_data["elfSymbolInfo"].data[symbol]
                    with self.assertRaisesRegex(RuntimeNameError, name):
                        rewrite(ir, "x64").run()
            ir, module = program("x64", name, "weak_function")
            add_symbol(module, name, "global")
            with self.assertRaisesRegex(RuntimeNameError, name):
                rewrite(ir, "x64").run()

    def test_a_static_scratchpad_is_refused_before_rewriting(self):
        for isa in ARCHITECTURES:
            with self.subTest(isa=isa):
                ir, module = program(isa, "scratchpad")
                sections = [section.name for section in module.sections]
                symbols = len(list(module.symbols))
                text = text_bytes(module)
                with self.assertRaisesRegex(RuntimeNameError,
                                            r"scratchpad: a LOCAL OBJECT symbol in \.bss at 0x404040"):
                    rewrite(ir, isa).run()
                # Nothing was added or rewritten.
                self.assertEqual([section.name for section in module.sections], sections)
                self.assertEqual(len(list(module.symbols)), symbols)
                self.assertEqual(text_bytes(module), text)

    def test_an_unrelated_name_and_an_ordinary_import_are_accepted(self):
        for isa in ARCHITECTURES:
            with self.subTest(isa=isa):
                ir, module = program(isa, "scratchpad_size")
                add_symbol(module, "memcpy", "undefined", version="GLIBC_2.14")
                rewrite(ir, isa).run()
                self.assertTrue(any(section.name == ".teapot_transient" for section in module.sections))

    def test_every_kind_of_symbol_is_refused(self):
        expected = {
            "static": r"a LOCAL OBJECT symbol in \.bss at 0x404040",
            "function": r"a LOCAL FUNC symbol in \.text at 0x1000",
            "global": r"a GLOBAL FUNC symbol in \.text at 0x1000",
            "weak": r"a WEAK OBJECT symbol in \.data at 0x405000",
            "tls": r"a GLOBAL TLS symbol in \.tbss at 0x406000",
            "value": r"an absolute LOCAL NOTYPE symbol with value 0x1234",
            "bare": r"a symbol in \.bss at 0x404040",
            "common": r"a COMMON definition, a GLOBAL OBJECT symbol of size 8",
        }
        for kind, description in expected.items():
            with self.subTest(kind=kind):
                ir, _ = program("x64", "checkpoint_cnt", kind)
                with self.assertRaisesRegex(RuntimeNameError, "checkpoint_cnt: " + description):
                    rewrite(ir, "x64").run()
        # A versioned definition is the same name.
        ir, module = program("x64")
        add_symbol(module, "checkpoint_cnt", "global", version="V1")
        with self.assertRaisesRegex(RuntimeNameError, "checkpoint_cnt: a GLOBAL FUNC symbol of version V1"):
            rewrite(ir, "x64").run()

    def test_every_imported_name_is_refused(self):
        # The refusal reads the list ImportSymbolsPass imports, so a new import is covered too.
        for isa in ARCHITECTURES:
            ir, _ = program(isa)
            pipeline = rewrite(ir, isa)
            imported = []
            original = import_symbols_pass.ImportSymbolsPass.__init__

            def capture(self, names):
                imported.extend(names)
                original(self, names)

            with patch.object(import_symbols_pass.ImportSymbolsPass, "__init__", capture):
                pipeline.run()
            self.assertEqual(imported, pipeline.runtime_imports())
            self.assertIn(fixture_contract(isa).anchor, imported)
            self.assertEqual(pipeline.runtime_names()[:len(imported)], imported)
            for name in imported:
                with self.subTest(isa=isa, name=name):
                    ir, _ = program(isa, name, "function")
                    with self.assertRaisesRegex(RuntimeNameError, re.escape(f"{name}: a LOCAL FUNC symbol in .text")):
                        rewrite(ir, isa).run()

    def test_a_mode_refuses_its_own_runtime_names(self):
        name = "libcheckpoint_enable_aarch64_bti_pac"
        ir, _ = program("aarch64", name, "function")
        with self.assertRaisesRegex(RuntimeNameError, name):
            rewrite(ir, "aarch64", target_identification="aarch64-bti-pac").run()

    def test_the_runtime_wrappers_are_refused(self):
        # DiftExtCallPass renames calls of signal to the runtime's signal__teapot_wrapper__, and with DIFT those
        # of memcpy to memcpy__dift_wrapper__ (wrapper_destinations): the program then refers to them.
        self.assertEqual(wrapper_destinations(False)["signal"], "signal__teapot_wrapper__")
        self.assertEqual(wrapper_destinations(True)["memcpy"], "memcpy__dift_wrapper__")
        for enable_dift in (True, False):
            for name in ("signal__teapot_wrapper__", "memcpy__dift_wrapper__"):
                with self.subTest(enable_dift=enable_dift, name=name):
                    ir, module = program("x64", name, "global")
                    pipeline = rewrite(ir, "x64", enable_dift=enable_dift)
                    # Without DIFT nothing calls the DIFT wrappers, but their names stay reserved.
                    runtime = enable_dift or name.startswith("signal")
                    kind = "names of the Teapot runtime" if runtime else "names reserved for the symbols Teapot generates"
                    with self.assertRaisesRegex(RuntimeNameError,
                                                kind + r"(.|\n)*" + re.escape(f"{name}: a GLOBAL FUNC symbol")):
                        pipeline.run()
                    self.assertEqual(name in pipeline.runtime_names(), runtime)

    def test_undefined_references(self):
        for isa in ARCHITECTURES:
            # Importing a runtime name: after the final link it would be the runtime's object.
            with self.subTest(isa=isa, name="scratchpad"):
                ir, _ = program(isa, "scratchpad", "undefined")
                with self.assertRaisesRegex(RuntimeNameError, "scratchpad: an undefined reference"):
                    rewrite(ir, isa).run()
            # A program compiled with -fsanitize-coverage calls the fuzzer's hooks, as the coverage runtime does.
            for name in COVERAGE_HOOK_SYMBOLS:
                with self.subTest(isa=isa, name=name):
                    ir, module = program(isa, name, "undefined")
                    add_symbol(module, name, "undefined")  # another, equivalent unversioned import
                    rewrite(ir, isa).run()
                    self.assertEqual(len(list(module.symbols_named(name))), 2)
                    # A versioned one would resolve differently from Teapot's reference.
                    ir, module = program(isa, name, "undefined")
                    add_symbol(module, name, "undefined", version="FUZZER_1")
                    with self.assertRaisesRegex(RuntimeNameError,
                                                f"{name}: an undefined reference of version FUZZER_1"):
                        rewrite(ir, isa).run()
                    # Defining them, with a fuzzer runtime of its own, is refused.
                    ir, _ = program(isa, name, "function")
                    with self.assertRaisesRegex(RuntimeNameError, f"{name}: a LOCAL FUNC symbol"):
                        rewrite(ir, isa).run()

    def test_only_plain_imports_of_the_coverage_hooks_are_accepted(self):
        # Teapot's code calls a hook through the program's own import, which gtirb-rewriting reuses: it must be
        # like Teapot's import, a GLOBAL DEFAULT function, undefined, without version or forwarding.
        name = COVERAGE_HOOK_SYMBOLS[0]
        plain = (0, "FUNC", "GLOBAL", "DEFAULT", 0)
        refused = {
            "COMMON": ((8, "OBJECT", "GLOBAL", "DEFAULT", 0xfff2), False, "a COMMON definition, a GLOBAL OBJECT "
                                                                           "symbol of size 8"),
            "forwarded": (plain, True, "which is not a plain import like Teapot's own: it forwards to puts"),
            "LOCAL": ((0, "FUNC", "LOCAL", "DEFAULT", 0), False, "plain import like Teapot's own: it is LOCAL"),
            "WEAK": ((0, "FUNC", "WEAK", "DEFAULT", 0), False, "plain import like Teapot's own: it is WEAK"),
            "HIDDEN": ((0, "FUNC", "GLOBAL", "HIDDEN", 0), False, "plain import like Teapot's own: it is HIDDEN"),
            "TLS": ((0, "TLS", "GLOBAL", "DEFAULT", 0), False, "plain import like Teapot's own: it is a TLS symbol"),
            "no entry": (None, False, "plain import like Teapot's own: it has no ELF symbol entry"),
        }
        for case, (entry, forwarded, description) in refused.items():
            with self.subTest(case=case):
                ir, module = program("x64")
                hook = gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
                if entry is not None:
                    module.aux_data["elfSymbolInfo"].data[hook] = entry
                if forwarded:
                    puts = add_symbol(module, "puts", "undefined")
                    module.aux_data["symbolForwarding"] = gtirb.AuxData({hook: puts}, "mapping<UUID,UUID>")
                with self.assertRaisesRegex(RuntimeNameError, re.escape(f"{name}: ") + ".*" + re.escape(description)):
                    rewrite(ir, "x64").run()
        # Several imports of a hook only with the same entry.
        ir, module = program("x64")
        for entry in (plain, (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)):
            symbol = gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
            module.aux_data["elfSymbolInfo"].data[symbol] = entry
        with self.assertRaises(RuntimeNameError) as refusal:
            rewrite(ir, "x64").run()
        self.assertEqual(str(refusal.exception).count("one of 2 imports of the name with different entries"), 2)
        # An undefined NOTYPE reference, as compiled from C, is a plain import.
        ir, module = program("x64")
        symbol = gtirb.Symbol(name, payload=gtirb.ProxyBlock(module=module), module=module)
        module.aux_data["elfSymbolInfo"].data[symbol] = (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)
        rewrite(ir, "x64").run()
        # A plain import that DDisasm's PLT stub forwards to: the hook is the forwarding target, not a source.
        ir, module = program("x64")
        hook = add_symbol(module, name, "undefined")
        stub = add_symbol(module, "FUN_1000", "function")
        module.aux_data["symbolForwarding"] = gtirb.AuxData({stub: hook}, "mapping<UUID,UUID>")
        rewrite(ir, "x64").run()

    def test_a_defined_and_an_undefined_symbol_of_one_name(self):
        for name in ("scratchpad", COVERAGE_HOOK_SYMBOLS[0]):
            for kinds in (("static", "undefined"), ("undefined", "static")):
                with self.subTest(name=name, kinds=kinds):
                    ir, module = program("x64")
                    for kind in kinds:
                        add_symbol(module, name, kind)
                    with self.assertRaises(RuntimeNameError) as refusal:
                        rewrite(ir, "x64").run()
                    message = str(refusal.exception)
                    self.assertIn(f"{name}: a LOCAL OBJECT symbol in .bss at 0x404040", message)
                    # The hook's import alone would be accepted; the runtime name's is not.
                    self.assertEqual(f"{name}: an undefined reference" in message, name == "scratchpad")

    def test_the_names_of_generated_symbols_are_refused(self):
        # Teapot finds and refers to the symbols it generates by name.
        for name in GENERATED_EXAMPLES:
            self.assertTrue(is_generated_name(name), name)
            for kind, description in (("static", "a LOCAL OBJECT symbol in .bss at 0x404040"),
                                      ("undefined", "an undefined reference")):
                with self.subTest(name=name, kind=kind):
                    ir, _ = program("x64", name, kind)
                    with self.assertRaises(RuntimeNameError) as refusal:
                        rewrite(ir, "x64").run()
                    message = str(refusal.exception)
                    self.assertIn("names reserved for the symbols Teapot generates", message)
                    self.assertIn(f"\n  {name}: {description}", message)
        # A runtime name of that rule is listed once, as a runtime name.
        ir, module = program("x64", "open__dift_wrapper__")
        add_symbol(module, "memcpy__dift_wrapper__", "global")
        with self.assertRaises(RuntimeNameError) as refusal:
            rewrite(ir, "x64").run()
        message = str(refusal.exception)
        self.assertEqual(message.count("memcpy__dift_wrapper__"), 1)
        self.assertLess(message.index("memcpy__dift_wrapper__"), message.index("\nand names reserved"))
        self.assertGreater(message.index("open__dift_wrapper__"), message.index("\nand names reserved"))

    def test_names_near_the_reserved_ones_are_accepted(self):
        for name in ORDINARY_EXAMPLES:
            with self.subTest(name=name):
                self.assertFalse(is_generated_name(name))
                ir, module = program("x64", name, "function")
                rewrite(ir, "x64").run()
                self.assertEqual(len(list(module.symbols_named(name))), 1)

    def test_every_name_a_rewrite_generates_is_reserved(self):
        # One rule covers the names of all the symbols Teapot adds, or renames, in every mode: a new kind of name
        # fails here until it is reserved in teapot/configs/runtime.py.
        cases = [(isa, {}) for isa in ARCHITECTURES]
        cases += [("x64", {"enable_nested_speculation": True}), ("aarch64", {"target_identification": "aarch64-bti-pac"}),
                  ("aarch64", {"component": True})]
        for isa, options in cases:
            with self.subTest(isa=isa, **options):
                if options.get("component"):
                    ir, module, pipeline = component()
                else:
                    ir, module = program(isa)
                    pipeline = rewrite(ir, isa, **options)
                before = {symbol.name for symbol in module.symbols}
                with redirect_stdout(io.StringIO()):
                    pipeline.run()
                runtime = set(pipeline.runtime_names())
                added = sorted({symbol.name for symbol in module.symbols} - before)
                self.assertTrue(any(is_generated_name(name) for name in added))
                unreserved = [name for name in added
                              if not (is_generated_name(name) or name in runtime or PATCH_LOCAL.match(name))]
                self.assertEqual(unreserved, [])

    def test_every_module_is_checked(self):
        ir, _ = program("x64")
        other = gtirb.Module(name="other", isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF,
                             ir=ir)
        gtirb.Symbol("dift_reg_tags", payload=0, module=other)
        with self.assertRaisesRegex(RuntimeNameError, r"module 'other' .*\n  dift_reg_tags: an absolute symbol"):
            rewrite(ir, "x64").run()

    def test_the_command_line_names_the_symbol(self):
        ir, _ = program("x64", "checkpoint_cnt")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.gtirb"
            ir.save_protobuf(source)
            root = Path(__file__).resolve().parents[1]
            result = subprocess.run(
                [sys.executable, "-m", "teapot.cmdline", str(source), str(Path(directory) / "out.gtirb"),
                 "--runtime-contract", str(fixture_contract_path("x64"))],
                cwd=root, capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (str(root),
                                                                              os.environ.get("PYTHONPATH"))))})
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("teapot: module", result.stderr)
            self.assertIn("checkpoint_cnt: a LOCAL OBJECT symbol in .bss at 0x404040", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse((Path(directory) / "out.gtirb").exists())


def load_driver():
    path = Path(__file__).resolve().parents[1] / "experiments/reusable_libraries/rewrite_components.py"
    spec = importlib.util.spec_from_file_location("preflight_driver", path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver


DRIVER = load_driver()


def component_lift(role, name, hidden=True):
    """An x64 component lift with a symbol called name of version LIBTEST_1 of libversions.so: for the selected
    library a definition (hidden: the non-default spelling name@LIBTEST_1), for an executable an import that the
    selected library provides."""
    ir, module = program("x64")
    if role == "selected":
        symbol, definitions, needed = add_symbol(module, name, "global"), {2: (["LIBTEST_1"], 0)}, {}
    else:
        symbol, definitions, needed = add_symbol(module, name, "undefined"), {}, {"libversions.so": {2: "LIBTEST_1"}}
    module.aux_data["elfSymbolVersions"] = gtirb.AuxData((definitions, needed, {symbol: (2, hidden)}), VERSIONS_TYPE)
    return ir, module


def component_item(role):
    return {"role": role, "soname": "libversions.so" if role == "selected" else None, "path": "/input",
            "machine": "EM_X86_64", "application_fdes": [], "symbols": [], "resolve_selected_versions": True}


class Rewritten(Exception):
    """The component driver reached the rewrite."""


def build_component(ir, role):
    """The component driver's build_component on an in-memory lift, up to the rewrite: the converted IR that the
    rewrite gets, unless the driver refuses the input first."""
    args = SimpleNamespace(ddisasm="ddisasm", jobs=1, resolve_selected_versions=True,
                           selected_sonames={"libversions.so"}, preserve_selected_lifecycle=False,
                           mode_layout="x64-la48-asan-new", instrumentation_options=InstrumentationOptions(),
                           contract=fixture_contract("x64"))
    rewritten = []

    def rewrite_stub(ir, *_, **__):
        rewritten.append(ir)
        raise Rewritten()

    with tempfile.TemporaryDirectory() as directory, patch.object(DRIVER, "run"), \
            patch.object(DRIVER.gtirb.IR, "load_protobuf", return_value=ir), \
            patch.object(converter, "validate_frontend_diagnostics", return_value=[]), \
            patch.object(DRIVER, "TeapotPipeline", side_effect=rewrite_stub):
        (Path(directory) / "lift").mkdir()
        (Path(directory) / "lift" / "stderr").write_text("")
        try:
            DRIVER.build_component(args, converter, component_item(role), {}, "a" * 64, frozenset(), 100,
                                   Path(directory))
        except Rewritten:
            return rewritten[0]
    raise AssertionError("the driver neither refused the component nor reached its rewrite")


class ComponentPreflightTests(unittest.TestCase):
    """The component driver runs the rewrite's complete preflight on the untouched lift, before its converter
    renames and localizes symbols (experiments/reusable_libraries/rewrite_components.py)."""

    def test_public_weak_annotation_functions_pass_the_untouched_input_preflight(self):
        for name in sorted(WEAK_ANNOTATION_FUNCTIONS):
            with self.subTest(name=name):
                ir, _ = program("x64", name, "weak_function")
                output = build_component(ir, "executable")
                symbol, = output.modules[0].symbols_named(name)
                self.assertEqual(output.modules[0].aux_data["elfSymbolInfo"].data[symbol][1:4],
                                 ("FUNC", "WEAK", "DEFAULT"))

    def test_nonweak_annotations_and_other_weak_runtime_names_fail_before_conversion(self):
        cases = [(name, kind) for name in sorted(WEAK_ANNOTATION_FUNCTIONS) for kind in ("global", "function")]
        cases += [(name, "weak_function") for name in ("scratchpad", "teapot_fault_low_bound")]
        for name, kind in cases:
            with self.subTest(name=name, kind=kind):
                ir, _ = program("x64", name, kind)
                with self.assertRaisesRegex(RuntimeNameError, name):
                    build_component(ir, "executable")

    def test_unrelated_and_near_miss_weak_functions_remain_accepted(self):
        for name in ("ordinary_function", "dift_copy_mem_tags_extra", "my_dift_taint_args"):
            with self.subTest(name=name):
                ir, _ = program("x64", name, "weak_function")
                self.assertIs(build_component(ir, "executable"), ir)

    def test_versioned_runtime_names_are_refused_before_the_converter_renames_them(self):
        for role, description in (("selected", "scratchpad: a GLOBAL FUNC symbol of version LIBTEST_1 in .text"),
                                  ("executable", "scratchpad: an undefined reference of version LIBTEST_1")):
            with self.subTest(role=role):
                # The converter alone gives the versioned scratchpad its linker name __teapot_selected_version_*,
                # which the rewrite's own check permits.
                ir, module = component_lift(role, "scratchpad")
                converter.resolve_selected_symbol_versions(module, component_item(role), {"libversions.so"})
                self.assertEqual(list(module.symbols_named("scratchpad")), [])
                refuse_runtime_names(module, ["scratchpad"], generated=is_generated_name)
                # The driver refuses the input before converting it.
                ir, module = component_lift(role, "scratchpad")
                with self.assertRaisesRegex(RuntimeNameError, re.escape(description)):
                    build_component(ir, role)
                self.assertEqual(len(list(module.symbols_named("scratchpad"))), 1)

    def test_ordinary_version_reconstruction_is_accepted(self):
        for role, hidden in (("selected", True), ("selected", False), ("executable", True)):
            with self.subTest(role=role, hidden=hidden):
                ir, _ = component_lift(role, "api", hidden)
                names = {symbol.name for symbol in build_component(ir, role).modules[0].symbols}
                self.assertTrue(any(name.startswith("__teapot_selected_version_") for name in names))
                # A default definition keeps its public alias.
                self.assertEqual("api" in names, role == "selected" and not hidden)


if __name__ == "__main__":
    unittest.main()
