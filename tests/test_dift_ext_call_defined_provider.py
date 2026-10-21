import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

import gtirb
from gtirb_rewriting.decoder import GtirbInstructionDecoder

from teapot.configs.blacklist import DIFT_WRAPPER_FUNCTIONS, RUNTIME_WRAPPER_FUNCTIONS
from teapot.datacls.linked_component import LinkedComponent
from teapot.passes.preprocessing.dift_ext_call_pass import DiftExtCallPass


class DefinedProviderTests(unittest.TestCase):
    def make(self, defined=True, linked=None, name="inflateEnd", wrap_dift=True):
        ir = gtirb.IR()
        module = gtirb.Module(
            name="libz.so.1", isa=gtirb.Module.ISA.ValidButUnsupported,
            byte_order=gtirb.Module.ByteOrder.Little,
            file_format=gtirb.Module.FileFormat.ELF, ir=ir)
        module.aux_data["archInfo"] = gtirb.AuxData(
            {"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module)
        plt = gtirb.Section(name=".plt", module=module)
        caller = gtirb.CodeBlock(size=4)
        interval = gtirb.ByteInterval(
            address=0x1000, contents=bytes.fromhex("ef000000"),
            blocks=[caller], section=text)
        stub = gtirb.CodeBlock(size=4)
        gtirb.ByteInterval(address=0x2000, contents=bytes.fromhex("67800000"),
                           blocks=[stub], section=plt)
        if defined:
            callee = gtirb.CodeBlock(size=4)
            gtirb.ByteInterval(address=0x3000, contents=bytes.fromhex("67800000"),
                               blocks=[callee], section=text)
        else:
            callee = gtirb.ProxyBlock(module=module)
        exported = gtirb.Symbol(name=name, payload=callee, module=module)
        alias = gtirb.Symbol(name=name + "@plt", payload=stub, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, alias)
        module.aux_data["symbolForwarding"] = gtirb.AuxData(
            {alias: exported}, "mapping<UUID,UUID>")
        versions = {exported: (2, False)}
        module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            ({}, {}, versions),
            "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
            "mapping<string,mapping<uint16_t,string>>,mapping<UUID,tuple<uint16_t,bool>>>")
        ir.cfg.add(gtirb.Edge(caller, stub, gtirb.Edge.Label(type=gtirb.EdgeType.Call)))
        kwargs = {"linked_function_symbols": linked} if linked is not None else {}
        transform = DiftExtCallPass(
            text, GtirbInstructionDecoder(module.isa),
            wrap_dift_calls=wrap_dift, **kwargs)
        transform.begin_module(module, [], None)
        transform.visit_code_block(caller)
        self.assertIn(alias, transform.symbols_to_rename)
        transform.end_module(module, [])
        self.assertIs(interval.symbolic_expressions[0].symbol, alias)
        self.assertIs(module.aux_data["symbolForwarding"].data[alias], exported)
        return module, exported, alias, versions

    def test_defined_inflateEnd_called_through_plt_keeps_export(self):
        module, exported, alias, versions = self.make()
        self.assertEqual(exported.name, "inflateEnd")
        self.assertIsInstance(exported.referent, gtirb.CodeBlock)
        self.assertEqual(versions[exported], (2, False))
        self.assertEqual(alias.name, "inflateEnd@plt")
        self.assertIs(next(module.symbols_named("inflateEnd")), exported)

    def test_selected_instrumented_provider_keeps_import_and_version(self):
        _, imported, alias, versions = self.make(False, {"inflateEnd"})
        self.assertEqual(imported.name, "inflateEnd")
        self.assertIsInstance(imported.referent, gtirb.ProxyBlock)
        self.assertEqual(versions[imported], (2, False))
        self.assertEqual(alias.name, "inflateEnd@plt")

    def test_uninstrumented_external_provider_still_wraps(self):
        for name in sorted(DIFT_WRAPPER_FUNCTIONS | RUNTIME_WRAPPER_FUNCTIONS.keys()):
            for enabled in (False, True):
                with self.subTest(name=name, enabled=enabled):
                    _, imported, _, versions = self.make(
                        False, name=name, wrap_dift=enabled)
                    expected = RUNTIME_WRAPPER_FUNCTIONS.get(
                        name, name + "__dift_wrapper__" if enabled else name)
                    self.assertEqual(imported.name, expected)
                    if expected == name:
                        self.assertEqual(versions[imported], (2, False))
                    else:
                        self.assertNotIn(imported, versions)

    def test_unrelated_selected_name_does_not_disable_wrapper(self):
        _, imported, _, versions = self.make(False, {"inflateReset"})
        self.assertEqual(imported.name, "inflateEnd__dift_wrapper__")
        self.assertNotIn(imported, versions)
        # A selected name exempts only DIFT wrappers; mandatory runtime
        # wrappers must still preserve rollback's signal handling.
        for name, wrapper in RUNTIME_WRAPPER_FUNCTIONS.items():
            with self.subTest(name=name):
                _, imported, _, versions = self.make(False, {name}, name=name)
                self.assertEqual(imported.name, wrapper)
                self.assertNotIn(imported, versions)

    def test_absolute_and_common_definitions_keep_names(self):
        for name in ("inflateEnd", "signal"):
            for kind in ("absolute-zero", "absolute", "common-proxy", "common-none",
                         "section-proxy", "data"):
                with self.subTest(name=name, kind=kind):
                    module = gtirb.Module(name="definition")
                    section = gtirb.Section(name=".text", module=module)
                    payload = {"absolute-zero": 0, "absolute": 123}.get(kind)
                    if kind in ("common-proxy", "section-proxy"):
                        payload = gtirb.ProxyBlock(module=module)
                    elif kind == "data":
                        payload = gtirb.DataBlock(size=1)
                        gtirb.ByteInterval(address=0x3000, contents=b"\0",
                                           blocks=[payload], section=section)
                    symbol = gtirb.Symbol(name=name, payload=payload, module=module)
                    section_index = (0xfff2 if kind.startswith("common") else
                                     0xfff1 if kind.startswith("absolute") else 1)
                    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
                        {symbol: (0, "FUNC", "GLOBAL", "DEFAULT", section_index)},
                        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
                    versions = {symbol: (2, False)}
                    module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
                        ({}, {}, versions),
                        "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
                        "mapping<string,mapping<uint16_t,string>>,mapping<UUID,tuple<uint16_t,bool>>>")
                    transform = DiftExtCallPass(section, None)
                    transform.begin_module(module, [], None)
                    transform.symbols_to_rename.add(symbol)
                    transform.end_module(module, [])
                    self.assertEqual(symbol.name, name)
                    self.assertEqual(versions[symbol], (2, False))

    def test_pipeline_passes_only_its_validated_component_link_set(self):
        path = Path(__file__).resolve().parents[1] / "teapot/pipeline.py"
        cls = next(node for node in ast.parse(path.read_bytes()).body
                   if isinstance(node, ast.ClassDef) and node.name == "TeapotPipeline")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                      and node.name == "_run_dift_ext_call_passes")
        code = compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                       str(path), "exec")

        class Manager:
            def __init__(self):
                self.passes = []

            def add(self, value):
                self.passes.append(value)

        namespace = {"PassManager": Manager, "DiftExtCallPass": DiftExtCallPass}
        exec(code, namespace)
        component = LinkedComponent("0123456789abcdef", frozenset({"inflateEnd"}), frozenset())
        for selected in (None, component):
            for enabled in (False, True):
                with self.subTest(component=selected, enabled=enabled):
                    observed = []
                    context = SimpleNamespace(
                        text_section=None, decoder=None,
                        options=SimpleNamespace(enable_dift=enabled), linked_component=selected,
                        runtime_contract=SimpleNamespace(shadow_mapping_enforcement=False),
                        _run_pass_manager=lambda manager, phase: observed.append((manager, phase)))
                    namespace[method.name](context)
                    self.assertEqual(len(observed), 1)
                    manager, phase = observed[0]
                    self.assertEqual(phase, "dift-ext-calls")
                    self.assertEqual(len(manager.passes), 1)
                    transform = manager.passes[0]
                    self.assertEqual(transform.wrap_dift_calls, enabled)
                    expected = component.linked_function_symbols if selected else frozenset()
                    self.assertEqual(transform.linked_function_symbols, expected)
                    # Exercise the pass created by the real pipeline method.
                    module = gtirb.Module(name="consumer")
                    symbol = gtirb.Symbol(name="inflateEnd", module=module)
                    transform.begin_module(module, [], None)
                    transform.symbols_to_rename.add(symbol)
                    transform.end_module(module, [])
                    self.assertEqual(symbol.name, "inflateEnd" if selected or not enabled
                                     else "inflateEnd__dift_wrapper__")


if __name__ == "__main__":
    unittest.main(verbosity=2)
