"""The runtime owns every captured defined-global name, not only emitter imports."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from teapot.configs.runtime import is_generated_name
from teapot.pipeline import InstrumentationOptions, refuse_reserved_names
from teapot.preprocess.runtime_names import RuntimeNameError
from teapot.runtime_exports import (ANCHOR, RuntimeExportError, check_exports,
                                    load_manifest, parse_nm, runtime_owned_names)
from runtime_contract_support import fixture_contract
from test_runtime_names import add_symbol, program, text_bytes


class RuntimeExportTests(unittest.TestCase):
    def test_runtime_and_rewriter_manifests_and_checkers_match(self):
        root = Path(__file__).resolve().parents[1]
        for suffix in ("py", "json"):
            with self.subTest(suffix=suffix):
                self.assertEqual((root / "teapot" / f"runtime_exports.{suffix}").read_bytes(),
                                 (root / "libcheckpoint/tools" / f"runtime_exports.{suffix}").read_bytes(),
                                 "refresh both archive coverage and packaged refusal policy together")

    def test_every_captured_name_is_refused_in_both_preflights(self):
        # Every literal export, not a hand-picked list. All names are checked
        # even when that architecture/mode would not import the symbol.
        names = runtime_owned_names()
        self.assertIn("teapot_fault_x64_mprotect", names)
        self.assertEqual(sum(name.startswith("teapot_fault_") for name in names), 23)
        self.assertTrue({"teapot_fault_risc_policy", "teapot_fault_risc_copied_kernel",
                         "teapot_shadow_registry", "teapot_shadow_registry_count",
                         "teapot_shadow_mapping_ready", "teapot_shadow_register_owned"} <= set(names))
        for isa in ("x64", "aarch64", "riscv64"):
            for component in (False, True):
                ir, module = program(isa)
                before = text_bytes(module)
                for name in names:
                    for kind in ("static", "undefined"):
                        with self.subTest(isa=isa, component=component, name=name, kind=kind):
                            symbol = add_symbol(module, name, kind)
                            with self.assertRaises(RuntimeNameError) as refusal:
                                refuse_reserved_names(ir, InstrumentationOptions(), fixture_contract(isa),
                                                      component=component)
                            self.assertIn(name + ":", str(refusal.exception))
                            self.assertEqual(text_bytes(module), before)
                            module.symbols.discard(symbol)

    def test_new_fault_names_keep_full_symbol_resolution_rules(self):
        for name in runtime_owned_names():
            if not name.startswith("teapot_fault_"):
                continue
            for kind in ("function", "global", "weak", "tls", "value", "bare", "common", "undefined"):
                ir, module = program("x64")
                add_symbol(module, name, kind, version="RUNTIME_PRIVATE_1")
                with self.subTest(name=name, kind=kind), self.assertRaises(RuntimeNameError):
                    refuse_reserved_names(ir, InstrumentationOptions(), fixture_contract("x64"))

    def test_missing_or_unknown_manifest_fails_both_preflights(self):
        for component in (False, True):
            ir, _ = program("x64")
            with patch("teapot.pipeline.runtime_owned_names", side_effect=RuntimeExportError("bad manifest")):
                with self.assertRaisesRegex(RuntimeExportError, "bad manifest"):
                    refuse_reserved_names(ir, InstrumentationOptions(), fixture_contract("x64"),
                                          component=component)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            with self.assertRaises(RuntimeExportError):
                load_manifest(path)
            original = load_manifest()
            for key, value in (("schema", "future-v2"), ("capture_format", "unknown"),
                               ("symbols", []), ("symbols", ["duplicate", "duplicate"]),
                               ("symbols", ["bad name"]), ("symbol_families", ["anything"]),
                               ("architectures", ["x64"]), ("configurations", [])):
                manifest = dict(original, **{key: value})
                path.write_text(json.dumps(manifest))
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeExportError):
                    load_manifest(path)

    def test_nm_parser_rejects_unsupported_or_incomplete_capture(self):
        for output in ("", "\n", "name T 0 8\n", "archive.a[o]: name U 0\n",
                       "archive.a[o]: name t 0 8\n", "archive.a[o]: name ? 0 8\n",
                       "archive.a[o]: name T 0 8\nunsupported line\n"):
            with self.subTest(output=output), self.assertRaises(RuntimeExportError):
                parse_nm(output)
        # A symbol without a size has a trailing space in GNU nm's real output.
        self.assertEqual(parse_nm("a.a[b.S.o]: hidden T c \na.a[c.o]: weak W 0 8\n"), {"hidden", "weak"})

    def test_each_fault_export_missing_from_manifest_is_a_failure(self):
        manifest = load_manifest()
        for name in runtime_owned_names():
            if not name.startswith("teapot_fault_"):
                continue
            mutant = copy.deepcopy(manifest)
            mutant["symbols"].remove(name)
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeExportError, name):
                check_exports({name}, mutant)
        with self.assertRaisesRegex(RuntimeExportError, "unreviewed_global"):
            check_exports({"unreviewed_global"}, manifest)

    def test_anchor_family_is_narrow_and_already_reserved(self):
        name = "__libcheckpoint_contract_v2_1234567890abcdef"
        self.assertTrue(ANCHOR.fullmatch(name))
        self.assertTrue(is_generated_name(name))
        check_exports({name}, load_manifest())
        for wrong in (name + "0", name.upper(), "__libcheckpoint_contract_v3_1234567890abcdef"):
            with self.subTest(name=wrong), self.assertRaises(RuntimeExportError):
                check_exports({wrong}, load_manifest())
