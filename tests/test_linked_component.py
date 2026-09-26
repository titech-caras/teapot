"""Conservative contracts for the opt-in x64 component prototype."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb

from teapot.arch.x64.architecture import X64Architecture
from teapot.datacls.linked_component import LinkedComponent
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from teapot.pipeline import InstrumentationOptions, TeapotPipeline


class LinkedComponentTests(unittest.TestCase):
    def context(self):
        return LinkedComponent("a" * 64, frozenset({"provider"}), frozenset({"provider"}))

    def module(self):
        module = gtirb.Module(name="component", isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        return module

    def test_identity_and_export_subset_are_validated(self):
        with self.assertRaises(ValueError):
            LinkedComponent("not-a-key", frozenset(), frozenset())
        with self.assertRaises(ValueError):
            LinkedComponent("a" * 64, frozenset(), frozenset({"provider"}))

    def test_bounds_are_external_globals_and_collisions_fail(self):
        module = self.module()
        context = self.context()
        bounds = context.bounds(module)
        self.assertEqual([s.name for s in bounds], ["__teapot_linked_" + part for part in
            ("normal_start", "normal_end", "transient_start", "transient_end")])
        for symbol in bounds:
            self.assertIsInstance(symbol.referent, gtirb.ProxyBlock)
            self.assertEqual(module.aux_data["elfSymbolInfo"].data[symbol][1:4],
                             ("NOTYPE", "GLOBAL", "DEFAULT"))
        with self.assertRaisesRegex(ValueError, "reserved"):
            context.bounds(module)

    def target(self, name="provider", offset=0, forwarded=False, expression=True):
        module = self.module()
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=b"\xe8\0\0\0\0", section=section)
        block = gtirb.CodeBlock(size=5, byte_interval=interval)
        destination = gtirb.ProxyBlock(module=module)
        symbol = gtirb.Symbol(name=name, payload=destination, module=module)
        if expression:
            interval.symbolic_expressions[1] = gtirb.SymAddrConst(offset, symbol)
        if forwarded:
            provider = gtirb.Symbol(name="provider", payload=gtirb.ProxyBlock(module=module), module=module)
            module.aux_data["symbolForwarding"] = gtirb.AuxData({symbol: provider}, "mapping<UUID,UUID>")
        edge = gtirb.Edge(block, destination, gtirb.Edge.Label(type=gtirb.EdgeType.Call, direct=True))
        visitor = TransientInsertRestorePointsPass(None, section, section, None, X64Architecture(),
                                                  linked_function_symbols={"provider"})
        instructions = [SimpleNamespace(address=0x1000, size=5)]
        return visitor._targets_linked_component(block, instructions, edge)

    def test_exact_named_provider_and_forwarded_plt_are_accepted(self):
        self.assertTrue(self.target())
        self.assertTrue(self.target("provider_plt", forwarded=True))

    def test_provider_interior_address_does_not_bypass_external_rollback(self):
        self.assertFalse(self.target(offset=8))
        self.assertFalse(self.target(offset=-4))

    def test_unknown_and_data_symbols_are_not_named_code_providers(self):
        self.assertFalse(self.target("puts"))
        self.assertFalse(self.target("dispatch_pointer"))

    def test_coverage_keeps_default_immediate_and_relocates_only_opt_in_index(self):
        arch = X64Architecture()
        context = SimpleNamespace(scratch_registers=("rax",))
        ordinary = arch.coverage_patch(3)(context)
        linked = arch.coverage_patch(3, index_base_symbol=gtirb.Symbol(name="component_base"))(context)
        self.assertIn("mov dword ptr [rax], 3", ordinary)
        self.assertNotIn("OFFSET", ordinary)
        self.assertIn("mov dword ptr [rax], OFFSET component_base + 3", linked)

    def test_component_profile_cannot_disable_required_instrumentation(self):
        for options in (InstrumentationOptions(enable_memlog=False),
                        InstrumentationOptions(enable_indirect_check=False),
                        InstrumentationOptions(enable_nested_speculation=True)):
            with self.subTest(options=options):
                ir = gtirb.IR(modules=[self.module()])
                pipeline = TeapotPipeline(ir, "x64-la48-asan-new", options, linked_component=self.context())
                with self.assertRaisesRegex(ValueError, "all default instrumentation"):
                    pipeline.run()

    def liveness_module(self):
        module = self.module()
        section = gtirb.Section(name=".text", module=module)
        interval = gtirb.ByteInterval(address=0x1000, contents=b"\x90\xc3", section=section)
        block = gtirb.CodeBlock(size=2, byte_interval=interval)
        names = ["rax", "rdx", "rflags"]
        masks = {gtirb.Offset(block, 0): 0, gtirb.Offset(block, 1): 2}
        module.aux_data["liveRegisterNames"] = gtirb.AuxData(names, "sequence<string>")
        module.aux_data["liveRegisterSets"] = gtirb.AuxData(masks, "mapping<Offset,uint64_t>")
        return module, block, names, masks

    def test_legacy_all_live_helper_remains_explicit(self):
        module, block, names, masks = self.liveness_module()
        self.assertEqual(self.context().make_liveness_caller_independent(module), 2)
        self.assertEqual(set(masks.values()), {7})
        self.assertEqual(module.aux_data["liveRegisterNames"].data, names)

    def test_component_pipeline_preserves_standalone_abi_masks(self):
        module, block, names, masks = self.liveness_module()
        del masks[gtirb.Offset(block, 1)]  # A missing instruction stays missing.
        expected = dict(masks)
        pipeline = TeapotPipeline(gtirb.IR(modules=[module]), "x64-la48-asan-new",
                                  linked_component=self.context())
        class LivenessInitialized(Exception):
            pass
        with patch('teapot.pipeline.LiveRegisterManager',
                   return_value=SimpleNamespace(analysis_source='ddisasm')), \
                patch.object(LinkedComponent, 'make_liveness_caller_independent') as force_live, \
                patch.object(pipeline, '_run_normalize_passes', side_effect=LivenessInitialized):
            with self.assertRaises(LivenessInitialized):
                pipeline.run()
        force_live.assert_not_called()
        self.assertEqual(masks, expected)
        self.assertNotIn(gtirb.Offset(block, 1), masks)
        self.assertEqual(module.aux_data['liveRegisterNames'].data, names)


if __name__ == "__main__":
    unittest.main()
