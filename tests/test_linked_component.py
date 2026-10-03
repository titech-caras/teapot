"""Conservative contracts for the opt-in x64 component prototype."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch.x64.architecture import X64Architecture
from teapot.arch.riscv64.architecture import RISCV64Architecture
from teapot.datacls.linked_component import LinkedComponent
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from runtime_contract_support import fixture_contract


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

    def riscv_target(self, name='provider', offset=0, low_word=0x000080e7,
                     direct=True, split_relocation=False, wrong_anchor=False):
        module = self.module()
        section = gtirb.Section(name='.text', module=module)
        words = (0x00000097).to_bytes(4, 'little') + low_word.to_bytes(4, 'little')
        interval = gtirb.ByteInterval(address=0x1000, contents=words, section=section)
        block = gtirb.CodeBlock(size=8, byte_interval=interval)
        plt = gtirb.Section(name='.plt', module=module)
        target_interval = gtirb.ByteInterval(address=0x2000, contents=bytes(16), section=plt)
        destination = gtirb.CodeBlock(size=16, byte_interval=target_interval)
        gtirb.Symbol(name='.L_pcrel_2000', payload=destination, module=module)
        symbol = gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(
            offset, symbol, {attrs.PCREL, attrs.HI} if split_relocation else {attrs.PLT})
        if split_relocation:
            anchor = gtirb.Symbol(name='.L_pcrel_1000',
                                  payload=destination if wrong_anchor else block, module=module)
            interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, anchor, {attrs.PCREL, attrs.LO})
        edge = gtirb.Edge(block, destination, gtirb.Edge.Label(type=gtirb.EdgeType.Call, direct=direct))
        instructions = [SimpleNamespace(address=0x1000 + n, size=4) for n in (0, 4)]
        visitor = TransientInsertRestorePointsPass(None, section, section, None, RISCV64Architecture(),
                                                  linked_function_symbols={'provider'})
        return visitor._targets_linked_component(block, instructions, edge)

    def test_riscv_call_relocation_on_auipc_names_selected_provider(self):
        self.assertTrue(self.riscv_target())
        self.assertTrue(self.riscv_target(split_relocation=True))

    def test_riscv_pair_requires_matching_registers_and_call_instruction(self):
        self.assertFalse(self.riscv_target(low_word=0x000280e7))  # JALR ra,t0,0
        self.assertFalse(self.riscv_target(low_word=0x0000b083))  # LD ra,0(ra)
        self.assertFalse(self.riscv_target(direct=False))
        self.assertFalse(self.riscv_target(split_relocation=True, wrong_anchor=True))

    def test_riscv_pair_does_not_admit_external_or_interior_targets(self):
        self.assertFalse(self.riscv_target(name='puts'))
        self.assertFalse(self.riscv_target(offset=8))
        self.assertFalse(self.riscv_target(offset=-4, split_relocation=True))

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
                                  linked_component=self.context(), runtime_contract=fixture_contract('x64'))
        class LivenessInitialized(Exception):
            pass
        with patch('teapot.pipeline.LiveRegisterManager',
                   return_value=SimpleNamespace(analysis_source='ddisasm',
                       analyzer=SimpleNamespace(decoder=GtirbInstructionDecoder(module.isa)))), \
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
