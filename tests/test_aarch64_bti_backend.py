"""The opt-in backend omits marker loads only for BTI-checked transfers."""
from contextlib import redirect_stdout
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import AArch64Architecture, X64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass
from test_live_register_preservation import make_module


class AArch64BTIBackendTests(unittest.TestCase):
    def test_marker_replaces_first_word_only_in_opt_in_architecture(self):
        self.assertEqual(AArch64Architecture.MAGIC_WORDS, (0xd280229f, 0xd280a29f))
        self.assertEqual(AArch64BTIArchitecture.MAGIC_WORDS, (0xd50324df, 0xd280a29f))
        self.assertEqual(InstrumentationOptions().target_identification, 'software')

    def test_fast_path_retains_four_bounds_and_removes_marker_loads(self):
        arch = AArch64BTIArchitecture()
        bounds = [gtirb.Symbol(name=n) for n in ('shadow_begin', 'shadow_end', 'normal_begin', 'normal_end')]
        fast = arch.indirect_branch_hardware_check_patch('x0', *bounds)(
            SimpleNamespace(scratch_registers=('x9', 'x10')))
        slow = arch.indirect_branch_check_patch('x0', *bounds)(
            SimpleNamespace(scratch_registers=('x9', 'x10', 'x11')))
        for bound in bounds:
            self.assertIn(bound.name, fast)
        self.assertIn('restore_checkpoint_MALFORMED_INDIRECT_BR', fast)
        self.assertNotIn('ldr w', fast.split('5:')[0])
        self.assertIn('tst x9, #3', fast)
        self.assertIn('ldr w10, [x0, #4]', fast.split('5:')[1])
        self.assertIn('ldr w', slow)

    def test_real_pass_keeps_software_check_for_ret(self):
        for mnemonic, contents, kind, expected in (
                ('ret', 'c0035fd6', gtirb.Edge.Type.Return, 'software'),
                ('br', '00001fd6', gtirb.Edge.Type.Branch, 'hardware'),
                ('blr', '00003fd6', gtirb.Edge.Type.Call, 'hardware')):
            with self.subTest(mnemonic=mnemonic):
                arch = AArch64BTIArchitecture()
                ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64,
                                                     bytes.fromhex(contents))
                ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                                      gtirb.Edge.Label(kind, direct=False)))
                decoder = GtirbInstructionDecoder(module.isa)
                bounds = [gtirb.Symbol(name=str(i)) for i in range(4)]
                visitor = TransientIndirectBranchCheckDestPass(None, block.section,
                                                               decoder, *bounds, arch)
                function = SimpleNamespace(get_name=lambda: 'callee__teapot__')
                with patch.object(visitor, 'insert_at'), \
                     patch.object(AArch64BTIArchitecture, 'indirect_branch_check_patch',
                                  wraps=arch.indirect_branch_check_patch) as software, \
                     patch.object(AArch64BTIArchitecture, 'indirect_branch_hardware_check_patch',
                                  wraps=arch.indirect_branch_hardware_check_patch) as hardware:
                    visitor.visit_code_block(block, function)
                    self.assertEqual(software.call_count, int(expected == 'software'))
                    self.assertEqual(hardware.call_count, int(expected == 'hardware'))

    def test_complete_pipeline_has_bti_entry_and_explicit_layout_contract(self):
        arch = AArch64Architecture()
        ir, module, block, _, registers = make_module(arch, gtirb.Module.ISA.ARM64,
                                                     bytes.fromhex('00008052c0035fd6'))
        symbol = next(module.symbols_named('test_function'))
        symbol.name = 'main'
        mask = (1 << len(registers)) - 1
        module.aux_data['liveRegisterSets'].data = {
            gtirb.Offset(block, inst.address - block.address): mask
            for inst in GtirbInstructionDecoder(module.isa).get_instructions(block)}
        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                              gtirb.Edge.Label(gtirb.Edge.Type.Return)))
        pipeline = TeapotPipeline(ir, 'aarch64-vma42',
                                 InstrumentationOptions(target_identification='aarch64-bti'))
        with redirect_stdout(io.StringIO()):
            pipeline.run()
        self.assertEqual(pipeline.reg_manager.analysis_source, 'ddisasm')
        self.assertEqual(pipeline.text_section.name, '.teapot_bti_normal')
        entry = symbol.referent
        self.assertEqual(entry.byte_interval.contents[entry.offset:entry.offset + 8],
                         bytes.fromhex('df2403d59fa280d2'))
        for suffix in ('text_start', 'text_end', 'transient_start', 'transient_end'):
            alias = next(module.symbols_named('__teapot_bti_' + suffix))
            self.assertEqual(module.aux_data['elfSymbolInfo'].data[alias][2], 'GLOBAL')
        self.assertTrue(any(module.symbols_named('libcheckpoint_enable_aarch64_bti')))

    def test_non_arm_and_disabled_required_checks_are_rejected(self):
        ir, _, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b'\xc3')
        with self.assertRaisesRegex(ValueError, 'requires AArch64'):
            TeapotPipeline(ir, options=InstrumentationOptions(target_identification='aarch64-bti')).run()
        ir, _, _, _, _ = make_module(AArch64Architecture(), gtirb.Module.ISA.ARM64,
                                      bytes.fromhex('c0035fd6'))
        for flag in ('enable_checkpoints', 'enable_indirect_check', 'enable_indirect_transform'):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'requires target'):
                TeapotPipeline(ir, options=InstrumentationOptions(
                    target_identification='aarch64-bti', **{flag: False})).run()
