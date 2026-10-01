"""The opt-in backend omits marker loads only for BTI-checked transfers."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import AArch64Architecture, X64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.datacls.linked_component import LinkedComponent
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass
from test_live_register_preservation import make_module, symbol_references


class AArch64BTIBackendTests(unittest.TestCase):
    def test_marker_replaces_first_word_only_in_opt_in_architecture(self):
        # The runtime recognises a BTI target by the words it defines in aarch64_bti.c.
        source = (Path(__file__).resolve().parents[1] / 'libcheckpoint/src/aarch64_bti.c').read_text()
        runtime = {name: int(value, 16) for name, value in re.findall(
            r'^#define (BTI_JC|SECOND_MAGIC) UINT32_C\((0x[0-9a-f]+)\)$', source, re.MULTILINE)}
        self.assertEqual(AArch64BTIArchitecture.MAGIC_WORDS, (runtime['BTI_JC'], runtime['SECOND_MAGIC']))
        self.assertEqual(AArch64Architecture.MAGIC_WORDS[1], runtime['SECOND_MAGIC'])
        self.assertNotEqual(AArch64Architecture.MAGIC_WORDS[0], runtime['BTI_JC'])
        self.assertEqual(InstrumentationOptions().target_identification, 'software')

    def test_fast_path_retains_four_bounds_and_removes_marker_loads(self):
        arch = AArch64BTIArchitecture()
        bounds = [gtirb.Symbol(name=n) for n in ('shadow_begin', 'shadow_end', 'normal_begin', 'normal_end')]
        fast = arch.indirect_branch_hardware_check_patch('x0', *bounds)(
            SimpleNamespace(scratch_registers=('x9', 'x10')))
        # The pass hands the combined mode's software predicate its window.
        self.assertEqual(arch.indirect_branch_check_options(SimpleNamespace(mnemonic='ret')),
                         {'window': True, 'ret_clause': True})
        slow = arch.indirect_branch_check_patch('x0', *bounds, window=True)(
            SimpleNamespace(scratch_registers=('x9', 'x10', 'x11')))
        self.assertIn('normal_begin', fast)
        self.assertIn('shadow_end', fast)
        self.assertNotIn('shadow_begin', fast)
        self.assertNotIn('normal_end', fast)
        self.assertIn('normal_begin', slow)
        self.assertIn('shadow_end', slow)
        self.assertNotIn('shadow_begin', slow)
        self.assertNotIn('normal_end', slow)
        self.assertIn('restore_checkpoint_MALFORMED_INDIRECT_BR', fast)
        self.assertNotIn('ldr w', fast)
        self.assertIn('tst x9, #3', fast)
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
                                 InstrumentationOptions(target_identification='aarch64-bti-pac'))
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
        # The combined build calls its own runtime entry point, after the marker, and not the ordinary one.
        calls = symbol_references(pipeline.text_section)
        self.assertIn('libcheckpoint_enable_aarch64_bti_pac', calls)
        self.assertGreaterEqual(min(calls['libcheckpoint_enable_aarch64_bti_pac']), entry.address + 8)
        self.assertNotIn('libcheckpoint_enable', calls)

    def test_non_arm_and_disabled_required_checks_are_rejected(self):
        ir, _, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b'\xc3')
        with self.assertRaisesRegex(ValueError, 'requires AArch64'):
            TeapotPipeline(ir, options=InstrumentationOptions(target_identification='aarch64-bti-pac')).run()
        ir, _, _, _, _ = make_module(AArch64Architecture(), gtirb.Module.ISA.ARM64,
                                      bytes.fromhex('c0035fd6'))
        for flag in ('enable_checkpoints', 'enable_indirect_check', 'enable_indirect_transform'):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, 'requires target'):
                TeapotPipeline(ir, options=InstrumentationOptions(
                    target_identification='aarch64-bti-pac', **{flag: False})).run()

    def test_bti_component_uses_global_link_bounds_without_defining_aliases(self):
        # Run the real component pipeline: exported library functions need the
        # same BTI marker as main, but each object must not define global bounds.
        for exported in ('provider', 'main'):
            arch = AArch64Architecture()
            ir, module, block, _, registers = make_module(
                arch, gtirb.Module.ISA.ARM64, bytes.fromhex('00008052c0035fd6'))
            symbol = next(module.symbols_named('test_function'))
            symbol.name = exported
            module.aux_data['liveRegisterSets'].data = {
                gtirb.Offset(block, inst.address - block.address): (1 << len(registers)) - 1
                for inst in GtirbInstructionDecoder(module.isa).get_instructions(block)}
            ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                                  gtirb.Edge.Label(gtirb.Edge.Type.Return)))
            context = LinkedComponent('a' * 64, frozenset({exported}), frozenset({exported}))
            pipeline = TeapotPipeline(ir, 'aarch64-vma42',
                                     InstrumentationOptions(target_identification='aarch64-bti-pac'),
                                     linked_component=context)
            with self.subTest(exported=exported), redirect_stdout(io.StringIO()):
                pipeline.run()
                self.assertEqual(pipeline.text_section.name, '.teapot_bti_normal')
                entry = symbol.referent
                self.assertEqual(entry.byte_interval.contents[entry.offset:entry.offset + 8],
                                 AArch64BTIArchitecture().nop_bytes)
                self.assertEqual(module.aux_data['teapotTargetIdentification'].data, 'aarch64-bti-pac-v1')
                for suffix in ('text_start', 'text_end', 'transient_start', 'transient_end'):
                    self.assertFalse(list(module.symbols_named('__teapot_bti_' + suffix)))
                for name in ('normal_start', 'normal_end', 'transient_start', 'transient_end'):
                    self.assertIsInstance(next(module.symbols_named('__teapot_linked_' + name)).referent,
                                          gtirb.ProxyBlock)
