"""The opt-in backend omits marker loads only for BTI-checked transfers."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting.abi import _ABIS

from teapot.arch import AArch64Architecture, X64Architecture
from teapot.arch.aarch64.bti import AArch64BTIArchitecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.datacls.linked_component import LinkedComponent
from teapot.passes.transient.indirect_branch_check_pass import TransientIndirectBranchCheckDestPass
from test_live_register_preservation import make_module, symbol_references
from runtime_contract_support import fixture_contract


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
        # The pass hands the combined mode's software predicate its window. A
        # return gets nothing more: no clause accepts a copy address without
        # the marker pair, so the copy's start is never compared.
        ret_options = arch.indirect_branch_check_options(SimpleNamespace(mnemonic='ret'))
        self.assertEqual(ret_options, {'window': True})
        slow = arch.indirect_branch_check_patch('x0', *bounds, **ret_options)(
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
        # A return's target must be aligned as well as marked.
        self.assertIn('tst x9, #3', slow)

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
                                 InstrumentationOptions(target_identification='aarch64-bti-pac'),
                                 runtime_contract=fixture_contract('aarch64', target_identification='aarch64-bti-pac'))
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

    def test_copy_returns_land_on_the_marker_pair(self):
        # main calls leaf directly, then through blr, then directly again in a call
        # the lift thinks never returns. In the combined mode each of the copy's
        # return sites starts with the marker pair right after its call, and the
        # copy's return check never compares a target with the copy's start: no
        # clause admits an unmarked copy address.
        arch = AArch64Architecture()
        # bl leaf; blr x1; bl leaf; ret; leaf: mov w0,#0; ret
        words = (0x94000004, 0xd63f0020, 0x94000002, 0xd65f03c0, 0x52800000, 0xd65f03c0)
        ir, module, direct, _, registers = make_module(arch, gtirb.Module.ISA.ARM64,
                                                      b''.join(word.to_bytes(4, 'little') for word in words))
        direct.size = 4
        interval = direct.byte_interval
        indirect, noreturn, last = (gtirb.CodeBlock(offset=offset, size=4, byte_interval=interval)
                                    for offset in (4, 8, 12))
        leaf = gtirb.CodeBlock(offset=16, size=8, byte_interval=interval)
        next(module.symbols_named('test_function')).name = 'main'
        leaf_symbol = gtirb.Symbol(name='leaf', payload=leaf, module=module)
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, leaf_symbol)
        interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, leaf_symbol)
        main_id = next(iter(module.aux_data['functionEntries'].data))
        module.aux_data['functionBlocks'].data[main_id].update({indirect, noreturn, last})
        leaf_id = uuid4()
        module.aux_data['functionEntries'].data[leaf_id] = {leaf}
        module.aux_data['functionBlocks'].data[leaf_id] = {leaf}
        module.aux_data['functionNames'].data[leaf_id] = leaf_symbol
        unknown = gtirb.ProxyBlock(module=module)
        for source, target, kind, is_direct in (
                (direct, leaf, gtirb.Edge.Type.Call, True), (direct, indirect, gtirb.Edge.Type.Fallthrough, True),
                (indirect, unknown, gtirb.Edge.Type.Call, False),
                (indirect, noreturn, gtirb.Edge.Type.Fallthrough, True),
                (noreturn, leaf, gtirb.Edge.Type.Call, True),
                (last, unknown, gtirb.Edge.Type.Return, False), (leaf, unknown, gtirb.Edge.Type.Return, False)):
            ir.cfg.add(gtirb.Edge(source, target, gtirb.Edge.Label(kind, direct=is_direct)))
        decoder = GtirbInstructionDecoder(module.isa)
        mask = (1 << len(registers)) - 1
        module.aux_data['liveRegisterSets'].data = {
            gtirb.Offset(block, inst.address - block.address): mask
            for block in (direct, indirect, noreturn, last, leaf) for inst in decoder.get_instructions(block)}
        pipeline = TeapotPipeline(ir, 'aarch64-vma42',
                                  InstrumentationOptions(target_identification='aarch64-bti-pac'),
                                  runtime_contract=fixture_contract('aarch64', target_identification='aarch64-bti-pac'))
        output = io.StringIO()
        with redirect_stdout(output):
            pipeline.run()
        self.assertIn('3 copy calls', output.getvalue())
        copy = pipeline.transient_section
        calls = [block for block in copy.code_blocks
                 if any(edge.label.type == gtirb.Edge.Type.Call for edge in block.outgoing_edges)]
        self.assertEqual(len(calls), 3)
        for block in calls:
            self.assertIn(list(decoder.get_instructions(block))[-1].mnemonic, ('bl', 'blr'))
            end = block.offset + block.size
            self.assertEqual(bytes(block.byte_interval.contents[end:end + 8]),
                             bytes.fromhex('df2403d59fa280d2'))
        references = symbol_references(copy)
        # leaf's return is checked; main's is not.
        self.assertIn('restore_checkpoint_MALFORMED_INDIRECT_BR', references)
        self.assertIn(pipeline.text_section_start_symbol.name, references)
        self.assertNotIn(pipeline.transient_section_start_symbol.name, references)

    def test_unclassified_authenticated_calls_and_returns_are_refused(self):
        # DDisasm marks only BL/BLR as calls and RET as the return, so these would
        # leave their return sites without a marker; both modes refuse them.
        for contents, mnemonic in (("43083fd7c0035fd6", "blraa"), ("ff0b5fd6", "retaa"), ("ff0f5fd6", "retab")):
            for options in (InstrumentationOptions(),
                            InstrumentationOptions(target_identification="aarch64-bti-pac")):
                with self.subTest(instruction=mnemonic, mode=options.target_identification):
                    arch = AArch64Architecture()
                    ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, bytes.fromhex(contents))
                    contract = fixture_contract("aarch64", target_identification=options.target_identification)
                    with self.assertRaisesRegex(ValueError, f"pointer-authenticated calls or returns the lift "
                                                            f"does not mark as such \\({mnemonic} at 0x"):
                        with redirect_stdout(io.StringIO()):
                            TeapotPipeline(ir, "aarch64-vma42", options, runtime_contract=contract).run()

    def test_a_return_site_needs_its_call_right_before_it(self):
        arch = AArch64BTIArchitecture()
        marker = bytes.fromhex('df2403d59fa280d2')
        ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, marker)
        pipeline = TeapotPipeline(ir)
        pipeline.module, pipeline.abi = module, arch.register_abi(_ABIS)
        checked, misplaced = pipeline._verify_copy_return_sites(block.section, {block.uuid})
        self.assertEqual((checked, len(misplaced)), (1, 1))
        self.assertIn("nothing ends right before the return site", misplaced[0])

    def test_a_recorded_return_site_that_disappears_is_refused(self):
        # Gone from the copy, or left empty: the check must not skip it.
        arch = AArch64BTIArchitecture()
        marker = bytes.fromhex('df2403d59fa280d2')
        ir, module, block, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, marker)
        empty = gtirb.CodeBlock(offset=8, size=0, byte_interval=block.byte_interval)
        pipeline = TeapotPipeline(ir)
        pipeline.module, pipeline.abi = module, arch.register_abi(_ABIS)
        gone = uuid4()
        checked, misplaced = pipeline._verify_copy_return_sites(block.section, {gone, empty.uuid})
        self.assertEqual(checked, 0)
        self.assertEqual(sorted(misplaced), sorted(f"the recorded return site {uuid} is gone or empty"
                                                   for uuid in (gone, empty.uuid)))

    def test_code_between_a_copy_call_and_its_return_site_is_refused(self):
        # bl; nop and then the padded return site: the return would land on the nop.
        arch = AArch64BTIArchitecture()
        marker = bytes.fromhex('df2403d59fa280d2')
        for words, expected in (((0x94000002,), []), ((0x94000002, 0xd503201f), ["follows nop"])):
            with self.subTest(words=words):
                call_bytes = b''.join(word.to_bytes(4, 'little') for word in words)
                ir, module, call, _, _ = make_module(arch, gtirb.Module.ISA.ARM64, call_bytes + marker)
                call.size = len(call_bytes)
                site = gtirb.CodeBlock(offset=len(call_bytes), size=8, byte_interval=call.byte_interval)
                ir.cfg.add(gtirb.Edge(call, gtirb.ProxyBlock(module=module),
                                      gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=False)))
                pipeline = TeapotPipeline(ir)
                pipeline.module, pipeline.abi = module, arch.register_abi(_ABIS)
                checked, misplaced = pipeline._verify_copy_return_sites(call.section, {site.uuid})
                self.assertEqual(checked, 1)
                self.assertEqual(len(misplaced), len(expected))
                for text, pattern in zip(misplaced, expected):
                    self.assertIn(pattern, text)

    def test_non_arm_and_disabled_required_checks_are_rejected(self):
        ir, _, _, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, b'\xc3')
        with self.assertRaisesRegex(ValueError, 'requires AArch64'):
            TeapotPipeline(ir, options=InstrumentationOptions(target_identification='aarch64-bti-pac')).run()
        ir, _, _, _, _ = make_module(AArch64Architecture(), gtirb.Module.ISA.ARM64,
                                      bytes.fromhex('c0035fd6'))
        for flag in ('enable_checkpoints', 'enable_indirect_check', 'enable_indirect_transform'):
            with self.subTest(flag=flag), self.assertRaisesRegex(
                    ValueError, 'aarch64-bti-pac requires .*drop --disable-'):
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
                                     linked_component=context,
                                     runtime_contract=fixture_contract('aarch64',
                                                                       target_identification='aarch64-bti-pac'))
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
                # The unused local bounds are pinned too, so the object is the same in every run.
                for local, at_end in zip(pipeline.local_section_bounds, (False, True, False, True)):
                    bound = local.referent
                    self.assertEqual(bound.offset, bound.byte_interval.size if at_end else 0, local.name)
