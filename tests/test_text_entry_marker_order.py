"""A legal normal target must start with its marker, not entry instrumentation."""
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import gtirb
from capstone import CS_OP_IMM, CS_OP_MEM
from gtirb_rewriting.decoder import GtirbInstructionDecoder
from gtirb_functions import Function
from gtirb_rewriting import RewritingContext, patch_constraints

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.passes.common.asan_stack_pass import AsanStackPass
from teapot.passes.text.text_indirect_branch_transform_pass import TextIndirectBranchTransformPass
from teapot.passes.text.text_initialize_library_pass import TextInitializeLibraryPass
from test_live_register_preservation import make_module, symbol_references
from runtime_contract_support import fixture_contract, fixture_layout


class TextEntryMarkerOrderTests(unittest.TestCase):
    def test_required_riscv_entry_marker_precedes_complete_pc_relative_pair(self):
        arch = RISCV64Architecture()
        # AUIPC t0; ADDI t1,t0,4; RET, with the same HI/LO pair as a lifted entry.
        _, module, block, _, _ = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported,
            bytes.fromhex('970200001383420067800000'))
        entry = next(module.symbols_named('test_function'))
        target = gtirb.Symbol(name='data_target', payload=0x2000, module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        interval = block.byte_interval
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, {attrs.PCREL, attrs.HI})
        interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, entry, {attrs.PCREL, attrs.LO})
        functions = list(Function.build_functions(module))
        ctx = RewritingContext(module, functions)
        visitor = TextIndirectBranchTransformPass(
            block.section, SimpleNamespace(code_blocks_map={block.uuid: block}),
            GtirbInstructionDecoder(module.isa), arch,
            required_target_symbols=('test_function',))
        marker = patch_constraints()(lambda _ctx: 'addi zero, zero, 276\naddi zero, zero, 1300')
        visitor._indirect_transform_target_patch = Mock(return_value=marker)
        with redirect_stdout(io.StringIO()):
            visitor.begin_module(module, functions, ctx)
            ctx.apply()
        # Register allocation must see the true entry state, not the state
        # after AUIPC or after its low-half consumer.
        call = visitor._indirect_transform_target_patch.call_args.args
        self.assertIs(call[2], block)
        self.assertEqual(call[3], 0)
        actual = entry.referent
        self.assertEqual(actual.byte_interval.contents[actual.offset:actual.offset + 8], arch.nop_bytes)
        self.assertEqual(sorted(interval.symbolic_expressions), [8, 12])

    def rewrite(self, name, arch=None):
        arch = arch or X64Architecture()
        isa, contents = {
            'x64': (gtirb.Module.ISA.X64, '29c08b07c3'),
            'aarch64': (gtirb.Module.ISA.ARM64, '00008052c0035fd6'),
            'riscv64': (gtirb.Module.ISA.ValidButUnsupported, '1305000067800000'),
        }[arch.name]
        ir, module, block, abi, registers = make_module(
            arch, isa, bytes.fromhex(contents))
        symbol = next(module.symbols_named('test_function'))
        symbol.name = name
        mask = (1 << len(registers)) - 1
        module.aux_data['liveRegisterSets'].data = {
            gtirb.Offset(block, inst.address - block.address): mask
            for inst in GtirbInstructionDecoder(isa).get_instructions(block)}
        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                              gtirb.Edge.Label(gtirb.Edge.Type.Return)))
        pipeline = TeapotPipeline(ir, 'x64-la48-asan-new' if arch.name == 'x64' else None,
                                  runtime_contract=fixture_contract(arch.name))
        with redirect_stdout(io.StringIO()):
            pipeline.run()
        self.assertEqual(pipeline.reg_manager.analysis_source, 'ddisasm')
        entry = symbol.referent
        prefix = entry.byte_interval.contents[entry.offset:entry.offset + 8]
        self.assertEqual(prefix, b''.join(word.to_bytes(4, 'little') for word in arch.MAGIC_WORDS))
        return pipeline

    def test_x64_target_marker_precedes_poison_with_all_passes(self):
        pipeline = self.rewrite('callback')
        # Moving the marker is not permission to suppress stack poisoning.
        moves = [inst for block in pipeline.text_section.code_blocks
                 for inst in pipeline.decoder.get_instructions(block) if inst.mnemonic == 'mov']
        self.assertTrue(any(len(inst.operands) == 2 and inst.operands[0].type == CS_OP_MEM and
                            inst.operands[1].type == CS_OP_IMM and inst.operands[1].imm == 255
                            for inst in moves))

    def test_main_marker_precedes_runtime_initialization(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name):
                pipeline = self.rewrite('main', arch)
                entry = next(pipeline.module.symbols_named('main')).referent
                calls = symbol_references(pipeline.text_section).get('libcheckpoint_enable')
                self.assertTrue(calls, 'no call to libcheckpoint_enable was inserted')
                self.assertGreaterEqual(min(calls), entry.address + 8)  # after the two marker words

    def test_section_bounds_end_at_their_intervals_ends(self):
        # Entry code goes in front of main, the first block of both sections;
        # the zero-size bounds must still name the sections' ends.
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name), \
                    patch.object(TeapotPipeline, '_pin_section_bounds', autospec=True,
                                 side_effect=TeapotPipeline._pin_section_bounds) as pin:
                pipeline = self.rewrite('main', arch)
                pin.assert_called_once()
                for symbol, at_end in zip(pipeline.local_section_bounds, (False, True, False, True)):
                    block = symbol.referent
                    self.assertEqual(block.offset, block.byte_interval.size if at_end else 0, symbol.name)

    def test_software_mode_needs_no_layout(self):
        # The software check tests only the marker pair, so normal text keeps
        # its name and no window bounds are exported for a linker script.
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            with self.subTest(arch=arch.name):
                pipeline = self.rewrite('callback', arch)
                self.assertEqual(pipeline.text_section.name, '.text')
                self.assertFalse([symbol.name for symbol in pipeline.module.symbols
                                  if symbol.name.startswith('__teapot_soft_')])

    def test_all_architectures_register_targets_before_other_entry_effects(self):
        for arch in (X64Architecture(), AArch64Architecture(), RISCV64Architecture()):
            for enabled in (False, True):
                with self.subTest(arch=arch.name, enabled=enabled):
                    pipeline = TeapotPipeline(gtirb.IR(), options=InstrumentationOptions(
                        enable_indirect_transform=enabled))
                    pipeline.arch = arch
                    pipeline.text_section = gtirb.Section(name='.text')
                    pipeline.text_transient_mapping = SimpleNamespace(code_blocks_map={})
                    pipeline.decoder = None
                    pipeline.dift_layout = fixture_layout(arch.name)
                    pipeline.landing_pad_targets = set()
                    pipeline.checkpoint_block_uuids = set()
                    pipeline.checkpoint_spare_registers = {}
                    # What the potential-target search hands the transform.
                    pipeline.state.potential_targets.set(frozenset())
                    pipeline.state.flags_dead_blocks.set(frozenset())
                    pipeline._run_pass_manager = Mock()
                    pipeline._run_text_passes()
                    manager, label = pipeline._run_pass_manager.call_args.args
                    self.assertEqual(label, 'text')
                    types = [type(p) for p in manager._passes]
                    self.assertIn(AsanStackPass, types)
                    self.assertIn(TextInitializeLibraryPass, types)
                    self.assertEqual(types.count(TextIndirectBranchTransformPass), int(enabled))
                    if enabled:
                        self.assertIs(types[0], TextIndirectBranchTransformPass)


if __name__ == '__main__':
    unittest.main()
