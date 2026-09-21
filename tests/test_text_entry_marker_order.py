"""A legal normal target must start with its marker, not entry instrumentation."""
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import gtirb
from capstone_gt import CS_OP_IMM, CS_OP_MEM
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.datacls.dift_layout import get_dift_layout
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from teapot.passes.common.asan_stack_pass import AsanStackPass
from teapot.passes.text.text_indirect_branch_transform_pass import TextIndirectBranchTransformPass
from teapot.passes.text.text_initialize_library_pass import TextInitializeLibraryPass
from test_live_register_preservation import make_module


class TextEntryMarkerOrderTests(unittest.TestCase):
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
        pipeline = TeapotPipeline(ir, 'x64-la48-asan-new' if arch.name == 'x64' else None)
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
                self.assertTrue(any(sym.name == 'libcheckpoint_enable' for sym in pipeline.module.symbols))

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
                    pipeline.dift_layout = get_dift_layout(arch.name)
                    pipeline.landing_pad_targets = set()
                    pipeline.checkpoint_block_uuids = set()
                    pipeline.checkpoint_spare_registers = {}
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
