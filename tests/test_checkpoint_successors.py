"""Uncopied conditional successors must not create dangling checkpoints."""
from types import SimpleNamespace
import unittest
from unittest import mock

import gtirb

from teapot.arch import X64Architecture
from teapot.datacls.copied_section_mapping import CopiedSectionMapping
from teapot.passes.preprocessing.create_trampolines_pass import CreateTrampolinesPass
from teapot.passes.common.insert_checkpoints_pass import InsertCheckpointsPass


class CheckpointSuccessorTests(unittest.TestCase):
    def test_missing_or_external_successors_skip_checkpoint_consistently(self):
        for shape in ('missing-fallthrough', 'external-branch', 'external-fallthrough', 'copied'):
            with self.subTest(shape=shape):
                module = gtirb.Module(name='probe', isa=gtirb.Module.ISA.X64)
                ir = gtirb.IR(modules=[module])
                text = gtirb.Section(name='.text', module=module)
                interval = gtirb.ByteInterval(address=0x1000, contents=b'\x75\x00\xc3\xc3', section=text)
                source = gtirb.CodeBlock(size=2, byte_interval=interval)
                fallthrough = gtirb.CodeBlock(size=1, offset=2, byte_interval=interval)
                taken = gtirb.CodeBlock(size=1, offset=3, byte_interval=interval)
                ir.cfg.add(gtirb.Edge(source, taken, gtirb.Edge.Label(gtirb.Edge.Type.Branch,
                                                                   conditional=True, direct=True)))
                if shape != 'missing-fallthrough':
                    ir.cfg.add(gtirb.Edge(source, fallthrough, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
                mapping = {block.uuid: gtirb.CodeBlock(size=block.size) for block in (source, taken, fallthrough)}
                if shape == 'external-branch':
                    del mapping[taken.uuid]
                if shape == 'external-fallthrough':
                    del mapping[fallthrough.uuid]
                sections = [gtirb.Section(name=name, module=module) for name in ('trampolines', 'counters')]
                for section in sections:
                    gtirb.ByteInterval(section=section)
                decoder = mock.Mock()
                decoder.get_instructions.return_value = [SimpleNamespace(size=2, mnemonic='jne', op_str='target')]
                arch = X64Architecture()
                visitor = CreateTrampolinesPass(text, *sections, CopiedSectionMapping(mapping, {}, {}), decoder, arch)
                visitor.module, visitor.rewriting_ctx = module, mock.Mock()
                if shape == 'copied':
                    visitor.visit_code_block(source)
                    self.assertEqual(visitor.processed_blocks, {source.uuid})
                    self.assertEqual(visitor.rewriting_ctx.replace_at.call_count, 1)
                else:
                    with self.assertWarnsRegex(RuntimeWarning, 'Checkpoint omitted'):
                        visitor.visit_code_block(source)
                    self.assertEqual(visitor.processed_blocks, set())
                    checkpoint = InsertCheckpointsPass(None, text, decoder, arch, visitor.processed_blocks)
                    checkpoint.insert_at = mock.Mock()
                    checkpoint.visit_code_block(source)
                    checkpoint.insert_at.assert_not_called()
                    visitor.rewriting_ctx.replace_at.assert_not_called()
                self.assertEqual(interval.contents, b'\x75\x00\xc3\xc3')


if __name__ == '__main__':
    unittest.main()
