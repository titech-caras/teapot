import unittest
from uuid import uuid4
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from teapot.arch import X64Architecture
from teapot.arch.x64.checkpoint_state import df_checkpoint_blocks, vector_state


def module_with(code):
    module = gtirb.Module(name='state', isa=gtirb.Module.ISA.X64,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    ir = gtirb.IR(modules=[module])
    section = gtirb.Section(name='.text', module=module)
    interval = gtirb.ByteInterval(address=0x1000, contents=bytes.fromhex(code), section=section)
    block = gtirb.CodeBlock(size=len(interval.contents), byte_interval=interval)
    fid = uuid4()
    module.aux_data['functionEntries'] = gtirb.AuxData({fid: {block}}, 'mapping<UUID,set<UUID>>')
    module.aux_data['functionBlocks'] = gtirb.AuxData({fid: {block}}, 'mapping<UUID,set<UUID>>')
    module.aux_data['functionNames'] = gtirb.AuxData({}, 'mapping<UUID,UUID>')
    return ir, module, block


class CheckpointStateSelectionTests(unittest.TestCase):
    def test_df_set_clear_and_unknown(self):
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        abi = X64Architecture().abi
        for code, expected in [('fd 7500', True), ('fd fc 7500', False),
                               ('9d 7500', True), ('fd e800000000 7500', False),
                               ('90 7500', False)]:
            ir, module, block = module_with(code)
            self.assertEqual(block.uuid in df_checkpoint_blocks(module, decoder, abi), expected)

    def test_vector_auto_does_not_guess_external_state(self):
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        for code, expected in [('660fefc0 c3', 1), ('66450fefc0 c3', 2),
                               ('0f58c0 c3', 2), ('c5fdefc0 c3', 3),
                               ('d9e8 c3', 4), ('ffd0 c3', 4), ('0fae10 c3', 2),
                               ('0fae08 c3', 4), ('62f17d08efc0 c3', 4)]:
            ir, module, block = module_with(code)
            self.assertEqual(vector_state(module, decoder), expected, code)
            self.assertEqual(vector_state(module, decoder, component=True), 4)
        ir, module, block = module_with('e800000000 c3')
        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                              gtirb.Edge.Label(gtirb.EdgeType.Call)))
        self.assertEqual(vector_state(module, decoder), 4)


if __name__ == '__main__':
    unittest.main()
