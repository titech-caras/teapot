import unittest
from uuid import uuid4
import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.manager import VECTOR_REGISTER_NAMES
from gtirb_capstone.instructions import GtirbInstructionDecoder
from teapot.arch import X64Architecture
from teapot.arch.x64.checkpoint_state import df_checkpoint_blocks, vector_checkpoint_cases, vector_state


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

    def test_vector_selection_uses_branch_liveness_and_honors_overrides(self):
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        abi = X64Architecture().abi
        for use, expected in [('', 0), ('0f2900', 1), ('440f2900', 2)]:
            ir, module, block = module_with('90 7500')
            contents = bytes.fromhex(use + '660fefc0 660fefc9 c3')
            interval = gtirb.ByteInterval(address=0x1003, contents=contents,
                                          section=block.section)
            after = gtirb.CodeBlock(size=len(contents), byte_interval=interval)
            next(iter(module.aux_data['functionBlocks'].data.values())).add(after)
            ir.cfg.add(gtirb.Edge(block, after, gtirb.Edge.Label(gtirb.EdgeType.Branch)))
            registers = [r for r in abi.all_registers() if r.name not in VECTOR_REGISTER_NAMES]
            module.aux_data['liveRegisterNames'] = gtirb.AuxData(
                [r.name for r in registers] + list(VECTOR_REGISTER_NAMES), 'sequence<string>')
            module.aux_data['liveRegisterSets'] = gtirb.AuxData({
                gtirb.Offset(b, i.address-b.address):
                    (1 << (len(registers) + (8 if expected == 2 else 0))) if expected else 0
                for b in (block, after)
                for i in decoder.get_instructions(b)}, 'mapping<Offset,uint64_t>')
            module.aux_data['liveRegisterSetsHigh'] = gtirb.AuxData(
                dict.fromkeys(module.aux_data['liveRegisterSets'].data, 0), 'mapping<Offset,uint64_t>')
            manager = LiveRegisterManager(module, abi, decoder)
            # The production path must not invoke the independent Python pass.
            manager.analyze_vectors = lambda _: self.fail('Python vector pass used without debug option')
            self.assertEqual(vector_checkpoint_cases(module, manager)[block.uuid], expected)
            for mode in ('xmm0-7', 'sse', 'avx', 'full'):
                self.assertEqual(vector_checkpoint_cases(module, manager, mode)[block.uuid],
                                 1 if mode == 'xmm0-7' else 2)
            module.aux_data['liveRegisterSetsHigh'].data.pop(gtirb.Offset(block, 1))
            self.assertEqual(vector_checkpoint_cases(module, manager)[block.uuid], 2)
        self.assertEqual([vector_state(m) for m in ('auto', 'xmm0-7', 'sse', 'avx', 'full')],
                         [4, 1, 2, 3, 4])


if __name__ == '__main__':
    unittest.main()
