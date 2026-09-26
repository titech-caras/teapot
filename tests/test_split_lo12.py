import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.passes.preprocessing.split_lo12 import symbolize_split_lo12

LO12 = gtirb.SymbolicExpression.Attribute.LO12
ADRP_X22_3000 = 0xD0000016      # adrp x22, 0x3000   (placed at 0x1000)
ADRP_X1_3000 = 0xD0000001       # adrp x1, 0x3000
ADD_X22_AB8 = 0x912AE2D6        # add x22, x22, #0xab8
ADD_X22_AC0 = 0x912B02D6        # add x22, x22, #0xac0
ADD_X1_AB8 = 0x912AE021         # add x1, x1, #0xab8
MOV_X22_0 = 0xD2800016          # mov x22, #0
BL_SELF = 0x94000000            # bl . (target irrelevant)
RET = 0xD65F03C0


class SplitLo12Tests(unittest.TestCase):
    def build(self, blocks, edges):
        """blocks: list of word lists laid out from 0x1000; edges: (src, dst, type)."""
        ir = gtirb.IR()
        module = gtirb.Module(name='split', isa=gtirb.Module.ISA.ARM64, ir=ir,
                              file_format=gtirb.Module.FileFormat.ELF,
                              byte_order=gtirb.Module.ByteOrder.Little)
        text = gtirb.Section(name='.text', module=module)
        contents = b''.join(w.to_bytes(4, 'little') for words in blocks for w in words)
        code = gtirb.ByteInterval(address=0x1000, section=text, contents=contents)
        made, offset = [], 0
        for words in blocks:
            made.append(gtirb.CodeBlock(size=4 * len(words), offset=offset, byte_interval=code))
            offset += 4 * len(words)
        data = gtirb.Section(name='.bss', module=module)
        interval = gtirb.ByteInterval(address=0x3000, size=0x1000, section=data)
        symbol = gtirb.Symbol(name='orig_pmeth', payload=gtirb.DataBlock(size=24, offset=0xab8, byte_interval=interval),
                              module=module)
        for src, dst, kind in edges:
            ir.cfg.add(gtirb.Edge(source=made[src], target=made[dst], label=gtirb.Edge.Label(type=kind)))
        code.symbolic_expressions[0] = gtirb.SymAddrConst(0, symbol, set())   # the symbolized ADRP
        return module, code, made, symbol

    def run_fix(self, module):
        return symbolize_split_lo12(module, GtirbInstructionDecoder(module.isa))

    def expr(self, code, block):
        return code.symbolic_expressions.get(block.offset)

    def test_user_behind_a_fallthrough_edge_is_symbolized(self):
        module, code, blocks, symbol = self.build(
            [[ADRP_X22_3000], [ADD_X22_AB8, RET]], [(0, 1, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(self.run_fix(module), 1)
        self.assertEqual(self.expr(code, blocks[1]), gtirb.SymAddrConst(0, symbol, {LO12}))

    def test_callee_saved_register_crosses_a_call(self):
        module, code, blocks, symbol = self.build(
            [[ADRP_X22_3000, BL_SELF], [ADD_X22_AB8, RET]], [(0, 1, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(self.run_fix(module), 1)

    def test_caller_saved_register_does_not_cross_a_call(self):
        module, code, blocks, symbol = self.build(
            [[ADRP_X1_3000, BL_SELF], [ADD_X1_AB8, RET]], [(0, 1, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(self.run_fix(module), 0)
        self.assertIsNone(self.expr(code, blocks[1]))

    def test_other_reaching_definition_blocks_the_fix(self):
        module, code, blocks, symbol = self.build(
            [[ADRP_X22_3000], [MOV_X22_0], [ADD_X22_AB8, RET]],
            [(0, 2, gtirb.Edge.Type.Branch), (1, 2, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(self.run_fix(module), 0)
        self.assertIsNone(self.expr(code, blocks[2]))

    def test_offset_that_is_not_the_adrp_target_is_left_alone(self):
        module, code, blocks, symbol = self.build(
            [[ADRP_X22_3000], [ADD_X22_AC0, RET]], [(0, 1, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(self.run_fix(module), 0)
        self.assertIsNone(self.expr(code, blocks[1]))


if __name__ == '__main__':
    unittest.main()
