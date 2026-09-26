import unittest

from gtirb_live_register_analysis.analysis import LiveRegisterAnalyzer
from teapot.arch.x64.architecture import X64Architecture
from teapot.arch.decoders import x64_decoder


class X64TestRegisterInputsTests(unittest.TestCase):
    def test_test_register_sources_are_read_not_written(self):
        arch = X64Architecture()
        decoder = x64_decoder()
        analyzer = LiveRegisterAnalyzer(arch.abi, decoder=None)
        rsi = arch.abi.get_register('rsi')
        rdi = arch.abi.get_register('rdi')
        for encoding in ('408437', '668537', '8537', '488537',
                         '4084f7', '6685f7', '85f7', '4885f7'):
            insn = next(decoder.disasm(bytes.fromhex(encoding), 0x1000))
            with self.subTest(instruction=insn.op_str):
                self.assertEqual(insn.mnemonic, 'test')
                self.assertTrue({rsi, rdi}.issubset(arch.access_registers(arch.abi, insn, 0)))
                self.assertEqual(arch.access_registers(arch.abi, insn, 1), set())
                self.assertTrue({rsi, rdi}.issubset(analyzer._instruction_regs_read(insn)))
                self.assertFalse({rsi, rdi} & analyzer._instruction_regs_write(insn))


if __name__ == '__main__':
    unittest.main()
