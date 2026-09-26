import unittest

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder


class X64CompareExchangeRegisterTests(unittest.TestCase):
    """CMPXCHG8B/16B read edx:eax and ecx:ebx and write edx:eax (Capstone 6 reports only al)."""

    def test_register_pairs(self):
        arch = X64Architecture()
        decoder = x64_decoder()
        names = lambda regs: {reg.name for reg in regs}
        for encoded in ("0fc70f", "f00fc70f", "480fc70f", "f0480fc70f"):  # [lock] cmpxchg8b/16b [rdi]
            inst = next(decoder.disasm(bytes.fromhex(encoded), 0x1000))
            with self.subTest(instruction=inst.mnemonic):
                self.assertTrue({"rax", "rbx", "rcx", "rdx", "rdi"} <= names(arch.access_registers(arch.abi, inst, 0)))
                self.assertTrue({"rax", "rdx"} <= names(arch.access_registers(arch.abi, inst, 1)))


if __name__ == "__main__":
    unittest.main()
