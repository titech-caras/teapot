"""Validate reachable CRT instructions, not bytes after a tail jump."""
import struct
import unittest
from types import SimpleNamespace

import convert


class Section(dict):
    def __init__(self, contents):
        super().__init__(sh_flags=2, sh_addr=0x1000, sh_size=len(contents))
        self.contents = contents

    def data(self):
        return bytes(self.contents)


class X64CrtPaddingTests(unittest.TestCase):
    def fixture(self, padding):
        self.data = bytearray(b'\xcc' * 0x1000)
        self.addresses = dict(frame_dummy=0x1000, register_tm_clones=0x1100,
                              deregister_tm_clones=0x1200, __do_global_dtors_aux=0x1300,
                              __TMC_END__=0x1700, **{'completed.0': 0x1708, '__dso_handle': 0x1710})
        for name, pattern in convert.CRT_PATTERNS.items():
            # Pin the executed frame_dummy body independently of the pattern
            # under test. Alignment bytes following its jump are not executed.
            if name == 'frame_dummy':
                body = bytes.fromhex('f3 0f 1e fa e9 00 00 00 00') + padding
            else:
                body = bytes(int(x, 16) if x != '??' else 0 for x in pattern.split())
            start = self.addresses[name] - 0x1000
            self.data[start:start + len(body)] = body

        def displacement(address, offset, end, target):
            struct.pack_into('<i', self.data, address + offset - 0x1000, target - address - end)

        displacement(0x1000, 5, 9, 0x1100)
        for address, got_offset, slot in ((0x1100, 39, 0x1800), (0x1200, 22, 0x1808)):
            displacement(address, 3, 7, 0x1700)
            displacement(address, 10, 14, 0x1700)
            displacement(address, got_offset, got_offset + 4, slot)
        for offset, end, target in ((6, 11, 0x1708), (46, 51, 0x1708),
                                    (17, 22, 0x1810), (30, 34, 0x1710),
                                    (40, 44, 0x1200), (35, 39, 0x1400)):
            displacement(0x1300, offset, end, target)
        self.data[0x400:0x406] = bytes.fromhex('ff 25 00 00 00 00')
        displacement(0x1400, 2, 6, 0x1810)
        hooks = ['_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', '__cxa_finalize']
        self.relocations = {0x1800 + 8 * i: {'r_info_type': 6, 'r_info_sym': i}
                            for i in range(3)}
        self.elf = SimpleNamespace(iter_sections=lambda: iter([Section(self.data)]))
        self.dynsym = SimpleNamespace(get_symbol=lambda i: SimpleNamespace(name=hooks[i]))
        self.static = [{'name': name, 'address': value, 'section': 1}
                       for name, value in self.addresses.items()]

    def validate(self):
        convert.validate_crt_callbacks(self.elf, self.static, self.relocations,
                                       self.dynsym, 'crt-fixture')

    def test_padding_after_tail_jump_is_not_part_of_callback(self):
        for padding in (bytes.fromhex('0f1f8000000000'), b'\x90' * 55,
                        bytes.fromhex('662e0f1f840000000000') * 5, b'\xcc' * 23):
            with self.subTest(padding=padding.hex()):
                self.fixture(padding)
                self.validate()

    def test_changed_reachable_instruction_is_rejected(self):
        self.fixture(b'\x90' * 55)
        self.data[4] = 0xe8  # CALL would execute the following bytes on return.
        with self.assertRaisesRegex(convert.Unsupported, 'UNSUPPORTED_CRT_CALLBACK_BODY:'):
            self.validate()

    def test_changed_tail_target_is_rejected(self):
        self.fixture(b'\x90' * 55)
        struct.pack_into('<i', self.data, 5, 0x1200 - 0x1009)
        with self.assertRaisesRegex(convert.Unsupported, 'UNSUPPORTED_CRT_CALLBACK_TARGET:'):
            self.validate()

    def test_registration_hook_is_still_validated(self):
        self.fixture(b'\x90' * 55)
        self.relocations[0x1800]['r_info_sym'] = 1
        with self.assertRaisesRegex(convert.Unsupported, 'UNSUPPORTED_CRT_CALLBACK_TARGET:'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
