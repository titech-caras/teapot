"""The default x64 CET CRT adds exactly one ENDBR64, not arbitrary prologues."""
import struct
from types import SimpleNamespace
import unittest

from tools.sharedlib import convert as converter


ENDBR = bytes.fromhex('f30f1efa')
INIT_PREFIX = bytes.fromhex('4883ec08488b05')
INIT_SUFFIX = bytes.fromhex('4885c07402ffd04883c408c3')
FINI = bytes.fromhex('4883ec084883c408c3')


class Section(dict):
    def __init__(self, data, address=0x1000):
        super().__init__(sh_addr=address)
        self.contents = data

    def data(self):
        return self.contents


class X64CrtEndbr64Tests(unittest.TestCase):
    def validate(self, init, fini, got, name='__gmon_start__'):
        class Symbols:
            def get_symbol(self, index):
                assert index == 7
                return SimpleNamespace(name=name)
        relocations = {got: {'r_info_sym': 7}} if got is not None else {}
        converter.validate_x64_init_fini(init, fini, relocations, Symbols(), '/input')

    def init(self, leading=b'', displacement=0x100):
        return Section(leading + INIT_PREFIX + struct.pack('<i', displacement) + INIT_SUFFIX)

    def test_plain_and_one_endbr_are_independently_accepted_on_each_body(self):
        for initial in (b'', ENDBR):
            for final in (b'', ENDBR):
                with self.subTest(initial=initial, final=final):
                    self.validate(self.init(initial), Section(final + FINI),
                                  0x1000 + len(initial) + 11 + 0x100)

    def test_endbr_moves_the_rip_relative_got_base_by_four_for_both_displacement_signs(self):
        for displacement in (-0x100, 0x100):
            got = 0x1000 + 4 + 11 + displacement
            self.validate(self.init(ENDBR, displacement), None, got)
            with self.assertRaisesRegex(converter.Unsupported, 'CUSTOM_DT_INIT'):
                self.validate(self.init(ENDBR, displacement), None, got - 4)

class X64CrtFinalizePltTests(unittest.TestCase):
    def fixture(self, prefix=b''):
        # Literal canonical bodies, not generated from the production regex.
        frame = bytearray.fromhex('f30f1efa e900000000')
        register = bytearray.fromhex(
            '488d3d00000000 488d3500000000 4829fe 4889f0 48c1ee3f 48c1f803 '
            '4801c6 48d1fe 7414 488b0500000000 4885c0 7408 ffe0 '
            '660f1f440000 c3 0f1f8000000000')
        deregister = bytearray.fromhex(
            '488d3d00000000 488d0500000000 4839f8 7415 488b0500000000 '
            '4885c0 7409 ffe0 0f1f8000000000 c3 0f1f8000000000')
        dtors = bytearray.fromhex(
            'f30f1efa 803d0000000000 752b 55 48833d0000000000 4889e5 740c '
            '488b3d00000000 e800000000 e800000000 c6050000000001 5d c3 '
            '0f1f00 c3 0f1f8000000000')
        def displacement(data, address, offset, end, destination):
            data[offset:offset + 4] = struct.pack('<i', destination - address - end)
        displacement(frame, 0x1000, 5, 9, 0x1100)
        for data, address, offset, hook in ((register, 0x1100, 39, 0x6000),
                                           (deregister, 0x1200, 22, 0x6008)):
            displacement(data, address, 3, 7, 0x5000)
            displacement(data, address, 10, 14, 0x5000)
            displacement(data, address, offset, offset + 4, hook)
        for offset, end, destination in ((6, 11, 0x5100), (46, 51, 0x5100),
                                         (17, 22, 0x6010), (30, 34, 0x5200),
                                         (40, 44, 0x1200), (35, 39, 0x1400)):
            displacement(dtors, 0x1300, offset, end, destination)
        plt = bytearray(prefix + bytes.fromhex('ff25') +
                        struct.pack('<i', 0x6010 - 0x1400 - len(prefix) - 6))
        sections = [Section(frame, 0x1000), Section(register, 0x1100),
                    Section(deregister, 0x1200), Section(dtors, 0x1300), Section(plt, 0x1400)]
        for section in sections:
            section.update(sh_flags=6, sh_size=len(section.contents))
        elf = SimpleNamespace(iter_sections=lambda: iter(sections))
        static = [dict(name=name, address=address, section=1) for name, address in
                  (('frame_dummy', 0x1000), ('register_tm_clones', 0x1100),
                   ('deregister_tm_clones', 0x1200), ('__do_global_dtors_aux', 0x1300),
                   ('__TMC_END__', 0x5000), ('completed.0', 0x5100), ('__dso_handle', 0x5200))]
        names = ('', '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', '__cxa_finalize', 'wrong')
        dynsym = SimpleNamespace(get_symbol=lambda index: SimpleNamespace(name=names[index]))
        relocations = {0x6000 + 8 * index: dict(r_info_type=6, r_info_sym=index + 1)
                       for index in range(3)}
        return elf, static, relocations, dynsym, sections

    def validate(self, fixture):
        converter.validate_crt_callbacks(*fixture[:4], '/input')

    def test_canonical_plain_or_one_exact_endbr_finalize_plt(self):
        for prefix in (b'', ENDBR):
            with self.subTest(prefix=prefix):
                self.validate(self.fixture(prefix))

    def test_duplicate_wrong_truncated_or_nop_prefix_refused(self):
        for prefix in (ENDBR * 2, b'\x90', bytes.fromhex('f30f1efb'), ENDBR[:3]):
            with self.subTest(prefix=prefix), self.assertRaises(converter.Unsupported):
                self.validate(self.fixture(prefix))

    def test_endbr_got_is_resolved_from_shifted_jump_pc(self):
        fixture = self.fixture(ENDBR)
        plt = fixture[4][-1]
        plt.contents[-4:] = struct.pack('<i', 0x6010 - 0x1400 - 6)
        with self.assertRaisesRegex(converter.Unsupported, 'GOT slot'):
            self.validate(fixture)

if __name__ == '__main__':
    unittest.main()
