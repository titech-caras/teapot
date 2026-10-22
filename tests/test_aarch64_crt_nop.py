"""Raw fixed AArch64 CRT forms: an ordinary NOP is not arbitrary padding."""
import struct
from types import SimpleNamespace
import unittest

from tools.sharedlib.convert import StartupImage, Unsupported


class Section(dict):
    def __init__(self, name, address, words):
        self.name = name
        self.words = list(words)
        super().__init__(sh_addr=address, sh_size=len(words) * 4, sh_flags=6)

    def data(self):
        return struct.pack('<' + 'I' * len(self.words), *self.words)


class Image(dict):
    def __init__(self, sections):
        super().__init__(e_machine='EM_AARCH64')
        self.sections = sections

    def iter_sections(self):
        return iter(self.sections)


def fixture(prefix='none'):
    # Independent literal opcodes at nonzero addresses. BL immediates account
    # for the prefix; a stale pre-prefix PC would miss call_weak_fn by four bytes.
    prefixes = {'none': [], 'nop': [0xd503201f], 'pac': [0xd503233f]}
    begin = prefixes[prefix]
    tail = [0xd50323bf] if prefix == 'pac' else []
    init = Section('.init', 0x401000, begin + [0xa9bf7bfd, 0x910003fd,
        0x9400007e if prefix == 'none' else 0x9400007d, 0xa8c17bfd] + tail + [0xd65f03c0])
    fini = Section('.fini', 0x401100, begin + [0xa9bf7bfd, 0x910003fd, 0xa8c17bfd] + tail + [0xd65f03c0])
    # call_weak_fn loads the GLOB_DAT slot at 0x403040 and jumps through the
    # matching PLT entry, whose JUMP_SLOT is at 0x403048.
    helper = Section('.text.helper', 0x401200,
        [0xd0000000, 0xf9402000, 0xb4000040, 0x1400003d, 0xd65f03c0])
    plt = Section('.plt', 0x401300, [0xd0000010, 0xf9402611, 0x91012210, 0xd61f0220])
    sections = [init, fini, helper, plt]
    static = [{'name': 'call_weak_fn', 'address': 0x401200, 'section': 1}]
    relocations = {0x403040: {'r_info_type': 1025, 'r_info_sym': 1, 'r_addend': 0},
                   0x403048: {'r_info_type': 1026, 'r_info_sym': 1, 'r_addend': 0}}
    names = ('', '__gmon_start__', 'unexpected_hook')
    dynamic = SimpleNamespace(get_symbol=lambda index: SimpleNamespace(name=names[index]))
    checked = StartupImage(Image(sections), static, relocations, dynamic, 'raw-crt')
    return checked, init, fini, helper, plt


class AArch64CrtNopTests(unittest.TestCase):
    def test_exact_no_prefix_pac_or_one_nop(self):
        for prefix in ('none', 'pac', 'nop'):
            with self.subTest(prefix=prefix):
                checked, init, fini, _, _ = fixture(prefix)
                self.assertEqual((init['sh_size'], fini['sh_size']),
                                 {'none': (20, 16), 'pac': (28, 24), 'nop': (24, 20)}[prefix])
                checked.arm_init_fini(init, fini)


    def test_wrong_hint_is_not_an_ordinary_nop(self):
        for word in (0xd503245f, 0xd503203f, 0xd50323bf, 0x14000000):
            for is_init in (True, False):
                with self.subTest(word=hex(word), init=is_init):
                    checked, init, fini, _, _ = fixture('nop')
                    (init if is_init else fini).words[0] = word
                    with self.assertRaises(Unsupported):
                        checked.arm_init_fini(init, fini)

    def test_nop_call_immediate_is_resolved_at_the_shifted_pc(self):
        checked, init, fini, _, _ = fixture('nop')
        init.words[3] = 0x9400007e  # Bare-form immediate, now targets helper+4.
        with self.assertRaisesRegex(Unsupported, 'CRT branch target'):
            checked.arm_init_fini(init, fini)


if __name__ == '__main__':
    unittest.main()
