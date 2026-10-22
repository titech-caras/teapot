"""Literal linked CRT bodies: accept two exact forms, never skip a prologue."""
from types import SimpleNamespace
import unittest

from tools.sharedlib.convert import StartupImage, Unsupported


class Section(dict):
    def __init__(self, name, address, words):
        self.name = name
        self.contents = bytearray().join(int(word, 16).to_bytes(len(word) // 2, 'little')
                                        for word in words.split())
        super().__init__(sh_addr=address, sh_size=len(self.contents), sh_flags=6)

    def data(self):
        return self.contents


class Image(dict):
    def __init__(self, sections):
        super().__init__(e_machine='EM_RISCV')
        self.sections = sections

    def iter_sections(self):
        return iter(self.sections)


# Independent objdump -M no-aliases literals from the retained r3 GCC13
# libprobe.so and FPGA expat-03/component/lib/libexpat.so.1.12.5, respectively.
FRAME_POINTER = (
    ('deregister_tm_clones', 0x3d0, '''1141 e422 0800 00002517 c3250513
        00002797 c2a78793 00a78a63 00002797 bfe7b783 c781 6422 0141 8782
        6422 0141 8082'''),
    ('register_tm_clones', 0x400, '''00002517 c0850513 00002597 c0058593
        8d89 1141 4035d793 91fd e422 95be 0800 8585 c989 00002797 bbc7b783
        c781 6422 0141 8782 6422 0141 8082'''),
    ('__do_global_dtors_aux', 0x43a, '''1101 e822 e426 ec06 1000 00002497
        bc448493 0004c783 e385 00002797 b867b783 c791 00002517 ba453503
        9782 f6bff0ef 4785 00f48023 60e2 6442 64a2 6105 8082'''),
    ('frame_dummy', 0x47a, '1141 e422 0800 6422 0141 bfb5'),
)
FRAME_POINTER_LESS = (
    ('deregister_tm_clones', 0x3aae, '''0001f517 60a50513 0001f797 60278793
        00a78863 0001f797 4c67b783 c391 8782 8082'''),
    ('register_tm_clones', 0x3ad0, '''0001f517 5e850513 0001f597 5e058593
        8d89 4035d793 91fd 95be 8585 c599 0001f797 4ea7b783 c391 8782 8082'''),
    ('__do_global_dtors_aux', 0x3afc, '''0001f797 5bc7c783 e79d 1141 e406
        0001f797 4c67b783 c791 0001f517 59c53503 9782 f91ff0ef 60a2 4785
        0001f717 58f70923 0141 8082 8082'''),
    ('frame_dummy', 0x3b34, 'bf71'),
)


def fixture(frame_pointer=True, displacement=0):
    sections = [Section(name, address + displacement, words)
                for name, address, words in (FRAME_POINTER if frame_pointer else FRAME_POINTER_LESS)]
    static = [{'name': section.name, 'address': section['sh_addr'], 'section': 1}
              for section in sections]
    completed = 0x2008 if frame_pointer else 0x230b8
    static += [{'name': name, 'address': address + displacement, 'section': 2}
               for name, address in (('__TMC_END__', completed), ('completed.0', completed),
                                     ('__dso_handle', completed - 8))]
    slots = (0x1fe8, 0x1fe0, 0x1fd8) if frame_pointer else (0x22f88, 0x22fd8, 0x22fd0)
    relocations = {address + displacement: {'r_info_type': 2, 'r_info_sym': index, 'r_addend': 0}
                   for index, address in enumerate(slots, 1)}
    names = ('', '_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable', '__cxa_finalize',
             '__gmon_start__', 'unexpected_hook')
    dynamic = SimpleNamespace(get_symbol=lambda index: SimpleNamespace(name=names[index]))
    return StartupImage(Image(sections), static, relocations, dynamic, 'literal-rv-crt'), sections


class RiscvCrtFramePointerTests(unittest.TestCase):
    def test_exact_old_and_frame_pointer_forms_at_different_addresses(self):
        for frame_pointer in (False, True):
            for displacement in (0, 0x100000):
                with self.subTest(frame_pointer=frame_pointer, displacement=displacement):
                    checked, _ = fixture(frame_pointer, displacement)
                    checked.rv_callbacks()


    def test_each_got_requires_exact_unadjusted_relocation_and_hook(self):
        for frame_pointer in (False, True):
            checked, _ = fixture(frame_pointer)
            for address in list(checked.relocations):
                for mutation in ('missing', 'kind', 'addend', 'gmon', 'other_hook'):
                    with self.subTest(frame_pointer=frame_pointer, address=address, mutation=mutation):
                        original = checked.relocations.pop(address)
                        changed = dict(original)
                        if mutation == 'kind':
                            changed['r_info_type'] = 3
                        elif mutation == 'addend':
                            changed['r_addend'] = 8
                        elif mutation in ('gmon', 'other_hook'):
                            changed['r_info_sym'] = 4 if mutation == 'gmon' else 5
                        if mutation != 'missing':
                            checked.relocations[address] = changed
                        try:
                            with self.assertRaisesRegex(Unsupported, 'UNSUPPORTED_CRT_CALLBACK_TARGET'):
                                checked.rv_callbacks()
                        finally:
                            checked.relocations[address] = original

if __name__ == '__main__':
    unittest.main()
