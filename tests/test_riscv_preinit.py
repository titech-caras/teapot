"""RV preinit regressions using production functions and real GTIRB metadata.

The linked-ELF fixtures implement the section/tag interface consumed by the
validator. These tests cover alignment and loader contracts, without claiming
a frontend, printer, or final executable integration run.
"""
import io
import struct
from types import SimpleNamespace
import unittest

import gtirb

from tools.sharedlib import convert as converter
from experiments.reusable_libraries.validate_link import validate_rv_preinit


LOAD_GP = 0x10420
PREINIT_ADDRESS = 0x23000


def lifted_preinit(sizes=(8,), alignment=1):
    module = gtirb.Module(name='rv-preinit', isa=gtirb.Module.ISA.RISCV64,
                          file_format=gtirb.Module.FileFormat.ELF)
    ir = gtirb.IR(modules=[module])
    section = gtirb.Section(name='.preinit_array', module=module)
    contents = struct.pack('<Q', LOAD_GP) * max(1, (sum(sizes) + 7) // 8)
    interval = gtirb.ByteInterval(address=PREINIT_ADDRESS,
                                  contents=contents, section=section)
    blocks = []
    offset = 0
    for size in sizes:
        blocks.append(gtirb.DataBlock(size=size, offset=offset, byte_interval=interval))
        offset += size
    other = gtirb.Section(name='.data', module=module)
    other_interval = gtirb.ByteInterval(address=0x24000, contents=b'unchanged', section=other)
    other_block = gtirb.DataBlock(size=8, byte_interval=other_interval)
    table = {other_block: 4}
    if alignment is not None:
        table.update((block, alignment) for block in blocks)
    module.aux_data['alignment'] = gtirb.AuxData(table, 'mapping<UUID,uint64_t>')
    item = {'role': 'executable', 'preinit_contract': {'load_gp': LOAD_GP},
            'path': '/inputs/rv-executable'}
    return ir, module, interval, blocks, other_block, item


class RiscvPreinitAlignmentTests(unittest.TestCase):
    def test_raise_alignment_without_changing_bytes_and_retain_it_in_serialized_ir(self):
        for initial in (None, 1, 4, 8, 16):
            with self.subTest(initial=initial):
                ir, module, interval, blocks, other, item = lifted_preinit(alignment=initial)
                block = blocks[0]
                before = bytes(interval.contents)
                self.assertEqual(converter.align_executable_preinit_array(module, item), 1)
                expected = max(initial or 1, 8)
                self.assertEqual(module.aux_data['alignment'].data[block], expected)
                self.assertEqual(module.aux_data['alignment'].data[other], 4)
                self.assertEqual(bytes(interval.contents), before)
                self.assertEqual((block.address, block.size), (PREINIT_ADDRESS, 8))
                self.assertEqual(converter.align_executable_preinit_array(module, item), 1)
                self.assertEqual(module.aux_data['alignment'].data[block], expected)
                encoded = io.BytesIO()
                ir.save_protobuf_file(encoded)
                encoded.seek(0)
                restored = gtirb.IR.load_protobuf_file(encoded).modules[0]
                restored_block = next(b for b in restored.data_blocks if b.uuid == block.uuid)
                self.assertEqual(restored.aux_data['alignment'].data[restored_block], expected)
                self.assertEqual(bytes(restored_block.byte_interval.contents), before)


class PreinitSection(dict):
    def __init__(self, words=(LOAD_GP,), address=PREINIT_ADDRESS, **updates):
        self.contents = b''.join(struct.pack('<Q', word) for word in words)
        super().__init__(sh_type='SHT_PREINIT_ARRAY', sh_addr=address,
                         sh_size=len(self.contents), sh_addralign=1)
        self.update(updates)

    def data(self):
        return self.contents


class PreinitELF:
    def __init__(self, section, tags=None):
        self.section = section
        self.tags = list(tags if tags is not None else (
            ('DT_PREINIT_ARRAY', section['sh_addr']),
            ('DT_PREINIT_ARRAYSZ', section['sh_size']),
            ('DT_INIT_ARRAYSZ', 24),
        ))

    def get_section_by_name(self, name):
        if name == '.preinit_array':
            return self.section
        if name == '.dynamic':
            return self
        return None

    def iter_tags(self):
        return iter(SimpleNamespace(entry=SimpleNamespace(d_tag=name, d_val=value))
                    for name, value in self.tags)


class LinkedRiscvPreinitTests(unittest.TestCase):
    def address(self, name):
        self.assertEqual(name, 'load_gp')
        return LOAD_GP

    def test_actual_address_alignment_and_one_load_gp_entry_survive_extra_callbacks(self):
        section = PreinitSection(words=(0x10800, LOAD_GP, 0x10900))
        elf = PreinitELF(section)
        before = section.data()
        self.assertEqual(validate_rv_preinit(elf, self.address),
                         {'address': PREINIT_ADDRESS, 'size': 24, 'load_gp': LOAD_GP})
        # A declared alignment of one is accepted when the loader address is aligned.
        self.assertEqual(section['sh_addralign'], 1)
        self.assertEqual(section.data(), before)

    def test_missing_mistyped_empty_or_misaligned_section_refuses(self):
        for section in (
            None,
            PreinitSection(sh_type='SHT_PROGBITS'),
            PreinitSection(words=()),
            PreinitSection(address=PREINIT_ADDRESS + 1),
            PreinitSection(sh_size=7),
        ):
            with self.subTest(section=section), self.assertRaisesRegex(
                    ValueError, 'preinit array is missing or misaligned'):
                validate_rv_preinit(PreinitELF(section, tags=[]), self.address)

    def test_dynamic_tags_must_describe_the_exact_preinit_section(self):
        valid = [('DT_PREINIT_ARRAY', PREINIT_ADDRESS), ('DT_PREINIT_ARRAYSZ', 8)]
        invalid = ([], valid[:1], valid[1:],
                   [('DT_PREINIT_ARRAY', PREINIT_ADDRESS + 8), valid[1]],
                   [valid[0], ('DT_PREINIT_ARRAYSZ', 16)])
        for tags in invalid:
            with self.subTest(tags=tags), self.assertRaisesRegex(
                    ValueError, 'dynamic preinit tags do not describe'):
                validate_rv_preinit(PreinitELF(PreinitSection(), tags=tags), self.address)

    def test_missing_or_repeated_load_gp_slot_refuses(self):
        for words in ((0x10800,), (LOAD_GP, LOAD_GP), (LOAD_GP, 0x10800, LOAD_GP)):
            with self.subTest(words=words), self.assertRaisesRegex(
                    ValueError, 'load_gp preinit entry is not retained once'):
                validate_rv_preinit(PreinitELF(PreinitSection(words=words)), self.address)


if __name__ == '__main__':
    unittest.main()
