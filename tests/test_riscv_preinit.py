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


if __name__ == '__main__':
    unittest.main()
