"""Raw adaptive-window bytes survive real printing, relaxation and linking."""
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile
from teapot.preprocess.fault_windows import add_fault_windows


@unittest.skipUnless(shutil.which('gtirb-pprinter') and shutil.which('gcc'), 'printer/compiler required')
class FaultWindowByteTests(unittest.TestCase):
    def test_raw_windows_and_page_tail_with_a_relaxing_branch(self):
        from test_fault_windows import FaultWindowEmitterTests
        ordinary = bytes.fromhex('488b074889c1c3')
        short = bytes.fromhex('488b07c3')
        relaxing = bytes.fromhex('488b074889c10f8500000000c3')
        for code in (ordinary, short, relaxing):
            with self.subTest(code=code.hex()), tempfile.TemporaryDirectory() as directory:
                module, section, bounds = FaultWindowEmitterTests().make_module(code)
                if code == relaxing:
                    interval = next(iter(section.byte_intervals))
                    block = next(b for b in interval.blocks if isinstance(b, gtirb.CodeBlock) and b.size)
                    block.size -= 1
                    target = gtirb.CodeBlock(size=1, offset=len(code)-1, byte_interval=interval)
                    symbol = gtirb.Symbol(name='relaxed_tail', payload=target, module=module)
                    next(iter(module.aux_data['functionBlocks'].data.values())).add(target)
                    interval.symbolic_expressions[8] = gtirb.SymAddrConst(0, symbol)
                    module.aux_data['symbolicExpressionSizes'] = gtirb.AuxData(
                        {gtirb.Offset(interval, 8): 4}, 'mapping<Offset,uint64_t>')
                add_fault_windows(module, section, bounds)
                interval = next(iter(section.byte_intervals))
                tail = next(b for b in interval.blocks if isinstance(b, gtirb.DataBlock)
                            and b.size and b.offset+b.size == interval.size)
                self.assertEqual(interval.size % 4096, 0)
                self.assertEqual(bytes(interval.contents[tail.offset:]), b'\xcc' * tail.size)
                root = Path(directory)
                module.ir.save_protobuf(root/'input.gtirb')
                (root/'runtime.S').write_text('''
.text
.global restore_checkpoint_SIGSEGV
restore_checkpoint_SIGSEGV: ret
.section teapot_protected_bss,"aw",@nobits
.balign 8
.global teapot_fault_low_bound
teapot_fault_low_bound: .zero 8
.section .note.GNU-stack,"",@progbits
''')
                for command in (["gtirb-pprinter", "--ir", "input.gtirb", "--asm", "output.S", "--shared", "no"],
                                ["gcc", "-nostdlib", "-no-pie", "output.S", "runtime.S", "-Wl,-e,window_test",
                                 "-Wl,-z,separate-code", "-o", "linked"]):
                    result = subprocess.run(command, cwd=root, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                with (root/'linked').open('rb') as stream:
                    elf = ELFFile(stream)
                    copy = elf.get_section_by_name('.teapot_transient')
                    data = copy.data()
                    self.assertEqual((copy['sh_addr'] % 4096, (copy['sh_addr']+copy['sh_size']) % 4096), (0, 0))
                    self.assertIn(b'\xcc' * 64, data[-128:])
                    table = elf.get_section_by_name('teapot_fault_sites')
                    records = table.data()
                    header_size, = struct.unpack_from('<H', records, 6)
                    count, = struct.unpack_from('<I', records, 12)
                    self.assertEqual(count, 1)
                    row = records[header_size:]
                    length, = struct.unpack_from('<H', row, 12)
                    expected = bytes.fromhex('488b8700000000') if code == short else ordinary[:6]
                    self.assertEqual(row[64:64+length], expected)
                    for offset in (0, 8):
                        relative, = struct.unpack_from('<i', row, offset)
                        pc = table['sh_addr'] + header_size + offset + relative
                        self.assertEqual(data[pc-copy['sh_addr']:pc-copy['sh_addr']+length], expected)
                    if code == relaxing:
                        target, = elf.get_section_by_name('.symtab').get_symbol_by_name('relaxed_tail')
                        at = target['st_value']-copy['sh_addr']
                        self.assertEqual(data[at-2:at+1], b'\x75\x00\xc3')
