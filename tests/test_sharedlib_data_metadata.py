from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from tools.sharedlib import convert as converter


class ExecutableDataMetadataTests(unittest.TestCase):
    @unittest.skipUnless(all(shutil.which(x) for x in ('gcc', 'ld', 'ar', 'ddisasm', 'gtirb-pprinter')),
                         'native compiler, linker, frontend and printer required')
    def test_converter_preserves_relocations_for_a_fresh_lift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'library.c'
            source.write_text('int value = 42; int *pointer = &value;\n'
                              'int api(void) { return *pointer; }\n')
            library = root / 'libprobe.so'
            subprocess.run(['gcc', '-shared', '-fPIC', '-O1', '-nostdlib',
                            str(source), '-Wl,-soname,libprobe.so', '-o', str(library)],
                           check=True, capture_output=True)
            source = root / 'main.c'
            source.write_text('extern int api(void); int main(void) { return api() != 42; }\n'
                              '__asm__(".text\\n.globl _start\\n_start: call main\\n'
                              'mov %eax,%edi\\ncall exit@PLT\\n");\n')
            original = root / 'original'
            subprocess.run(['gcc', '-O1', '-fPIC', '-no-pie', '-nostartfiles',
                            '-Wl,--emit-relocs', str(source), '-L' + str(root), '-lprobe',
                            '-Wl,-rpath,' + str(root), '-o', str(original)],
                           check=True, capture_output=True)
            external = []
            for name in ('libc.so.6', 'ld-linux-x86-64.so.2'):
                path = subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()
                external += ['--external', path]
            output = root / 'converted'
            converted = subprocess.run([sys.executable, converter.__file__, '--executable', str(original),
                            '--select', str(library), *external, '--out', str(output),
                            '--ddisasm', shutil.which('ddisasm'),
                            '--pprinter', shutil.which('gtirb-pprinter'), '--jobs', '1',
                            '--preserve-weak-imports'], capture_output=True, text=True)
            self.assertEqual(converted.returncode, 0, converted.stderr)
            linked = output / 'monolith'
            subprocess.run([str(original)], check=True, capture_output=True)
            subprocess.run([str(linked)], check=True, capture_output=True)
            with linked.open('rb') as stream:
                elf = ELFFile(stream)
                table = elf.get_section_by_name('.symtab')
                pointer = table.get_symbol_by_name('pointer')[0]['st_value']
                # The ordinary converter's output is lifted again. Its data
                # pointers must remain provable without guessing from integers.
                self.assertTrue(any(
                    rel['r_offset'] == pointer
                    for section in elf.iter_sections()
                    if isinstance(section, RelocationSection)
                    and elf.get_section(section['sh_link']).name == '.symtab'
                    for rel in section.iter_relocations()))
            lifted = root / 'second.gtirb'
            subprocess.run(['ddisasm', str(linked), '--ir', str(lifted), '-j', '1'],
                           check=True, capture_output=True)
            module = gtirb.IR.load_protobuf(lifted).modules[0]
            block = next(module.symbols_named('pointer')).referent
            self.assertIn(block.offset, block.byte_interval.symbolic_expressions)

    def fixture(self):
        module = gtirb.Module(name='fixture', isa=gtirb.Module.ISA.X64,
                              file_format=gtirb.Module.FileFormat.ELF)
        ir = gtirb.IR(modules=[module])
        section = gtirb.Section(name='.text', module=module,
            flags={gtirb.Section.Flag.Readable, gtirb.Section.Flag.Executable,
                   gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized})
        interval = gtirb.ByteInterval(address=4096, contents=b'\xc3\x90\x7c\xfc\x90', section=section)
        code = gtirb.CodeBlock(offset=0, size=1, byte_interval=interval)
        data = gtirb.DataBlock(offset=1, size=4, byte_interval=interval)
        module.aux_data['elfSymbolInfo'] = gtirb.AuxData({},
            'mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>')
        return ir, module, interval, code, data

    def test_metadata_does_not_change_bytes_or_code(self):
        ir, module, interval, code, data = self.fixture()
        before = bytes(interval.contents)
        evidence = converter.preserve_executable_data_blocks(module)
        self.assertEqual(bytes(interval.contents), before)
        self.assertEqual(list(module.code_blocks), [code])
        self.assertEqual([(e['address'], e['size']) for e in evidence], [(4097, 4)])
        symbol = next(module.symbols_named(evidence[0]['name']))
        self.assertIs(symbol.referent, data)
        self.assertEqual(module.aux_data['elfSymbolInfo'].data[symbol],
                         (4, 'OBJECT', 'LOCAL', 'DEFAULT', 0))

    def test_nonexecutable_data_is_not_annotated(self):
        ir, module, interval, code, data = self.fixture()
        interval.section.flags.discard(gtirb.Section.Flag.Executable)
        self.assertEqual(converter.preserve_executable_data_blocks(module), [])

    def test_overlapping_code_data_is_rejected(self):
        ir, module, interval, code, data = self.fixture()
        gtirb.CodeBlock(offset=2, size=1, byte_interval=interval)
        with self.assertRaisesRegex(converter.Unsupported, 'AMBIGUOUS_RECOVERED_DATA'):
            converter.preserve_executable_data_blocks(module)

    @unittest.skipUnless(all(shutil.which(x) for x in ('gcc', 'ddisasm', 'gtirb-pprinter')),
                         'native compiler, frontend and printer required')
    def test_data_classification_survives_relink_and_second_lift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.S'
            source.write_text('''
                .text
                .globl read_pool
                .type read_pool,@function
            read_pool:
                movzbl pool(%rip),%eax
                ret
                .size read_pool,.-read_pool
                .p2align 4
                .type pool,@object
            pool:
                .byte 0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38
                .byte 0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,0x7c,0xe3
                .size pool,.-pool
                .section .note.GNU-stack,"",@progbits
            ''')
            original = root / 'input.so'
            subprocess.run(['gcc', '-shared', '-nostdlib', str(source), '-o', str(original)],
                           check=True, capture_output=True)
            first = root / 'first.gtirb'
            subprocess.run(['ddisasm', str(original), '--ir', str(first), '-j', '1'],
                           check=True, capture_output=True)
            ir = gtirb.IR.load_protobuf(first)
            module = ir.modules[0]
            pool = next(module.symbols_named('pool'))
            info = module.aux_data['elfSymbolInfo'].data
            # Reproduce an inferred pool with a label but no surviving ELF type.
            info[pool] = (0, 'NOTYPE', 'LOCAL', 'DEFAULT', info[pool][4])
            evidence = converter.preserve_executable_data_blocks(module)
            expected = next(e for e in evidence if e['address'] == pool.referent.address)
            prepared, assembly = root / 'prepared.gtirb', root / 'output.S'
            ir.save_protobuf(prepared)
            subprocess.run(['gtirb-pprinter', '--ir', str(prepared), '--asm', str(assembly),
                            '--shared', 'no', '--policy', 'complete'], check=True, capture_output=True)
            main = root / 'main.c'
            main.write_text('extern int read_pool(void); int main(void) { return read_pool() != 0x52; }')
            linked = root / 'linked'
            subprocess.run(['gcc', '-no-pie', '-Wl,--emit-relocs',
                            str(assembly), str(main), '-o', str(linked)],
                           check=True, capture_output=True)
            subprocess.run([str(linked)], check=True, capture_output=True)
            with linked.open('rb') as stream:
                elf = ELFFile(stream)
                symbol = elf.get_section_by_name('.symtab').get_symbol_by_name(expected['name'])[0]
                self.assertEqual(symbol['st_info']['type'], 'STT_OBJECT')
                self.assertEqual(symbol['st_info']['bind'], 'STB_LOCAL')
                start, size = symbol['st_value'], symbol['st_size']
                self.assertEqual(size, expected['size'])
            second = root / 'second.gtirb'
            subprocess.run(['ddisasm', str(linked), '--ir', str(second), '-j', '1'],
                           check=True, capture_output=True)
            recovered = gtirb.IR.load_protobuf(second).modules[0]
            self.assertFalse(list(recovered.code_blocks_on(range(start, start + size))))
            blocks = list(recovered.byte_blocks_on(range(start, start + size)))
            self.assertTrue(blocks)
            self.assertTrue(all(isinstance(b, gtirb.DataBlock) for b in blocks))


if __name__ == '__main__':
    unittest.main()
