"""Debug return contracts are object-bound, narrow and fail closed."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile

from tools.sharedlib.aarch64_return_abi import (
    produce, dwarf_pointer_definitions)


class AArch64ReturnAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for executable in ('aarch64-linux-gnu-gcc', 'ddisasm'):
            if shutil.which(executable) is None:
                raise unittest.SkipTest('required native gate tool missing: ' + executable)
        cls.temporary = tempfile.TemporaryDirectory(prefix='aarch64-return-abi-')
        cls.root = Path(cls.temporary.name)
        source = cls.root / 'fixture.c'
        source.write_text('''
static int value, other;
struct pair { void *a, *b; };
__attribute__((noinline)) void *pointer_result(void) { return &value; }
__attribute__((noinline)) struct pair pair_result(void) {
    struct pair p = { &value, &other }; return p;
}
__attribute__((noinline)) long integer_result(void) { return 43; }
void _start(void) {
    long failed = pointer_result() != &value || pair_result().b != &other || integer_result() != 43;
    register long status __asm__("x0") = failed;
    register long call __asm__("x8") = 93;
    __asm__ volatile("svc #0" : "+r"(status) : "r"(call) : "memory");
    __builtin_unreachable();
}
''')
        cls.flags = ['-nostdlib', '-static', '-no-pie', '-Wl,--build-id=sha1', '-Wa,--fatal-warnings']
        cls.run_command(['aarch64-linux-gnu-gcc', *cls.flags, '-O1', '-g', '-fno-inline',
                         '-fno-ipa-cp', '-fno-ipa-sra', source, '-o', cls.root / 'original'])
        cls.run_command(['ddisasm', cls.root / 'original', '--ir', cls.root / 'original.gtirb', '-j', '1'])
        cls.manifest = produce(cls.root / 'original', cls.root / 'original.gtirb')
        if {r['name'] for r in cls.manifest['records']} != {'pointer_result'}:
            raise AssertionError(cls.manifest)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def run_command(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True)
        if result.returncode:
            raise AssertionError(str(argv) + '\n' + result.stderr.decode(errors='replace'))
        return result

    def test_linked_emit_relocs_does_not_relocate_dwarf_twice(self):
        binary = self.root / 'retained-relocations'
        self.run_command(['aarch64-linux-gnu-gcc', *self.flags, '-O1', '-g', '-fno-inline',
                          '-fno-ipa-cp', '-fno-ipa-sra', '-Wl,--emit-relocs',
                          self.root / 'fixture.c', '-o', binary])
        with binary.open('rb') as stream:
            elf = ELFFile(stream)
            self.assertIsNotNone(elf.get_section_by_name('.rela.eh_frame'))
            rows = dwarf_pointer_definitions(elf)
        self.assertEqual({r['name'] for r in rows}, {'pointer_result'})
        self.assertEqual(rows[0]['address'], self.manifest['records'][0]['address'])

    def test_only_dwarf_proved_pointer_returns_are_produced(self):
        self.assertEqual({row['name'] for row in self.manifest['records']}, {'pointer_result'})

    def test_changed_original_ir_bytes_are_refused(self):
        ir = gtirb.IR.load_protobuf(self.root / 'original.gtirb')
        symbol = next(ir.modules[0].symbols_named('pointer_result'))
        block = symbol.referent
        interval = block.byte_interval
        interval.contents[block.offset] ^= 1
        path = self.root / 'changed.gtirb'
        ir.save_protobuf(path)
        result = produce(self.root / 'original', path)
        self.assertEqual(result['records'], [])
        self.assertIn(['pointer_result', 'original IR function bytes changed'], result['rejected'])


if __name__ == '__main__':
    unittest.main()
