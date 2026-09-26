"""Debug return contracts are object-bound, narrow and fail closed."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from elftools.elf.elffile import ELFFile

from tools.sharedlib.aarch64_return_abi import (SECTION, annotate_assembly, bind, digest, produce)
from teapot.utils.return_abi import POINTER_RETURNS, SCHEMA, has_pointer_return_contract


class AArch64ReturnAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for executable in ('aarch64-linux-gnu-gcc', 'ddisasm', 'qemu-aarch64'):
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
        cls.run_command([os.environ.get('PPRINTER_PATH', 'gtirb-pprinter'), '--ir', cls.root / 'original.gtirb',
                         '--asm', cls.root / 'plain.S', '--policy', 'complete', '--shared', 'no'])
        cls.plain = (cls.root / 'plain.S').read_text()
        (cls.root / 'marked.S').write_text(annotate_assembly(cls.plain, cls.manifest))
        for variant in ('plain', 'marked'):
            cls.run_command(['aarch64-linux-gnu-gcc', *cls.flags, '-x', 'assembler', cls.root / (variant + '.S'),
                             '-o', cls.root / variant])
        cls.run_command(['ddisasm', cls.root / 'marked', '--ir', cls.root / 'linked.gtirb', '-j', '1'])
        if Path('/out').is_dir():
            shutil.copytree(cls.root, '/out/native-fixture')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def run_command(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True)
        if result.returncode:
            raise AssertionError(str(argv) + '\n' + result.stderr.decode(errors='replace'))
        return result

    def current_ir(self):
        return gtirb.IR.load_protobuf(self.root / 'linked.gtirb')

    def test_native_roundtrip_loaded_bytes_and_execution_unchanged(self):
        def allocated(path):
            with path.open('rb') as stream:
                elf = ELFFile(stream)
                return {s.name: (s['sh_addr'], s['sh_size'], s['sh_flags'],
                                None if s.name == '.note.gnu.build-id' else s.data())
                        for s in elf.iter_sections() if s['sh_flags'] & 2}
        self.assertEqual(allocated(self.root / 'plain'), allocated(self.root / 'marked'))
        for variant in ('original', 'plain', 'marked'):
            result = self.run_command(['qemu-aarch64', self.root / variant])
            self.assertEqual(result.stdout, b'')
        ir = self.current_ir()
        result = bind(self.root / 'marked', self.manifest, ir)
        self.assertEqual(result['bound_pointer_returns'], 1)
        module = ir.modules[0]
        function = next(iter(module.aux_data[POINTER_RETURNS].data))
        self.assertTrue(has_pointer_return_contract(module, function))
        self.assertEqual(module.aux_data['functionNames'].data[function].name, 'pointer_result')

    def test_aggregate_and_integer_returns_remain_unknown(self):
        ir = self.current_ir()
        bind(self.root / 'marked', self.manifest, ir)
        m = ir.modules[0]
        for key, name in m.aux_data['functionNames'].data.items():
            if name.name in ('pair_result', 'integer_result'):
                self.assertFalse(has_pointer_return_contract(m, key))

    def test_absent_link_records_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing, loaded or malformed'):
            bind(self.root / 'plain', self.manifest, self.current_ir())

    def test_changed_manifest_identity_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['records'][0]['return_kind'] = 'pretend-aggregate-is-pointer'
        with self.assertRaisesRegex(ValueError, 'altered ABI records'):
            bind(self.root / 'marked', manifest, self.current_ir())

    def test_new_manifest_digest_cannot_match_an_old_link_record(self):
        manifest = copy.deepcopy(self.manifest)
        row = manifest['records'][0]
        row['source_elf_sha256'] = 'e' * 64
        row['id'] = digest({k: v for k, v in row.items() if k != 'id'})
        with self.assertRaisesRegex(ValueError, 'unknown/duplicate ABI'):
            bind(self.root / 'marked', manifest, self.current_ir())

    def test_edited_function_bytes_cannot_reuse_a_contract(self):
        ir = self.current_ir()
        bind(self.root / 'marked', self.manifest, ir)
        m = ir.modules[0]
        function = next(iter(m.aux_data[POINTER_RETURNS].data))
        block = next(iter(m.aux_data['functionEntries'].data[function]))
        block.byte_interval.contents[block.offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'stale pointer-return'):
            has_pointer_return_contract(m, function)

    def test_changed_current_ir_rejected_before_annotation(self):
        ir = self.current_ir()
        block = next(ir.modules[0].symbols_named('pointer_result')).referent
        block.byte_interval.contents[block.offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'bytes disagree'):
            bind(self.root / 'marked', self.manifest, ir)
        self.assertNotIn(POINTER_RETURNS, ir.modules[0].aux_data)

    def test_extra_return_is_not_treated_as_alignment_padding(self):
        ir = self.current_ir()
        module = ir.modules[0]
        entry = next(module.symbols_named('pointer_result')).referent
        owner = next(k for k, v in module.aux_data['functionEntries'].data.items() if entry in v)
        padding = next(b for b in module.aux_data['functionBlocks'].data[owner] if b is not entry)
        self.assertEqual(bytes(padding.contents), bytes.fromhex('1f2003d5'))
        padding.byte_interval.contents[padding.offset:padding.offset + 4] = bytes.fromhex('c0035fd6')
        with self.assertRaisesRegex(ValueError, 'membership crosses'):
            bind(self.root / 'marked', self.manifest, ir)
        self.assertNotIn(POINTER_RETURNS, module.aux_data)

    def test_missing_or_duplicate_printed_endpoint_rejected(self):
        line = next(line for line in self.plain.splitlines() if '.size pointer_result,' in line)
        for assembly in (self.plain.replace(line, ''), self.plain + '\n' + line + '\n'):
            with self.assertRaisesRegex(ValueError, 'ABI function endpoint'):
                annotate_assembly(assembly, self.manifest)

if __name__ == '__main__':
    unittest.main()
