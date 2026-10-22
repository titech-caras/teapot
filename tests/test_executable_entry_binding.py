"""One real-ELF positive/negative regression for preserved entry bindings."""
from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from tools.sharedlib import convert
from experiments.reusable_libraries import rewrite_components as driver


class ExecutableEntryBindingTests(unittest.TestCase):
    def test_rdynamic_entry_and_selected_external_entry_import(self):
        output = os.environ.get('ENTRY_TEST_OUTPUT')
        with (nullcontext(output) if output else TemporaryDirectory(prefix='teapot-entry-binding-')) as directory:
            root = Path(directory) if output else Path(directory) / 'fixtures'
            root.mkdir()
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            executable = root / 'driver'
            subprocess.run(['aarch64-linux-gnu-gcc', '-O2', '-g', '-rdynamic', '-no-pie',
                            str(source), '-o', str(executable)], check=True)
            item = convert.inspect(executable, 'executable', preserve_weak_imports=True)
            entry = driver.executable_entry_exports(item, convert)
            self.assertEqual(entry, frozenset({'_start'}))
            bindings = driver.export_bindings(item, [], [], convert)
            self.assertIn(('main', 'executable'), bindings)
            self.assertNotIn(('_start', 'executable'), bindings)
            self.assertNotIn('_start', driver.exports(item, convert))
            self.assertIn('_start', driver.exports(item, convert, functions_only=False))

            importer_source = root / 'entry_import.c'
            importer_source.write_text('extern void _start(void);\nvoid entry_import(void) { _start(); }\n')
            importer_path = root / 'entry_import.so'
            subprocess.run(['aarch64-linux-gnu-gcc', '-O2', '-g', '-shared', '-fPIC',
                            '-Wl,-soname,entry_import.so', str(importer_source), '-o', str(importer_path)],
                           check=True)
            for role in ('selected', 'external'):
                with self.subTest(importer_role=role):
                    importer = convert.inspect(importer_path, role, preserve_weak_imports=True)
                    self.assertTrue(any(symbol['name'] == '_start' and symbol['section'] == 'SHN_UNDEF'
                                        for symbol in importer['symbols']))
                    selected, external = ([importer], []) if role == 'selected' else ([], [importer])
                    with self.assertRaisesRegex(RuntimeError,
                            '^selected/external input imports trusted executable entry: _start$'):
                        driver.export_bindings(item, selected, external, convert)


if __name__ == '__main__':
    unittest.main()
