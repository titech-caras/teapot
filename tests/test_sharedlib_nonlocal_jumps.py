"""Nonlocal control-flow families require the explicit conversion opt-in."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.sharedlib import convert


class NonlocalJumpTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('gcc'), 'gcc unavailable')
    def test_real_elf_imports_require_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('longjmp', '_longjmp', 'siglongjmp', '__longjmp', '__siglongjmp',
                         '__longjmp_chk', '__libc_longjmp', '__libc_siglongjmp',
                         'setcontext', '__setcontext', 'swapcontext', '__swapcontext',
                         '__cxa_throw', '_Unwind_Resume'):
                with self.subTest(name=name):
                    source = root / 'call.c'
                    source.write_text('extern void transfer(void) __asm__("%s");\n'
                                      'void entry(void) { transfer(); }\n' % name)
                    library = root / 'libcall.so'
                    subprocess.run(['gcc', '-shared', '-fPIC', '-nostdlib', str(source),
                                    '-Wl,-soname,libcall.so', '-o', str(library)],
                                   check=True, capture_output=True)
                    with self.assertRaisesRegex(convert.Unsupported, 'NONLOCAL_UNWIND.*' + name):
                        convert.inspect(library, 'selected')
                    if name in ('__cxa_throw', '_Unwind_Resume'):
                        with self.assertRaisesRegex(convert.Unsupported, 'NONLOCAL_UNWIND'):
                            convert.inspect(library, 'selected', preserve_nonlocal_jumps=True)
                    else:
                        self.assertTrue(convert.inspect(library, 'selected',
                            preserve_nonlocal_jumps=True)['preserve_nonlocal_jumps'])
