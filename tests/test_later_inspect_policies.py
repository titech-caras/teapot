"""S2/S3 complete inspect() admission with an ELF reader boundary double.

The actual inspect, symbol conversion, closure predicates, and result recording
are imported. Only ELFFile supplies synthetic section/header records; no AST
fragments or replacement policy implementation are used. This is a parser-boundary
unit test, not qualification of a real ELF, toolchain, or workload.
"""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.sharedlib import convert as converter


class Symbol(dict):
    def __init__(self, name, *, section='SHN_UNDEF', binding='STB_GLOBAL', kind='STT_FUNC',
                 visibility='STV_DEFAULT', address=0, size=0):
        super().__init__(st_info={'type': kind, 'bind': binding},
                         st_other={'visibility': visibility},
                         st_shndx=section, st_value=address, st_size=size)
        self.name = name


class PolicyELF(dict):
    elfclass = 64
    little_endian = True

    def __init__(self, role, symbols):
        super().__init__(e_machine='EM_X86_64', e_flags=0, e_entry=0x1000,
                         e_type='ET_EXEC' if role == 'executable' else 'ET_DYN')
        start = Symbol('_start', section=1, address=0x1000, size=4)
        self.tables = {
            '.dynsym': SimpleNamespace(iter_symbols=lambda: iter(symbols)),
            '.symtab': SimpleNamespace(iter_symbols=lambda: iter((start,))),
            '.dynamic': SimpleNamespace(iter_tags=lambda: iter(())),
        }

    def get_section_by_name(self, name):
        return self.tables.get(name)

    def iter_sections(self):
        return iter(())

    def iter_segments(self):
        interpreter = converter.ARCHITECTURES['EM_X86_64']['interpreter']
        class Segment(dict):
            def data(self):
                return interpreter.encode() + b'\0'
        return iter((Segment(p_type='PT_INTERP', p_flags=0),))


class CompleteInspectPolicyTests(unittest.TestCase):
    def invoke(self, role, symbols, **options):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'reader-boundary-input'
            path.write_bytes(b'input bytes are hashed by production inspect')
            with patch.object(converter, 'ELFFile', return_value=PolicyELF(role, symbols)):
                return converter.inspect(path, role, **options)

    def test_weak_callback_and_lookup_grants_remain_independent_when_composed(self):
        symbols = [
            Symbol('application_callback', binding='STB_WEAK', section=1, address=0x2000, size=4),
            Symbol('dlsym'),
        ]
        for callbacks, lookup in ((False, False), (False, True), (True, False)):
            with self.subTest(callbacks=callbacks, lookup=lookup), self.assertRaises(converter.Unsupported):
                self.invoke('executable', symbols, allow_executable_weak_callbacks=callbacks,
                            allow_runtime_symbol_lookup=lookup)
        accepted = self.invoke(
            'executable', symbols, allow_executable_weak_callbacks=True,
            allow_runtime_symbol_lookup=True, allow_integral_constant_symbols=['.L_constant'])
        self.assertEqual(accepted['executable_weak_callbacks'], ['application_callback'])
        self.assertFalse(accepted['weak_callback_closure_validated'])
        self.assertTrue(accepted['allow_runtime_symbol_lookup'])
        self.assertEqual(accepted['allow_integral_constant_symbols'], ['.L_constant'])
        selected = self.invoke(
            'selected', [Symbol('application_callback', binding='STB_WEAK', kind='STT_NOTYPE')],
            allow_executable_weak_callbacks=True,
            executable_weak_callbacks=accepted['executable_weak_callbacks'],
            allow_runtime_symbol_lookup=True)
        self.assertEqual(selected['executable_weak_callbacks'], ['application_callback'])
        self.assertFalse(selected['weak_callback_closure_validated'])

if __name__ == '__main__':
    unittest.main()
