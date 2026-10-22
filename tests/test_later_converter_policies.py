"""S2/S3 composition regressions using full imported production functions.

No AST extraction, no copied policy predicates, no target execution. Synthetic
symbol metadata is input to actual closure/export/cache-policy implementations;
these tests do not claim a complete ELF lift or end-to-end CLI qualification.
"""
import argparse
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.sharedlib import convert as converter
from experiments.reusable_libraries import rewrite_components as driver


def callback(**updates):
    result = {
        'name': 'application_callback', 'type': 'STT_FUNC', 'binding': 'STB_WEAK',
        'visibility': 'STV_DEFAULT', 'section': 1, 'address': 0x1000, 'size': 4,
    }
    result.update(updates)
    return result


def closure(lookup=False):
    common = {
        'machine': 'EM_RISCV', 'elf_flags': 5, 'riscv_profile': 'lp64d',
        'versions': [], 'version_definitions': [], 'symbolic_lookup': False,
        'static_symbols': [], 'allow_executable_weak_callbacks': True,
        'allow_runtime_symbol_lookup': lookup,
        'weak_callback_closure_validated': False, 'entry': 0,
    }
    executable = dict(common, path='/inputs/main', role='executable', soname=None,
                      needed=['libselected.so', 'libc.so.6'], sha256='1' * 64,
                      symbols=[callback()], executable_weak_callbacks=['application_callback'])
    selected = dict(common, path='/inputs/libselected.so', role='selected',
                    soname='libselected.so', needed=['libc.so.6'], sha256='2' * 64,
                    symbols=[callback(section='SHN_UNDEF', type='STT_NOTYPE', address=0, size=0)],
                    executable_weak_callbacks=['application_callback'])
    external = dict(common, path='/inputs/libc.so.6', role='external', soname='libc.so.6',
                    needed=[], sha256='3' * 64, symbols=[],
                    executable_weak_callbacks=[], allow_runtime_symbol_lookup=False)
    # No mutable list is shared across role records.
    return copy.deepcopy(executable), [copy.deepcopy(selected)], [copy.deepcopy(external)]


class ComposedWeakCallbackTests(unittest.TestCase):
    def test_closure_guards_real_exports_with_both_lookup_settings(self):
        for lookup in (False, True):
            with self.subTest(lookup=lookup):
                executable, selected, external = closure(lookup)
                with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                    driver.exports(executable, converter)
                self.assertEqual(converter.validate_closure(executable, selected, external), ['libselected.so'])
                self.assertTrue(executable['weak_callback_closure_validated'])
                self.assertTrue(selected[0]['weak_callback_closure_validated'])
                self.assertEqual(driver.export_bindings(executable, selected, external, converter),
                                 [('application_callback', 'executable')])
                self.assertEqual(executable['symbols'][0]['binding'], 'STB_WEAK')
                ctx = {'bindings': [('application_callback', 'executable')],
                       'selected_libraries': [('libselected.so', '2' * 64)]}
                self.assertEqual(driver.component_bindings(selected[0], converter, ctx), ctx['bindings'])
                selected[0]['weak_callback_closure_validated'] = False
                with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                    driver.exports(selected[0], converter)

    def test_revalidation_clears_prior_success_and_refuses_conflicting_provider(self):
        for lookup in (False, True):
            for where in ('dynamic', 'private'):
                with self.subTest(lookup=lookup, where=where):
                    executable, selected, external = closure(lookup)
                    converter.validate_closure(executable, selected, external)
                    field = 'symbols' if where == 'dynamic' else 'static_symbols'
                    external[0][field].append(callback(binding='STB_GLOBAL'))
                    with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                        converter.validate_closure(executable, selected, external)
                    self.assertFalse(executable['weak_callback_closure_validated'])
                    self.assertFalse(selected[0]['weak_callback_closure_validated'])

    def test_complete_closure_refuses_bad_import_shapes_and_missing_optin(self):
        for change in (
            {'binding': 'STB_GLOBAL'}, {'type': 'STT_OBJECT'},
            {'visibility': 'STV_HIDDEN'}, {'version': 'VERSION_1'},
        ):
            executable, selected, external = closure()
            selected[0]['symbols'][0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                converter.validate_closure(executable, selected, external)
        executable, selected, external = closure()
        selected[0]['allow_executable_weak_callbacks'] = False
        with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
            converter.validate_closure(executable, selected, external)

    def test_actual_reconstruction_guard_runs_before_creating_output(self):
        executable, _, _ = closure()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(converter.Unsupported, 'WEAK_BINDING'):
                converter.reconstruct(executable, argparse.Namespace(), directory)
            self.assertEqual(list(directory.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
