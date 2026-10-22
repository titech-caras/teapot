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


class ComposedConverterPolicyTests(unittest.TestCase):
    def source(self, lookup=False):
        return dict(path='/inputs/libselected.so', sha256='2' * 64, role='selected',
                    machine='EM_RISCV', entry=0, allow_runtime_symbol_lookup=lookup,
                    allow_executable_weak_callbacks=True,
                    executable_weak_callbacks=['application_callback'],
                    weak_callback_closure_validated=True)

    def args(self, lookup=False):
        return argparse.Namespace(
            allow_runtime_symbol_lookup=lookup, allow_executable_weak_callbacks=True,
            allow_ambiguous_data_pointers=False,
            cache_context={'allow_runtime_symbol_lookup': lookup,
                           'allow_executable_weak_callbacks': True,
                           'allow_ambiguous_data_pointers': False, 'executable': 'caller'},
            tool_identities={'ddisasm': {'sha256': 'frontend'}},
            source_provenance_data={}, jobs=1)

    def test_lookup_and_callback_identity_survive_the_composed_cache_recipe(self):
        ordinary, lifted = [], []
        for lookup in (False, True):
            source, args = self.source(lookup), self.args(lookup)
            original = copy.deepcopy(args.cache_context)
            recipe = converter.ordinary_object_recipe(source, args.cache_context)
            ordinary.append(converter.content_key(recipe))
            lifted.append(converter.content_key(converter.recovered_ir_recipe(source, args)))
            self.assertIs(recipe['context']['allow_runtime_symbol_lookup'], lookup)
            self.assertEqual(recipe['executable_weak_callbacks'], ['application_callback'])
            self.assertNotIn('executable', recipe['context'])
            self.assertEqual(args.cache_context, original)
            changed = dict(source, executable_weak_callbacks=['another_callback'])
            self.assertNotEqual(ordinary[-1], converter.content_key(
                converter.ordinary_object_recipe(changed, args.cache_context)))
        self.assertNotEqual(ordinary[0], ordinary[1])
        self.assertNotEqual(lifted[0], lifted[1])

    def test_ordinary_cache_rejects_nonboolean_and_mismatched_lookup_policy(self):
        source = self.source(True)
        for policy in (False, None, 0, 1, 'true'):
            ctx = dict(self.args(True).cache_context, allow_runtime_symbol_lookup=policy)
            with self.subTest(policy=policy), self.assertRaisesRegex(
                    converter.Unsupported, 'RUNTIME_SYMBOL_LOOKUP'):
                converter.ordinary_object_recipe(source, ctx)
        legacy = self.args(False).cache_context
        legacy.pop('allow_runtime_symbol_lookup')
        self.assertFalse(converter.ordinary_object_recipe(self.source(False), legacy)
                         ['context']['allow_runtime_symbol_lookup'])
        self.assertNotIn('allow_runtime_symbol_lookup', legacy)

    def test_actual_reconstruct_rejects_request_context_mismatch_before_lift(self):
        source, args = self.source(True), self.args(False)
        args.cache_context['allow_runtime_symbol_lookup'] = True
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(converter, 'run', side_effect=AssertionError('must not lift')) as run:
            with self.assertRaisesRegex(converter.Unsupported, 'request/cache policy mismatch'):
                converter.reconstruct(source, args, Path(temporary))
            run.assert_not_called()

    def test_actual_inspect_rejects_malformed_options_before_opening_elf(self):
        for key in ('allow_runtime_symbol_lookup', 'allow_executable_weak_callbacks'):
            for bad in (None, 0, 1, 'true', [], {}):
                with self.subTest(key=key, bad=bad), self.assertRaisesRegex(
                        converter.Unsupported, 'explicit boolean'):
                    converter.inspect('/must-not-open', 'executable', **{key: bad})
        for bad in ('.L_constant', ('.L_constant',), [''], ['b', 'a'], ['a', 'a'], [1], True):
            with self.subTest(names=bad), self.assertRaisesRegex(converter.Unsupported, 'canonical list'):
                converter.inspect('/must-not-open', 'executable', allow_integral_constant_symbols=bad)
        with self.assertRaisesRegex(converter.Unsupported, 'explicit callback opt-in'):
            converter.inspect('/must-not-open', 'selected',
                              executable_weak_callbacks=['application_callback'])

    def test_named_integral_permission_does_not_admit_other_diagnostics(self):
        warning = 'WARNING: Found integral symbol pointing into existing block: .L_constant\n'
        for lookup in (False, True):
            source = dict(self.source(lookup), role='executable', entry=1)
            with self.subTest(lookup=lookup):
                with self.assertRaises(converter.Unsupported):
                    converter.validate_frontend_diagnostics(None, source, warning)
                source['allow_integral_constant_symbols'] = ['.L_constant']
                rows = converter.validate_frontend_diagnostics(None, source, warning)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['category'], 'integral-constant')
                self.assertEqual(rows[0]['symbol'], '.L_constant')
                self.assertFalse(rows[0]['constant_value_preservation_claimed'])
                for bad in (
                    warning.replace('.L_constant', '.L_other'),
                    warning.replace('.L_constant', '.L_constant trailing'),
                    'WARNING: unrelated\n', 'ERROR: unrelated\n',
                ):
                    with self.subTest(diagnostic=bad), self.assertRaises(converter.Unsupported):
                        converter.validate_frontend_diagnostics(None, source, bad)


if __name__ == '__main__':
    unittest.main()
