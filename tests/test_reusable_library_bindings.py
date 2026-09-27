"""Standalone components use the converter's stable versioned link identities."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.sharedlib import convert as converter


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load('reuse_binding_driver', 'experiments/reusable_libraries/rewrite_components.py')


class LibraryBindingTests(unittest.TestCase):
    def test_unrelated_executable_exports_reuse_one_object(self):
        base = dict(section=1, binding='STB_GLOBAL', visibility='STV_DEFAULT', type='STT_FUNC')
        item = dict(role='selected', soname='libtest.so', sha256='same-library',
                    path='/libtest.so', machine='EM_RISCV', application_fdes=[],
                    symbols=[dict(base, name='api'), dict(base, name='callback', section='SHN_UNDEF')])
        context = dict(selected_libraries=[('libtest.so', 'same-library')],
                       bindings=[('api', 'libtest.so'), ('callback', 'executable'),
                                 ('unrelated_A', 'executable')])

        def build(args, converter, item, key, identity, selected, priority, directory):
            self.assertEqual(selected, {'api', 'callback'})
            driver.dump(directory / 'key.json', key)
            (directory / 'component.o').write_bytes(b'one instrumented library object')
            result = {'component_id': identity,
                      'files': {'component.o': driver.sha(directory / 'component.o')}}
            driver.dump(directory / 'component.json', result)
            return result

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(driver, 'build_component', side_effect=build) as builder, \
                patch.object(driver, 'validate_object'):
            args = SimpleNamespace(cache=Path(directory))
            cold = driver.cached_component(args, converter, item, context, set(), 100)
            other = dict(context, bindings=context['bindings'][:2] + [('unrelated_B', 'executable')])
            warm = driver.cached_component(args, converter, item, other, set(), 100)
            self.assertFalse(cold['cache_hit'])
            self.assertTrue(warm['cache_hit'])
            self.assertEqual(cold['cache_path'], warm['cache_path'])
            self.assertEqual(builder.call_count, 1)
            # Moving a referenced callback out of the selected set changes the key.
            external = dict(context, bindings=[('api', 'libtest.so')])
            self.assertNotEqual(driver.component_bindings(item, converter, context),
                                driver.component_bindings(item, converter, external))

    def test_versioned_import_binding_matches_selected_definition(self):
        symbol = dict(name='api', section='SHN_UNDEF', version='V1',
                      version_library='libprovider.so')
        item = dict(role='selected', soname='libcaller.so', resolve_selected_versions=True,
                    symbols=[symbol])
        name = converter.selected_version_name('libprovider.so', 'api', 'V1')
        context = dict(selected_libraries=[('libprovider.so', 'bytes')],
                       bindings=[(name, 'libprovider.so'), ('api', 'executable')])
        self.assertEqual(driver.component_bindings(item, converter, context),
                         [(name, 'libprovider.so')])

    def test_versions_default_aliases_and_data_exports(self):
        base = dict(section=1, binding='STB_GLOBAL', visibility='STV_DEFAULT',
                    type='STT_FUNC', name='api', version_library=None)
        item = dict(role='selected', soname='libtest.so', resolve_selected_versions=True,
                    version_definitions=[dict(name='V1'), dict(name='V2')], symbols=[
                        dict(base, version='V1', version_default=False),
                        dict(base, version='V2', version_default=True),
                        dict(base, name='data', type='STT_OBJECT'),
                        dict(base, name='V1', type='STT_OBJECT', section='SHN_ABS')])
        functions = {converter.selected_version_name('libtest.so', 'api', version)
                     for version in ('V1', 'V2')} | {'api'}
        self.assertEqual(driver.exports(item, converter), functions)
        self.assertEqual(driver.exports(item, converter, False), functions | {'data'})


if __name__ == '__main__':
    unittest.main()
