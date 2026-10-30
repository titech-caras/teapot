"""Component policies are checked against actual cache and diagnostic bytes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.reusable_libraries import rewrite_components as driver
from tools.sharedlib import convert as converter
from frontend_diagnostic_support import component_frontend_fields
from test_sharedlib_ambiguity_policy import args, item


class ComponentFrontendPoliciesTests(unittest.TestCase):

    def test_component_basename_separates_entries_but_parent_directory_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, source = Path(temporary), item('selected')
            source['path'] = '/input/libtest.so.1.2'
            request = args(False, root)
            context = {'allow_ambiguous_data_pointers': False, 'bindings': [],
                       'selected_libraries': [], 'runtime_contract': {'coverage': False}}
            built = []
            def build(req, conv, src, key_data, key, selected, priority, directory):
                built.append(src['path'])
                result = {'component_id': key, 'coverage': False,
                          **component_frontend_fields(directory, src, False)}
                driver.dump(directory / 'key.json', key_data)
                driver.dump(directory / 'component.json', result)
                return result
            with patch.object(driver, 'build_component', side_effect=build), \
                    patch.object(driver, 'validate_object'):
                cold = driver.cached_component(request, converter, source, context, frozenset(), 0)
                moved = driver.cached_component(request, converter,
                    dict(source, path='/elsewhere/libtest.so.1.2'), context, frozenset(), 0)
                renamed = driver.cached_component(request, converter,
                    dict(source, path='/input/libtest.so.1'), context, frozenset(), 0)
                warm = driver.cached_component(request, converter,
                    dict(source, path='/input/libtest.so.1'), context, frozenset(), 0)
            self.assertFalse(cold['cache_hit'])
            self.assertTrue(moved['cache_hit'])
            self.assertFalse(renamed['cache_hit'])
            self.assertTrue(warm['cache_hit'])
            self.assertNotEqual(cold['component_id'], renamed['component_id'])
            self.assertEqual(built, ['/input/libtest.so.1.2', '/input/libtest.so.1'])

    def test_component_narrowing_separates_cold_and_warm_cache_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, source = Path(temporary), item('selected')
            source['application_fdes'] = []
            request = args(True, root)
            context = {'allow_ambiguous_data_pointers': True, 'bindings': [],
                       'selected_libraries': [], 'runtime_contract': {'coverage': False}}
            original_context = copy.deepcopy(context)
            built = []
            def build(req, conv, src, key_data, key, selected, priority, directory):
                built.append(req.allow_ambiguous_data_pointers)
                result = {'component_id': key, 'coverage': False,
                          **component_frontend_fields(directory, src, req.allow_ambiguous_data_pointers)}
                driver.dump(directory / 'key.json', key_data)
                driver.dump(directory / 'component.json', result)
                return result
            with patch.object(driver, 'build_component', side_effect=build), \
                    patch.object(driver, 'validate_object'), \
                    patch.object(converter, 'component_frontend_policy', create=True, return_value=False):
                cold = driver.cached_component(request, converter, source, context, frozenset(), 0)
                warm = driver.cached_component(request, converter, source, context, frozenset(), 0)
            self.assertEqual(built, [False])
            self.assertFalse(cold['cache_hit'])
            self.assertTrue(warm['cache_hit'])
            self.assertEqual(cold['component_id'], warm['component_id'])
            self.assertTrue(request.allow_ambiguous_data_pointers)
            self.assertEqual(context, original_context)
            with patch.object(driver, 'build_component', side_effect=build), \
                    patch.object(converter, 'component_frontend_policy', create=True, return_value=True):
                wider = driver.cached_component(request, converter, source, context, frozenset(), 0)
                self.assertNotEqual(cold['component_id'], wider['component_id'])
                with self.assertRaisesRegex(ValueError, 'may only narrow'):
                    driver.cached_component(args(False, root), converter, source,
                                            dict(context, allow_ambiguous_data_pointers=False), frozenset(), 0)
            self.assertEqual(built, [False, True])


if __name__ == '__main__':
    unittest.main()
