"""Component policies are checked against actual cache and diagnostic bytes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.reusable_libraries import rewrite_components as driver
from experiments.reusable_libraries.validate_link import validate_frontend_policy
from tools.sharedlib import convert as converter
from frontend_diagnostic_support import component_frontend_fields
from test_sharedlib_ambiguity_policy import args, item


class ComponentFrontendPoliciesTests(unittest.TestCase):
    def test_mixed_policies_require_diagnostics_for_the_same_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = []
            for index, policy in enumerate((True, False)):
                directory = root / str(index)
                directory.mkdir()
                source = item('executable' if index == 0 else 'selected')
                rows.append({'component_id': str(index), 'role': source['role'],
                             'input_sha256': source['sha256'], 'cache_path': str(directory),
                             **component_frontend_fields(directory, source, policy)})
            manifest = {'allow_ambiguous_data_pointers': True,
                        'pointer_inference': 'unproven heuristic', 'components': rows}
            receipt = validate_frontend_policy(manifest)
            self.assertEqual([row['allow_ambiguous_data_pointers'] for row in
                              receipt['component_frontend_policies'].values()], [True, False])
            self.assertEqual(validate_frontend_policy(dict(manifest, components=rows[::-1])), receipt)
            # A forged but correctly rehashed record must not transfer evidence
            # from another input to this component.
            diagnostic = root / '1/frontend-diagnostics.json'
            record = json.loads(diagnostic.read_text())
            record['input_sha256'] = 'b' * 64
            converter.dump(diagnostic, record)
            rows[1]['frontend_diagnostics_sha256'] = converter.sha(diagnostic)
            rows[1]['files']['frontend-diagnostics.json'] = converter.sha(diagnostic)
            with self.assertRaisesRegex(ValueError, 'input identity mismatch'):
                validate_frontend_policy(manifest)

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
