"""Component policies are checked against actual cache and diagnostic bytes."""
import json
from pathlib import Path
import tempfile
import unittest

from experiments.reusable_libraries.validate_link import validate_frontend_policy
from tools.sharedlib import convert as converter
from frontend_diagnostic_support import component_frontend_fields
from test_sharedlib_ambiguity_policy import item


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



if __name__ == '__main__':
    unittest.main()
