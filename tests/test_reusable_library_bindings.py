"""Standalone components use the converter's stable versioned link identities."""
import importlib.util
from pathlib import Path
import unittest

from tools.sharedlib import convert as converter


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load('reuse_binding_driver', 'experiments/reusable_libraries/rewrite_components.py')


class LibraryBindingTests(unittest.TestCase):
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
