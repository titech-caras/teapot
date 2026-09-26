"""Caller-independent ordinary reconstruction, not instrumented-object reuse."""
import copy
import importlib.util
from pathlib import Path
import unittest


CONVERTER = Path(__file__).resolve().parents[1] / 'tools/sharedlib/convert.py'
spec = importlib.util.spec_from_file_location('sharedlib_cache_converter', CONVERTER)
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


class OrdinaryLibraryCacheTests(unittest.TestCase):
    def setUp(self):
        self.item = {'path': '/inputs/libcore.so', 'sha256': 'library-A',
                     'role': 'selected'}
        self.context = {'contract': 'test-contract', 'executable': 'harness-A',
                        'selected_order': [['libcore.so', 'library-A']],
                        'external_order': [['libc.so.6', 'libc-A']],
                        'initialization_order': ['libcore.so'],
                        'tools': {'pprinter': 'printer-A'},
                        'instrumentation': None}

    def key(self, item=None, context=None, priority=100):
        return converter.content_key(converter.ordinary_object_recipe(
            self.item if item is None else item,
            self.context if context is None else context, priority))

    def test_different_harness_reuses_ordinary_library(self):
        changed = copy.deepcopy(self.context)
        changed['executable'] = 'harness-B'
        self.assertEqual(self.key(), self.key(context=changed))

    def test_executable_object_still_depends_on_harness(self):
        item = dict(self.item, role='executable', path='/inputs/main')
        changed = dict(self.context, executable='harness-B')
        self.assertNotEqual(self.key(item=item), self.key(item=item, context=changed))

    def test_library_contents_invalidate(self):
        self.assertNotEqual(self.key(), self.key(item=dict(self.item, sha256='library-B')))

    def test_dependency_tool_and_order_changes_invalidate(self):
        for field, value in (
                ('selected_order', [['libcore.so', 'library-B']]),
                ('external_order', [['libc.so.6', 'libc-B']]),
                ('initialization_order', ['libother.so', 'libcore.so']),
                ('tools', {'pprinter': 'printer-B'}),
                ('contract', 'changed-contract')):
            with self.subTest(field=field):
                self.assertNotEqual(self.key(), self.key(context=dict(self.context, **{field: value})))
        self.assertNotEqual(self.key(), self.key(priority=101))

    def test_does_not_mutate_run_manifest(self):
        before = copy.deepcopy(self.context)
        self.key()
        self.assertEqual(self.context, before)


if __name__ == '__main__':
    unittest.main()
