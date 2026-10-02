from pathlib import Path
import importlib.metadata
import importlib.util
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gtirb_rewriting
import gtirb_live_register_analysis
import teapot

from experiments.reusable_libraries import rewrite_components as driver


class CacheIdentityTests(unittest.TestCase):
    def test_toolchain_identity_skips_programs_the_driver_does_not_run(self):
        # clang prints a bare cc1: its compiler is built in, not a separate file.
        printed = {'-print-prog-name=as': '/usr/bin/as\n', '-print-prog-name=cc1': 'cc1\n'}
        converter = SimpleNamespace(native_tool_identity=lambda path: {'path': path})
        with patch.object(driver.subprocess, 'run',
                          lambda argv, **_: SimpleNamespace(stdout=printed[argv[1]])), \
                patch.object(driver.shutil, 'which', lambda name: None):
            identity = driver.toolchain_identity(converter, 'clang')
        self.assertEqual(identity, {'driver': {'path': 'clang'}, 'as': {'path': '/usr/bin/as'},
                                    'cc1': None})

    def test_toolchain_identity_keeps_programs_found_on_path(self):
        # Native gcc prints a bare `as` and runs the one on PATH.
        printed = {'-print-prog-name=as': 'as\n', '-print-prog-name=cc1': '/usr/libexec/gcc/cc1\n'}
        converter = SimpleNamespace(native_tool_identity=lambda path: {'path': path})
        with patch.object(driver.subprocess, 'run',
                          lambda argv, **_: SimpleNamespace(stdout=printed[argv[1]])), \
                patch.object(driver.shutil, 'which', lambda name: '/usr/bin/as' if name == 'as' else None):
            identity = driver.toolchain_identity(converter, 'gcc')
        self.assertEqual(identity, {'driver': {'path': 'gcc'}, 'as': {'path': 'as'},
                                    'cc1': {'path': '/usr/libexec/gcc/cc1'}})

    def test_tool_keys_leave_out_paths(self):
        installed = {'path': '/usr/local/bin/ddisasm', 'sha256': 'a',
                     'libraries': {'/usr/local/lib/libgtirb.so.2': 'b', '/lib/libc.so.6': 'c'}}
        mounted = {'path': '/newdd/bin/ddisasm', 'sha256': 'a',
                   'libraries': {'/newdd/lib/libgtirb.so.2': 'b', '/lib/libc.so.6': 'c'}}
        self.assertEqual(driver.portable_identity(installed), driver.portable_identity(mounted))
        mounted['libraries']['/newdd/lib/libgtirb.so.2'] = 'd'
        self.assertNotEqual(driver.portable_identity(installed), driver.portable_identity(mounted))
        self.assertIsNone(driver.portable_identity(None))

    def test_package_files_are_key_material(self):
        identity = driver.dependency_versions()
        self.assertEqual(identity, driver.dependency_versions())
        self.assertIn('networkx', {name for name, _ in identity['installed']})
        for distribution, name in driver.OUTPUT_PACKAGES:
            with self.subTest(package=distribution):
                if importlib.util.find_spec(name) is None:
                    self.skipTest(f'{name} is not installed here')
                self.assertIsNotNone(identity[distribution])

        def no_metadata(name):
            raise importlib.metadata.PackageNotFoundError(name)

        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'teapot_fixture_package'
            package.mkdir()
            (package / '__init__.py').write_text('')
            (package / 'libfixture.so').write_bytes(b'v1')
            with patch.object(driver, 'OUTPUT_PACKAGES', (('fixture', 'teapot_fixture_package'),)), \
                    patch.object(sys, 'path', [directory] + sys.path):
                try:
                    with patch('importlib.metadata.version', lambda name: '1.0'):
                        before = driver.dependency_versions()['fixture']
                        (package / 'libfixture.so').write_bytes(b'v2')
                        after = driver.dependency_versions()['fixture']
                    # A checkout without distribution metadata is hashed all the same.
                    with patch('importlib.metadata.version', no_metadata):
                        checkout = driver.dependency_versions()['fixture']
                finally:
                    sys.modules.pop('teapot_fixture_package', None)
        self.assertEqual(before['version'], after['version'])
        self.assertNotEqual(before['files'], after['files'])
        self.assertEqual(checkout, {'version': None, 'files': after['files']})

    def test_layout_and_shadow_stack_file_contents_invalidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout, stack = root / 'layout.cmake', root / 'stack.h'
            layout.write_text('layout-v1')
            stack.write_text('stack-v1')
            with patch.dict(os.environ, TEAPOT_DIFT_LAYOUT_FILE=str(layout),
                            TEAPOT_AARCH64_SHADOW_STACK_CONFIG=str(stack)):
                first = driver.configuration_identity()
                layout.write_text('layout-v2')
                second = driver.configuration_identity()
                self.assertNotEqual(first, second)
                stack.write_text('stack-v2')
                self.assertNotEqual(second, driver.configuration_identity())
                # Paths themselves do not destroy cross-host reuse.
                alternate = root / 'same-stack.h'
                alternate.write_bytes(stack.read_bytes())
                latest = driver.configuration_identity()
                with patch.dict(os.environ, TEAPOT_AARCH64_SHADOW_STACK_CONFIG=str(alternate)):
                    self.assertEqual(latest, driver.configuration_identity())

    def test_import_must_match_declared_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual, claimed = root / 'installed', root / 'checkout'
            actual.mkdir()
            claimed.mkdir()
            init = actual / '__init__.py'
            init.write_text('implementation = 1\n')
            (claimed / '__init__.py').write_text('implementation = 2\n')
            package = SimpleNamespace(__file__=str(init), __name__='fixture')
            with self.assertRaisesRegex(RuntimeError, 'outside declared source'):
                driver.imported_package_hash(package, claimed)
            key = driver.imported_package_hash(package, actual)
            init.write_text('implementation = 3\n')
            self.assertNotEqual(key, driver.imported_package_hash(package, actual))

    def test_checkout_and_site_packages_harness_paths(self):
        for package in (teapot, gtirb_rewriting, gtirb_live_register_analysis):
            root = Path(package.__file__).resolve().parent
            with self.subTest(package=package.__name__):
                self.assertEqual(driver.imported_package_hash(package, root),
                                 driver.imported_package_hash(package, root.parent))
                self.assertIn('__init__.py', driver.imported_package_hash(package, root))
