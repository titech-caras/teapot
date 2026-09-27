from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import gtirb_rewriting
import gtirb_live_register_analysis
import teapot

from experiments.reusable_libraries import rewrite_components as driver


class CacheIdentityTests(unittest.TestCase):
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
