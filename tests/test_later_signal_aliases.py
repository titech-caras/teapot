"""B20 aliases compose with canonical B92 using the actual GTIRB pass."""
import unittest

from teapot.configs.blacklist import RUNTIME_WRAPPER_FUNCTIONS
from teapot.runtime_exports import runtime_owned_names
import test_dift_ext_call_defined_provider as providers


class SignalAliasProviderTests(unittest.TestCase):
    def test_alias_imports_wrap_but_defined_exports_keep_their_identity(self):
        helper = providers.DefinedProviderTests(
            methodName='test_defined_inflateEnd_called_through_plt_keeps_export')
        names = ('__sysv_signal', 'sysv_signal', 'bsd_signal', 'ssignal', 'sigset')
        for name in names:
            expected = name + '__teapot_wrapper__'
            self.assertEqual(RUNTIME_WRAPPER_FUNCTIONS[name], expected)
            self.assertIn(expected, runtime_owned_names())
            for enabled in (False, True):
                with self.subTest(name=name, enabled=enabled):
                    _, imported, _, versions = helper.make(
                        False, {name}, name=name, wrap_dift=enabled)
                    self.assertEqual(imported.name, expected)
                    self.assertNotIn(imported, versions)
                    _, defined, _, versions = helper.make(
                        True, {name}, name=name, wrap_dift=enabled)
                    self.assertEqual(defined.name, name)
                    self.assertEqual(versions[defined], (2, False))


if __name__ == '__main__':
    unittest.main()
