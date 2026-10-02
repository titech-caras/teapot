"""The x64 report-call snippet's register arguments."""
import unittest

from teapot.arch import X64Architecture


class X64ReportSnippetTests(unittest.TestCase):
    def test_tag_register_is_optional(self):
        # The signature documents tag_reg=None; it must not be dereferenced.
        snippet = X64Architecture.report_gadget_snippet("KASPER_MDS")
        self.assertIn("mov rdx, 0", snippet)
        self.assertIn("mov rsi, 0", snippet)


if __name__ == "__main__":
    unittest.main()
