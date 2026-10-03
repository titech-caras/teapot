"""Teapot's layout between rewrite rounds (teapot/utils/layout.py).

It must not depend on set order, must keep the alignment gtirb-layout infers for
the input's intervals, including a block that does not start its interval, and
gives Teapot's own sections an explicit alignment.
"""
import unittest
from unittest import mock

import gtirb
from gtirb_rewriting.prepare import _layout_module

from teapot.utils import dependencies
from teapot.utils.layout import (
    TEAPOT_SECTION_ALIGNMENT,
    remember_input_order,
    set_interval_alignment,
    settle_layout,
)


def build(*, explicit_new=True):
    """An input with a block at offset 8 of an interval at 0x1008, and two sections Teapot adds."""
    module = gtirb.Module(name="layout", isa=gtirb.Module.ISA.X64,
                          file_format=gtirb.Module.FileFormat.ELF,
                          byte_order=gtirb.Module.ByteOrder.Little)
    gtirb.IR(modules=[module])
    flags = {gtirb.Section.Flag.Readable, gtirb.Section.Flag.Loaded, gtirb.Section.Flag.Initialized}
    # Created out of address order: the layout must follow addresses, not creation.
    late = gtirb.Section(name=".late", flags=flags, module=module)
    late_interval = gtirb.ByteInterval(address=0x2000, contents=bytes(5), section=late)
    gtirb.DataBlock(size=5, byte_interval=late_interval)
    first = gtirb.Section(name=".first", flags=flags, module=module)
    first_interval = gtirb.ByteInterval(address=0x1000, contents=bytes(8), section=first)
    gtirb.DataBlock(size=8, byte_interval=first_interval)
    # gtirb-layout infers 16 for the block at 0x1010: its interval starts at
    # 8 modulo 16, with nothing in a block before it.
    leading = gtirb.Section(name=".leading", flags=flags | {gtirb.Section.Flag.Executable}, module=module)
    leading_interval = gtirb.ByteInterval(address=0x1008, contents=bytes(8) + b"\x90" * 16 + b"\xc3",
                                          section=leading)
    anchor = gtirb.CodeBlock(size=17, offset=8, byte_interval=leading_interval)
    gtirb.Symbol(name="exported", payload=anchor, module=module)
    module.aux_data["alignment"] = gtirb.AuxData(type_name="mapping<UUID,uint64_t>", data={})
    remember_input_order(module)
    # Two sections Teapot adds, without addresses, so a layout is due.
    added = []
    for name in (".teapot_z", ".teapot_a"):
        section = gtirb.Section(name=name, flags=flags, module=module)
        interval = gtirb.ByteInterval(contents=bytes(3), section=section)
        gtirb.DataBlock(size=3, byte_interval=interval)
        if explicit_new:
            set_interval_alignment(interval, TEAPOT_SECTION_ALIGNMENT)
        added.append(interval)
    return module, anchor, added


def addresses(module):
    return {section.name: [interval.address for interval in section.byte_intervals]
            for section in module.sections}


class DeterministicLayoutTests(unittest.TestCase):
    def test_a_leading_offset_block_keeps_its_inferred_alignment(self):
        module, anchor, added = build()
        settle_layout(module)
        self.assertEqual(anchor.address % 16, 0)
        self.assertEqual(anchor.byte_interval.address % 16, 8)
        for interval in added:
            self.assertEqual(interval.address % TEAPOT_SECTION_ALIGNMENT, 0)
        # gtirb-rewriting's own layout infers the same alignment for that block.
        reference, reference_anchor, _ = build()
        _layout_module(reference)
        self.assertEqual(reference_anchor.address % 16, 0)

    def test_sections_follow_input_addresses_then_added_names(self):
        module, _, _ = build()
        settle_layout(module)
        order = [section.name for section in sorted(module.sections, key=lambda section: section.address)]
        self.assertEqual(order, [".first", ".leading", ".late", ".teapot_a", ".teapot_z"])

    def test_the_rewriters_own_layout_does_not_change_the_result(self):
        # The end hook runs after the rewriter may have laid the module out in
        # set order. Inference must use the addresses this layout gave, not those.
        module, anchor, _ = build()
        settle_layout(module)
        settled = addresses(module)
        for shift, interval in enumerate(sorted(module.byte_intervals, key=lambda i: -i.address), 1):
            interval.address = 0x10000 * shift + 4 * shift
        settle_layout(module)
        self.assertEqual(addresses(module), settled)
        self.assertEqual(anchor.address % 16, 0)

    def test_the_same_input_gets_the_same_addresses(self):
        results = []
        for _ in range(3):
            module, _, _ = build()
            settle_layout(module)
            results.append(addresses(module))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])

    def test_unaligned_added_sections_only_follow_what_precedes_them(self):
        # Without the explicit entry an added section has nothing to keep;
        # the pipeline sets one for each of Teapot's sections.
        module, _, added = build(explicit_new=False)
        settle_layout(module)
        self.assertTrue(any(interval.address % TEAPOT_SECTION_ALIGNMENT for interval in added))

    def test_uninspected_dependency_versions_are_refused(self):
        verified = set(dependencies._verified)
        dependencies._verified.clear()
        try:
            with mock.patch.object(dependencies.importlib.metadata, "version",
                                   side_effect=lambda name: "9.9.9" if name == "gtirb-layout"
                                   else dependencies.INSPECTED_VERSIONS[name]):
                with self.assertRaisesRegex(RuntimeError, r"gtirb-layout 1\.0\.0.*gtirb-layout 9\.9\.9"):
                    dependencies.require_inspected("gtirb", "gtirb-layout", "gtirb-rewriting")
        finally:
            dependencies._verified.clear()
            dependencies._verified.update(verified)
        dependencies.require_inspected(*dependencies.INSPECTED_VERSIONS)


if __name__ == "__main__":
    unittest.main()
