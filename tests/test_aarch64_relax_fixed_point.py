import unittest
import uuid
from unittest import mock

import gtirb

from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.passes.common.aarch64_relax_conditional_branches_pass import (
    AArch64RelaxConditionalBranchesPass,
    _Replacement,
)


def build_layout_growth_case():
    module = gtirb.Module(
        name="aarch64-layout-growth",
        isa=gtirb.Module.ISA.ARM64,
        file_format=gtirb.Module.FileFormat.ELF,
        byte_order=gtirb.Module.ByteOrder.Little,
    )
    section = gtirb.Section(
        name=".text",
        flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Readable},
        module=module,
    )
    # The internal BL is initially in range.  Three external BL veneers grow
    # by eight bytes each during iteration one, moving the internal target past
    # the deliberately small test range.  A fixed-point driver must discover
    # and relax that internal call during iteration two.
    interval = gtirb.ByteInterval(
        address=0x400000,
        contents=(0x94000000).to_bytes(4, "little") * 4
        + (0xD65F03C0).to_bytes(4, "little"),
        section=section,
    )
    blocks = [
        gtirb.CodeBlock(size=4, offset=offset, byte_interval=interval)
        for offset in range(0, 20, 4)
    ]
    target_symbol = gtirb.Symbol(
        name="internal_target", payload=blocks[-1], module=module
    )
    interval.symbolic_expressions[0] = gtirb.SymAddrConst(
        0, target_symbol, set()
    )
    for index, offset in enumerate((4, 8, 12)):
        proxy = gtirb.ProxyBlock(module=module)
        symbol = gtirb.Symbol(
            name=f"external_{index}", payload=proxy, module=module
        )
        interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
            0, symbol, {gtirb.SymbolicExpression.Attribute.PLT}
        )
    module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
        type_name="mapping<Offset,uint64_t>",
        data={gtirb.Offset(interval, offset): 4 for offset in (0, 4, 8, 12)},
    )
    module.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<UUID,set<UUID>>",
        data={uuid.uuid4(): {blocks[-1]}},
    )
    return module, interval, blocks


class AArch64RelaxFixedPointTests(unittest.TestCase):
    def test_auxdata_remapping_does_not_depend_on_insertion_order(self):
        module, interval, _ = build_layout_growth_case()
        other = gtirb.ByteInterval(contents=b'1234')
        original = [(gtirb.Offset(interval, 20), 8), (gtirb.Offset(interval, 0), 4),
                    (gtirb.Offset(other, 4), 2), (gtirb.Offset(interval, 8), 8),
                    (gtirb.Offset(interval, 12), 4)]
        replacements = [_Replacement(0, b'0' * 8), _Replacement(12, b'0' * 12)]
        visitor = AArch64RelaxConditionalBranchesPass(None, direct_pads={})
        visitor.module = module
        expected = {gtirb.Offset(interval, 32): 8, gtirb.Offset(interval, 12): 8,
                    gtirb.Offset(other, 4): 2, gtirb.Offset(interval, 0): 4,
                    gtirb.Offset(interval, 4): 4, gtirb.Offset(interval, 16): 4}
        for items in (original, list(reversed(original))):
            module.aux_data['symbolicExpressionSizes'].data = dict(items)
            visitor._rewrite_symbolic_expression_sizes(interval, replacements, [0, 4, 16])
            self.assertEqual(module.aux_data['symbolicExpressionSizes'].data, expected)

    def test_layout_growth_is_relaxed_to_fixed_point(self):
        module, interval, blocks = build_layout_growth_case()
        test_margin = 134217728 - 32
        with mock.patch.object(
            AArch64RelaxConditionalBranchesPass,
            "DIRECT_BRANCH_SAFETY_MARGIN",
            test_margin,
        ):
            AArch64Architecture().relax_conditional_branches(module, direct_pads={})

        self.assertEqual(blocks[-1].offset, 48)
        self.assertEqual(
            interval.contents[:12],
            bytes.fromhex("100000901002009100023fd6"),
        )

    def test_relaxed_branch_to_a_direct_label_lands_on_the_pad(self):
        # bl body; b body; pad: nop; body: ret. Direct transfers name the label
        # after the pad; relaxed into BLR/BR, they are indirect and must land
        # on the pad itself.
        module = gtirb.Module(
            name="aarch64-direct-label",
            isa=gtirb.Module.ISA.ARM64,
            file_format=gtirb.Module.FileFormat.ELF,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        section = gtirb.Section(
            name=".text",
            flags={gtirb.Section.Flag.Executable, gtirb.Section.Flag.Readable},
            module=module,
        )
        interval = gtirb.ByteInterval(
            address=0x400000,
            contents=b"".join(word.to_bytes(4, "little") for word in (
                0x94000000, 0x14000000, 0xD503201F, 0xD65F03C0)),
            section=section,
        )
        blocks = [gtirb.CodeBlock(size=4, offset=offset, byte_interval=interval)
                  for offset in range(0, 16, 4)]
        pad = gtirb.Symbol(name="f", payload=blocks[2], module=module)
        label = gtirb.Symbol(name=".L__teapot_direct_entry__f__teapot___1",
                             payload=blocks[3], module=module)
        for offset in (0, 4):
            interval.symbolic_expressions[offset] = gtirb.SymAddrConst(0, label, set())
        module.aux_data["symbolicExpressionSizes"] = gtirb.AuxData(
            type_name="mapping<Offset,uint64_t>",
            data={gtirb.Offset(interval, offset): 4 for offset in (0, 4)},
        )
        module.aux_data["functionEntries"] = gtirb.AuxData(
            type_name="mapping<UUID,set<UUID>>",
            data={uuid.uuid4(): {blocks[2]}},
        )
        arch = AArch64Architecture()
        with mock.patch.object(
            AArch64RelaxConditionalBranchesPass,
            "DIRECT_BRANCH_SAFETY_MARGIN",
            134217728 - 4,
        ):
            arch.relax_conditional_branches(module, direct_pads={label: pad})

        # Both became ADRP/ADD/BR(L) through IP0, to the pad.
        self.assertEqual(len(interval.symbolic_expressions), 4)
        self.assertEqual({expression.symbol for expression in interval.symbolic_expressions.values()},
                         {pad})


if __name__ == "__main__":
    unittest.main()
