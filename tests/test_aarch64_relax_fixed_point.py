import unittest
import uuid
from unittest import mock

import gtirb

from teapot.arch.aarch64.architecture import AArch64Architecture
from teapot.passes.common.aarch64_relax_conditional_branches_pass import (
    AArch64RelaxConditionalBranchesPass,
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
    def test_layout_growth_is_relaxed_to_fixed_point(self):
        module, interval, blocks = build_layout_growth_case()
        test_margin = 134217728 - 32
        with mock.patch.object(
            AArch64RelaxConditionalBranchesPass,
            "DIRECT_BRANCH_SAFETY_MARGIN",
            test_margin,
        ):
            AArch64Architecture().relax_conditional_branches(module)

        self.assertEqual(blocks[-1].offset, 48)
        self.assertEqual(
            interval.contents[:12],
            bytes.fromhex("100000901002009100023fd6"),
        )


if __name__ == "__main__":
    unittest.main()
