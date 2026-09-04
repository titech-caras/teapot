import unittest

import gtirb
from gtirb_rewriting import Pass, PassManager, Patch, patch_constraints

from teapot.passes.preprocessing.normalize_data_block_alignment_pass import (
    NormalizeDataBlockAlignmentPass,
)


class _InsertNopsPass(Pass):
    def __init__(self, block, count=16):
        self.block = block
        self.count = count

    def begin_module(self, module, functions, rewriting_ctx):
        @patch_constraints()
        def nops(_):
            return "\n".join("nop" for _ in range(self.count))

        rewriting_ctx.insert_at(
            self.block,
            self.block.size,
            Patch.from_function(nops),
        )


class NormalizeDataBlockAlignmentPassTests(unittest.TestCase):
    @staticmethod
    def _case(
        *,
        code_size=0x20,
        head_offset=0x20,
        head_size=0x80,
        symbolize_head=True,
        tail_offset=0xA0,
    ):
        module = gtirb.Module(
            name="data-alignment-test",
            file_format=gtirb.Module.FileFormat.ELF,
            isa=gtirb.Module.ISA.X64,
            byte_order=gtirb.Module.ByteOrder.Little,
        )
        section = gtirb.Section(
            name=".text",
            flags={
                gtirb.Section.Flag.Readable,
                gtirb.Section.Flag.Executable,
                gtirb.Section.Flag.Loaded,
                gtirb.Section.Flag.Initialized,
            },
            module=module,
        )
        interval = gtirb.ByteInterval(
            address=0x1000,
            contents=b"\x90" * 0xC0,
            section=section,
        )
        code = gtirb.CodeBlock(
            size=code_size,
            offset=0,
            byte_interval=interval,
        )
        head = gtirb.DataBlock(
            size=head_size,
            offset=head_offset,
            byte_interval=interval,
        )
        tail = gtirb.DataBlock(
            size=0x20,
            offset=tail_offset,
            byte_interval=interval,
        )
        if symbolize_head:
            gtirb.Symbol(
                name="table_anchor",
                payload=head,
                module=module,
            )
        ir = gtirb.IR(modules=[module])

        module.aux_data["binaryType"] = gtirb.AuxData(
            ["EXEC"], "sequence<string>"
        )
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {section: (1, 0x6)},
            "mapping<UUID,tuple<uint64_t,uint64_t>>",
        )
        module.aux_data["alignment"] = gtirb.AuxData(
            {tail: 32}, "mapping<UUID,uint64_t>"
        )
        module.aux_data["comments"] = gtirb.AuxData(
            {}, "mapping<Offset,string>"
        )
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {},
            "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>",
        )
        module.aux_data["padding"] = gtirb.AuxData(
            {}, "mapping<Offset,uint64_t>"
        )
        for name, type_name in (
            ("functionEntries", "mapping<UUID,set<UUID>>"),
            ("functionBlocks", "mapping<UUID,set<UUID>>"),
            ("functionNames", "mapping<UUID,UUID>"),
        ):
            module.aux_data[name] = gtirb.AuxData({}, type_name)

        return ir, module, code, head, tail

    def test_propagates_interior_alignment_to_contiguous_run_head(self):
        _, module, _, head, tail = self._case()
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        alignment = module.aux_data["alignment"].data
        self.assertEqual(alignment[head], 32)
        self.assertEqual(alignment[tail], 32)
        self.assertEqual(normalize.propagated, 1)

    def test_does_not_propagate_across_a_gap(self):
        _, module, _, head, _ = self._case(head_size=0x70)
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        self.assertNotIn(head, module.aux_data["alignment"].data)
        self.assertEqual(normalize.propagated, 0)

    def test_does_not_use_an_unidentified_split_as_an_anchor(self):
        _, module, _, head, _ = self._case(symbolize_head=False)
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        self.assertNotIn(head, module.aux_data["alignment"].data)
        self.assertEqual(normalize.propagated, 0)

    def test_does_not_change_an_incompatible_run_head_residue(self):
        _, module, _, head, _ = self._case(
            head_offset=0x10,
            head_size=0x90,
        )
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        self.assertNotIn(head, module.aux_data["alignment"].data)
        self.assertEqual(normalize.propagated, 0)

    def test_uses_first_compatible_boundary_after_unaligned_prefix(self):
        _, module, _, anchor, _ = self._case(code_size=0x08)
        interval = anchor.byte_interval
        prefix = gtirb.DataBlock(
            size=0x18,
            offset=0x08,
            byte_interval=interval,
        )
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        alignment = module.aux_data["alignment"].data
        self.assertNotIn(prefix, alignment)
        self.assertEqual(alignment[anchor], 32)
        self.assertEqual(normalize.propagated, 1)

    def test_does_not_propagate_through_overlapping_data_blocks(self):
        _, module, _, head, _ = self._case()
        interval = head.byte_interval
        gtirb.DataBlock(
            size=0x10,
            offset=head.offset + 0x10,
            byte_interval=interval,
        )
        normalize = NormalizeDataBlockAlignmentPass()

        normalize.begin_module(module, (), None)

        self.assertNotIn(head, module.aux_data["alignment"].data)
        self.assertEqual(normalize.propagated, 0)

    def test_code_growth_keeps_the_data_run_contiguous(self):
        ir, module, code, head, tail = self._case()
        normalize = NormalizeDataBlockAlignmentPass()
        manager = PassManager()
        manager.add(normalize)
        manager.add(_InsertNopsPass(code))

        manager.run(ir)

        self.assertEqual(normalize.propagated, 1)
        self.assertEqual(head.address % 32, 0)
        self.assertEqual(tail.address % 32, 0)
        self.assertEqual(head.address + head.size, tail.address)
        self.assertEqual(module.aux_data["alignment"].data[head], 32)


if __name__ == "__main__":
    unittest.main()
