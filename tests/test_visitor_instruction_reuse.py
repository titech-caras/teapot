from collections import Counter
import unittest
from unittest.mock import Mock

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.mixins.visitor_pass_mixin import InstVisitorPassMixin


class CountingDecoder:
    def __init__(self, isa):
        self.decoder = GtirbInstructionDecoder(isa)
        self.calls = Counter()

    def get_instructions(self, block):
        self.calls[block] += 1
        return self.decoder.get_instructions(block)


class InsertingVisitor(InstVisitorPassMixin):
    def __init__(self, arch, decoder, action=None):
        super().__init__(None, decoder, enable_live_reg_analysis=False)
        self.arch = arch
        self.rewriting_ctx = Mock()
        self.action = action

    def visit_inst(self, inst, inst_idx, inst_offset, block, function, live_registers):
        self.insert_at(block, inst_offset, None)
        if self.action is not None:
            self.action(self, block, inst_idx)


class VisitorInstructionReuseTests(unittest.TestCase):
    def _block(self, contents, address=0x1000):
        interval = gtirb.ByteInterval(address=address, contents=contents)
        return gtirb.CodeBlock(size=len(contents), byte_interval=interval)

    def test_one_decode_per_visit_with_unchanged_placement(self):
        for arch, isa, contents, expected in (
            (X64Architecture(), gtirb.Module.ISA.X64, b"\x90\x90\x90", [0, 1, 2]),
            (AArch64Architecture(), gtirb.Module.ISA.ARM64,
             bytes.fromhex("1f2003d5" * 3), [0, 4, 8]),
            (RISCV64Architecture(), gtirb.Module.ISA.ValidButUnsupported,
             bytes.fromhex("970200001303000013030000"), [4, 4, 8]),
        ):
            with self.subTest(arch=arch.name):
                arch.install_decoder_compat()
                block = self._block(contents)
                if arch.name == "riscv64":
                    module = gtirb.Module(name="rv64", isa=isa)
                    module.aux_data["archInfo"] = gtirb.AuxData(
                        {"ISA": "RISCV64"}, "mapping<string,string>")
                    block.byte_interval.section = gtirb.Section(name=".text", module=module)
                    block.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(
                        0, gtirb.Symbol(name="target", payload=0x2000),
                        {gtirb.SymbolicExpression.Attribute.PCREL,
                         gtirb.SymbolicExpression.Attribute.HI},
                    )
                decoder = CountingDecoder(isa)
                visitor = InsertingVisitor(arch, decoder)
                visitor.visit_code_block(block)
                self.assertEqual(
                    [call.args[1] for call in visitor.rewriting_ctx.insert_at.call_args_list],
                    expected,
                )
                self.assertEqual(decoder.calls[block], 1)

                block.byte_interval.contents = contents + contents
                block.size *= 2
                visitor.rewriting_ctx.reset_mock()
                visitor.visit_code_block(block)
                self.assertEqual(decoder.calls[block], 2)
                self.assertEqual(visitor.rewriting_ctx.insert_at.call_count, 6)

    def test_nested_visits_restore_the_outer_block(self):
        outer = self._block(b"\x90\x90")
        inner = self._block(b"\x90", address=0x2000)
        decoder = CountingDecoder(gtirb.Module.ISA.X64)

        def action(visitor, block, index):
            if block is outer and index == 0:
                visitor.visit_code_block(inner)
                visitor.insert_at(outer, 0, None)

        visitor = InsertingVisitor(X64Architecture(), decoder, action)
        visitor.visit_code_block(outer)
        self.assertEqual(decoder.calls, {outer: 1, inner: 1})
        visitor.insert_at(inner, 0, None)
        self.assertEqual(decoder.calls[inner], 2)

    def test_foreign_block_and_exception_do_not_reuse_wrong_instructions(self):
        outer = self._block(b"\x90")
        other = self._block(b"\x90\x90", address=0x2000)
        decoder = CountingDecoder(gtirb.Module.ISA.X64)

        def action(visitor, block, index):
            visitor.insert_at(other, 1, None)
            raise RuntimeError("stop visiting")

        visitor = InsertingVisitor(X64Architecture(), decoder, action)
        with self.assertRaisesRegex(RuntimeError, "stop visiting"):
            visitor.visit_code_block(outer)
        self.assertEqual(decoder.calls, {outer: 1, other: 1})
        visitor.insert_at(outer, 0, None)
        self.assertEqual(decoder.calls[outer], 2)


if __name__ == "__main__":
    unittest.main()
