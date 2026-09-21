import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import _auxdata

from teapot.arch import RISCV64Architecture
from teapot.passes.preprocessing.dift_ext_call_pass import DiftExtCallPass


class RiscvDiftExtCallPairTests(unittest.TestCase):
    def make_call(self, *, tail=False, split=False, relocation="plt", mismatch=False,
                  high_opcode=0x17, internal=False):
        RISCV64Architecture().install_decoder_compat()
        ir = gtirb.IR()
        module = gtirb.Module(name="call-pair", isa=gtirb.Module.ISA.ValidButUnsupported,
                             byte_order=gtirb.Module.ByteOrder.Little, ir=ir)
        module.aux_data["archInfo"] = gtirb.AuxData({"ISA": "RISCV64"}, "mapping<string,string>")
        text = gtirb.Section(name=".text", module=module)
        plt = gtirb.Section(name=".plt", module=module)
        base = 6 if tail else 1
        high_word = (base << 7) | high_opcode
        low_word = ((5 if mismatch else base) << 15) | ((0 if tail else 1) << 7) | 0x67
        interval = gtirb.ByteInterval(address=0x1000, contents=high_word.to_bytes(4, "little")
                                     + low_word.to_bytes(4, "little"), section=text)
        high = gtirb.CodeBlock(size=4 if split else 8, byte_interval=interval)
        low = gtirb.CodeBlock(offset=4, size=4, byte_interval=interval) if split else high
        target = gtirb.CodeBlock(size=4)
        gtirb.ByteInterval(address=0x2000, contents=bytes.fromhex("67800000"), blocks=[target],
                           section=text if internal else plt)
        plt_anchor = gtirb.Symbol(".L_plt_anchor", payload=target, module=module)
        function = gtirb.Symbol("memcpy", payload=target if internal else gtirb.ProxyBlock(module=module),
                                module=module)
        high_anchor = gtirb.Symbol(".L_auipc_anchor", payload=high, module=module)
        attr = gtirb.SymbolicExpression.Attribute
        attributes = {attr.PLT} if relocation == "plt" else (
            {attr.HI, attr.PCREL} if relocation == "split" else set())
        interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, function, attributes)
        if relocation == "split":
            interval.symbolic_expressions[4] = gtirb.SymAddrConst(0, high_anchor, {attr.LO, attr.PCREL})
        ir.cfg.add(gtirb.Edge(low, target, gtirb.Edge.Label(
            gtirb.EdgeType.Branch if tail else gtirb.EdgeType.Call)))
        if split:
            ir.cfg.add(gtirb.Edge(high, low, gtirb.Edge.Label(gtirb.EdgeType.Fallthrough)))
        versions = {function: (2, False)}
        _auxdata.elf_symbol_versions.set(module, ({}, {}, versions))
        transform = DiftExtCallPass(text, GtirbInstructionDecoder(module.isa))
        transform.begin_module(module, [], None)
        return transform, module, high, low, function, high_anchor, plt_anchor, versions

    def test_high_relocation_names_external_call_and_tail(self):
        for tail in (False, True):
            for split in (False, True):
                for relocation in ("plt", "plain", "split"):
                    with self.subTest(tail=tail, split=split, relocation=relocation):
                        transform, module, high, low, function, anchor, plt_anchor, versions = self.make_call(
                            tail=tail, split=split, relocation=relocation)
                        transform.visit_code_block(low)
                        transform.end_module(module, [])
                        self.assertEqual(function.name, "memcpy__dift_wrapper__")
                        self.assertNotIn(function, versions)
                        self.assertEqual(anchor.name, ".L_auipc_anchor")
                        self.assertEqual(plt_anchor.name, ".L_plt_anchor")
                        if relocation == "split":
                            self.assertIs(high.byte_interval.symbolic_expressions[4].symbol, anchor)

    def test_unrelated_preceding_address_is_not_a_call_target(self):
        for mismatch, opcode in ((True, 0x17), (False, 0x37)):
            for split in (False, True):
                with self.subTest(mismatch=mismatch, opcode=opcode, split=split):
                    transform, module, _, low, function, _, _, versions = self.make_call(
                        mismatch=mismatch, high_opcode=opcode, split=split)
                    transform.visit_code_block(low)
                    transform.end_module(module, [])
                    self.assertEqual(function.name, "memcpy")
                    self.assertIn(function, versions)

    def test_internal_pair_is_not_wrapped(self):
        for split in (False, True):
            with self.subTest(split=split):
                transform, module, _, low, function, _, _, versions = self.make_call(
                    internal=True, split=split)
                transform.visit_code_block(low)
                transform.end_module(module, [])
                self.assertEqual(function.name, "memcpy")
                self.assertIn(function, versions)


if __name__ == "__main__":
    unittest.main()
