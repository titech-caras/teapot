import unittest
from unittest.mock import Mock

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import RewritingContext, patch_constraints
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import RISCV64Architecture
from teapot.passes.transient.transient_insert_restore_points_pass import (
    TransientInsertRestorePointsPass,
)
from teapot.passes.transient.transient_coverage import TransientCoveragePass
from test_live_register_preservation import make_module


class RiscvControlFlowPairInsertionTests(unittest.TestCase):
    def make_pair(self, *, tail, split, attributes="split"):
        arch = RISCV64Architecture()
        pair = "17030000 67000300" if tail else "97000000 e7800000"
        _, module, high, _, _ = make_module(
            arch, gtirb.Module.ISA.ValidButUnsupported,
            bytes.fromhex(pair + " 67800000"))
        high.size = 4 if split else 8
        low = gtirb.CodeBlock(offset=4, size=4, byte_interval=high.byte_interval) if split else high
        after = gtirb.CodeBlock(offset=8, size=4, byte_interval=high.byte_interval)
        next(iter(module.aux_data["functionBlocks"].data.values())).update({low, after})
        target = gtirb.Symbol("external", payload=gtirb.ProxyBlock(module=module), module=module)
        anchor = gtirb.Symbol("anchor", payload=high, module=module)
        attrs = gtirb.SymbolicExpression.Attribute
        high_attrs = {attrs.HI, attrs.PCREL} if attributes == "split" else (
            {attrs.PLT} if attributes == "plt" else set())
        high.byte_interval.symbolic_expressions[0] = gtirb.SymAddrConst(0, target, high_attrs)
        if attributes == "split":
            high.byte_interval.symbolic_expressions[4] = gtirb.SymAddrConst(
                0, anchor, {attrs.LO, attrs.PCREL})
        edge_type = gtirb.Edge.Type.Branch if tail else gtirb.Edge.Type.Call
        module.ir.cfg.add(gtirb.Edge(low, target.referent,
                                    gtirb.Edge.Label(edge_type, conditional=False, direct=True)))
        if split:
            module.ir.cfg.add(gtirb.Edge(high, low, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
        if not tail:
            module.ir.cfg.add(gtirb.Edge(low, after, gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
        return arch, module, high, low

    def test_insert_before_transfer_stays_before_pair(self):
        for tail in (False, True):
            for split in (False, True):
                for attrs in ("split", "plt", "plain"):
                    with self.subTest(tail=tail, split=split, attributes=attrs):
                        _, _, high, low = self.make_pair(tail=tail, split=split, attributes=attrs)
                        block, offset = RewritingContext._teapot_insert_location(low, 0 if split else 4)
                        self.assertIs(block, high)
                        self.assertEqual(offset, 0)

    def test_real_restore_pass_precedes_external_transfer(self):
        for tail in (False, True):
            for split in (False, True):
                with self.subTest(tail=tail, split=split):
                    arch, module, high, low = self.make_pair(tail=tail, split=split)
                    section = high.section
                    section.name = ".teapot_transient"
                    text = gtirb.Section(name=".text", module=module)
                    decoder = GtirbInstructionDecoder(module.isa)
                    functions = list(Function.build_functions(module))
                    ctx = RewritingContext(module, functions)

                    # A distinct non-clobber-sensitive probe makes the actual
                    # restore pass's placement observable after ctx.apply().
                    @patch_constraints()
                    def restore_probe(_ctx):
                        return "addi a7,zero,77"

                    arch.unconditional_restore_point_patch = lambda: restore_probe
                    visitor = TransientInsertRestorePointsPass(None, text, section, decoder, arch)
                    visitor.rewriting_ctx = ctx
                    visitor.visit_code_block(low, functions[0])
                    ctx.apply()
                    instructions = [inst for block in sorted(section.code_blocks, key=lambda b: b.address)
                                    if block.size
                                    for inst in decoder.get_instructions(block)]
                    self.assertEqual(instructions[0].operands[-1].imm, 77)
                    self.assertEqual(instructions[1].mnemonic, "auipc")
                    self.assertIn(instructions[2].mnemonic, ("jalr", "jr"))

    def test_data_pair_still_inserts_after_low(self):
        _, _, high, _ = self.make_pair(tail=False, split=False)
        high.byte_interval.contents = bytes.fromhex("97000000 93804000 67800000")
        block, offset = RewritingContext._teapot_insert_location(high, 4)
        self.assertIs(block, high)
        self.assertEqual(offset, 8)

    def test_liveness_uses_actual_pre_pair_boundary(self):
        for tail in (False, True):
            for split in (False, True):
                with self.subTest(tail=tail, split=split):
                    arch, module, high, low = self.make_pair(tail=tail, split=split)
                    t0 = arch.abi.get_register("t0")
                    names = module.aux_data["liveRegisterNames"].data
                    module.aux_data["liveRegisterSets"].data = {
                        gtirb.Offset(high, 0): 1 << names.index(t0.name),
                        gtirb.Offset(low, 0 if split else 4): 0,
                    }
                    manager = LiveRegisterManager(module, arch.abi)
                    manager.analyzer.analyze = Mock(side_effect=AssertionError("Python fallback"))
                    function = next(iter(Function.build_functions(module)))
                    manager.analyze(function)
                    allocated = []

                    @patch_constraints(scratch_registers=1)
                    def probe(ctx):
                        allocated.extend(ctx.scratch_registers)
                        return f"li {ctx.scratch_registers[0]},7"

                    arch.coverage_patch = lambda _idx: probe
                    guard = gtirb.Section(name=".teapot_guards", module=module)
                    visitor = TransientCoveragePass(manager, high.section, manager.analyzer.decoder,
                                                    guard, arch)
                    ctx = RewritingContext(module, [function])
                    visitor.rewriting_ctx = ctx
                    visitor.visit_code_block(low, function)
                    ctx.apply()
                    manager.refresh(preserve_liveness=True)
                    self.assertEqual(len(allocated), 1)
                    self.assertNotIn(t0, allocated)
                    instructions = [inst for block in sorted(high.section.code_blocks,
                                                            key=lambda b: b.address) if block.size
                                    for inst in manager.analyzer.decoder.get_instructions(block)]
                    probe_index = next(i for i, inst in enumerate(instructions)
                                       if inst.mnemonic in ("li", "addi")
                                       and inst.operands[-1].imm == 7)
                    high_index = next(i for i, inst in enumerate(instructions)
                                      if inst.mnemonic == "auipc")
                    self.assertLess(probe_index, high_index)


if __name__ == "__main__":
    unittest.main()
