"""Checkpoints belong to application branches, never generated target guards."""
import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from teapot.arch import RISCV64Architecture
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
from test_live_register_preservation import make_module


class RISCV64CheckpointPlacementTests(unittest.TestCase):
    def test_checkpoint_remains_at_application_branch_after_entry_split(self):
        for prefix in (b"", bytes.fromhex("13000000")):
            for branch_bytes in ("63140500", "63040500"):
                with self.subTest(prefix_size=len(prefix), branch=branch_bytes):
                    arch = RISCV64Architecture()
                    # BNE/BEQ a0, zero, +8; RET; RET. With no incoming edge,
                    # the entry also requires an indirect-target redirect guard.
                    contents = prefix + bytes.fromhex(branch_bytes + "6780000067800000")
                    ir, module, entry, _, registers = make_module(
                        arch, gtirb.Module.ISA.ValidButUnsupported, contents)
                    entry.size = len(prefix) + 4
                    interval = entry.byte_interval
                    fallthrough = gtirb.CodeBlock(size=4, offset=entry.size,
                                                  byte_interval=interval)
                    taken = gtirb.CodeBlock(size=4, offset=entry.size + 4,
                                            byte_interval=interval)
                    target = gtirb.Symbol("taken", payload=taken, module=module)
                    interval.symbolic_expressions[len(prefix)] = gtirb.SymAddrConst(0, target)
                    next(iter(module.aux_data["functionBlocks"].data.values())).update(
                        {fallthrough, taken})
                    ir.cfg.add(gtirb.Edge(entry, taken,
                        gtirb.Edge.Label(gtirb.Edge.Type.Branch, conditional=True, direct=True)))
                    ir.cfg.add(gtirb.Edge(entry, fallthrough,
                        gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)))
                    for block in (fallthrough, taken):
                        ir.cfg.add(gtirb.Edge(block, gtirb.ProxyBlock(module=module),
                            gtirb.Edge.Label(gtirb.Edge.Type.Return, direct=False)))
                    # Force the real first-spill fallback, where a misplaced
                    # checkpoint would sit inside the guard's spill lifetime.
                    module.aux_data["liveRegisterSets"].data = {
                        gtirb.Offset(block, offset): (1 << len(registers)) - 1
                        for block in (entry, fallthrough, taken)
                        for offset in range(0, block.size, 4)
                    }
                    original_uuid = entry.uuid
                    pipeline = TeapotPipeline(ir, options=InstrumentationOptions(
                        enable_dift=False, enable_asan=False, enable_gadgets=False,
                        enable_memlog=False, enable_indirect_check=False))
                    pipeline.run()
                    returns = [symbol for symbol in module.symbols
                               if symbol.name.startswith(".__return_landing_")]
                    self.assertEqual(len(returns), 1, "one checkpoint per original branch")
                    self.assertIn(str(original_uuid).replace("-", "_"), returns[0].name)
                    address = returns[0].referent.address
                    decoder = GtirbInstructionDecoder(module.isa)
                    instructions = [inst
                        for block in sorted(pipeline.text_section.code_blocks,
                                            key=lambda block: block.address)
                        if block.size
                        for inst in decoder.get_instructions(block)
                        if inst.address >= address]
                    conditional = next(inst for inst in instructions
                        if inst.mnemonic in ("beq", "bne", "beqz", "bnez", "c.beqz", "c.bnez"))
                    self.assertEqual(conditional.reg_name(conditional.operands[0].reg), "a0",
                        "checkpoint followed the generated checkpoint_cnt/t0 guard instead of application a0")
                    # Late landing-pad/long-jump work must not insert a second
                    # checkpoint or change the checkpoint's source identity.
                    self.assertEqual(pipeline.checkpoint_block_uuids, {original_uuid})


if __name__ == "__main__":
    unittest.main()
