import unittest

import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import PassManager

from teapot.arch import AArch64Architecture, X64Architecture
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from test_live_register_preservation import make_module


class TransientTrapTests(unittest.TestCase):
    def test_traps_get_unconditional_rollback_before_execution(self):
        for arch, isa, nop, traps in (
                (X64Architecture(), gtirb.Module.ISA.X64, bytes.fromhex("90"),
                 ("cc", "f1", "cd80", "cd03")),
                (AArch64Architecture(), gtirb.Module.ISA.ARM64, bytes.fromhex("1f2003d5"),
                 ("000020d4", "200020d4"))):
            for encoding in traps:
                with self.subTest(arch=arch.name, encoding=encoding):
                    trap = bytes.fromhex(encoding)
                    ir, module, block, abi, _ = make_module(arch, isa, nop + trap + nop)
                    decoder = GtirbInstructionDecoder(module.isa)
                    instructions = list(decoder.get_instructions(block))
                    self.assertFalse(arch.instruction_must_rollback(instructions[0]))
                    self.assertTrue(arch.instruction_must_rollback(instructions[1]))
                    gtirb.Symbol(name="restore_checkpoint_EXT_LIB",
                                 payload=gtirb.ProxyBlock(module=module), module=module)
                    manager = LiveRegisterManager(module, abi)
                    passes = PassManager()
                    passes.add(TransientInsertRestorePointsPass(
                        manager, block.section, block.section, decoder, arch))
                    passes.run(ir)
                    interval = next(iter(block.section.byte_intervals))
                    destinations = [(offset, expr.symbol.name)
                                    for offset, expr in interval.symbolic_expressions.items()
                                    if isinstance(expr, gtirb.SymAddrConst)]
                    rollback = [offset for offset, name in destinations
                                if name == "restore_checkpoint_EXT_LIB"]
                    self.assertEqual(len(rollback), 1)
                    self.assertLess(rollback[0], bytes(interval.contents).index(trap))
                    self.assertNotIn("instruction_cnt", [name for _, name in destinations])
