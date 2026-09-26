from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.arch.decoders import aarch64_decoder, riscv64_decoder
from teapot.configs.slots import (
    AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
    AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass
from teapot.passes.text.dift.riscv64 import RISCV64TextDiftPropagationLLVMPass


class RISCDiftRegisterAllocationTests(unittest.TestCase):
    def _passes(self):
        for arch, pass_type in (
                (AArch64Architecture(), AArch64TextDiftPropagationLLVMPass),
                (RISCV64Architecture(), RISCV64TextDiftPropagationLLVMPass)):
            yield arch, pass_type(SimpleNamespace(abi=arch.abi), None, None, arch,
                                  dift_layout=SimpleNamespace(xor_mask=0))

    def test_spares_are_preferred_and_only_live_fallbacks_are_saved(self):
        for arch, dift in self._passes():
            with self.subTest(arch=arch.name):
                candidates = list(arch.abi._scratch_registers())
                live = set(arch.abi.all_registers()) - set(candidates[-2:])
                plan = dift._plan_scratch_registers(4, live)
                self.assertEqual(plan.registers[:2], tuple(candidates[-2:]))
                self.assertEqual(plan.saved_regs, plan.registers[2:])
                self.assertEqual(len(plan.saved_regs), 2)
                all_live = dift._plan_scratch_registers(4)
                self.assertEqual(all_live.registers, all_live.saved_regs)
                no_live = dift._plan_scratch_registers(4, set())
                self.assertFalse(no_live.saved_regs)

    def test_moved_insertion_keeps_both_source_and_destination_live(self):
        for arch, dift in self._passes():
            with self.subTest(arch=arch.name):
                candidates = list(arch.abi._scratch_registers())
                original, adjusted, function = object(), object(), object()
                states = {(original, 0): {candidates[0]}, (adjusted, 1): {candidates[1]}}
                dift.insertion_register_location = Mock(return_value=(adjusted, 1))
                dift.reg_manager.live_registers = Mock(
                    side_effect=lambda _fn, block, index: states[block, index])
                plan = dift._scratch_plan(function, original, 0)
                self.assertEqual(plan.live_registers, {candidates[0], candidates[1]})
                self.assertTrue(set(plan.registers).isdisjoint(plan.live_registers))
                self.assertEqual(states[original, 0], {candidates[0]})
                self.assertEqual(states[adjusted, 1], {candidates[1]})

    def test_capture_omits_saves_for_spares_and_retains_operand_alias_saves(self):
        for arch, dift in self._passes():
            with self.subTest(arch=arch.name):
                if arch.name == "aarch64":
                    decoder = aarch64_decoder()
                    encoded = bytes.fromhex("000040f9")  # ldr x0,[x0]
                else:
                    arch.install_decoder_compat()
                    decoder = riscv64_decoder()
                    encoded = bytes.fromhex("83b20200")  # ld t0,0(t0)
                inst = next(decoder.disasm(encoded, 0x1000))
                operand = arch.memory_operand(inst)
                live = arch.mem_operand_registers(arch.abi, inst, operand)
                free_plan = dift._plan_scratch_registers(2, live)
                free_patch = dift._build_store_values_patch(inst, [(0, operand, None)],
                                                           scratch_plan=free_plan)
                free_asm = free_patch(SimpleNamespace(stack_adjustment=0))
                self.assertFalse(free_plan.saved_regs)
                self.assertNotIn("sub sp", free_asm)
                self.assertNotIn(f"scratchpad+{SCRATCHPAD_FIRST_SPILL_OFFSET}", free_asm)
                self.assertTrue(set(free_plan.registers).isdisjoint(live))

                saved_plan = dift._plan_scratch_registers(2)
                saved_patch = dift._build_store_values_patch(inst, [(0, operand, None)],
                                                            scratch_plan=saved_plan)
                saved_asm = saved_patch(SimpleNamespace(stack_adjustment=0))
                self.assertTrue(saved_plan.saved_regs)
                self.assertGreater(len(saved_asm), len(free_asm))
                if arch.name == "aarch64":
                    self.assertIn(f"#{AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET}", saved_asm)
                    self.assertNotEqual(AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
                                        AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET)
                else:
                    self.assertIn(f"scratchpad+{SCRATCHPAD_FIRST_SPILL_OFFSET}", saved_asm)

    def test_replay_filters_gpr_saves_but_not_untracked_fp_state(self):
        for arch, dift in self._passes():
            with self.subTest(arch=arch.name):
                candidates = list(arch.abi._scratch_registers())
                kept, dead = candidates[-2:]
                if arch.name == "aarch64":
                    body = f"mov {kept}, #0\nmov {dead}, #0\nmovi v0.16b, #0\n"
                    save, restore = "str", "ldr"
                    float_save, float_restore = "str q0,", "ldr q0,"
                else:
                    body = f"li {kept}, 0\nli {dead}, 0\nfmv.d.x ft0, zero\n"
                    save, restore = "sd", "ld"
                    float_save, float_restore = "fsd ft0,", "fld ft0,"
                plan = dift._plan_scratch_registers(2, {kept})
                patch = dift._build_optimized_dift_values_patch(
                    body, dift._get_register_usage(body), scratch_plan=plan)
                asm = patch(SimpleNamespace(stack_adjustment=0))
                self.assertIn(f"{save} {kept},", asm)
                self.assertIn(f"{restore} {kept},", asm)
                self.assertNotIn(f"{save} {dead},", asm)
                self.assertNotIn(f"{restore} {dead},", asm)
                self.assertIn(float_save, asm)
                self.assertIn(float_restore, asm)


if __name__ == "__main__":
    unittest.main()
