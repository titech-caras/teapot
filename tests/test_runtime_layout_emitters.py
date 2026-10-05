"""The emitters encode some runtime-contract facts implicitly; pin them to the constants.

teapot/runtime_contract.py compares teapot/configs/runtime.py with the
runtime. Where an emitter writes a fact into its instruction choice instead of
reading the constant (an offset of 0, a byte store, a 64-bit counter), editing
the constant alone would make Teapot accept a runtime its code does not match.
These tests fail first.
"""
import re
from types import SimpleNamespace
import unittest
import uuid

import gtirb
from gtirb_rewriting.abi import _ABIS

from teapot.arch import get_arch
from teapot.configs import runtime


def arch_for(isa):
    arch = get_arch(gtirb.Module(name="probe", isa=isa))
    return arch, arch.register_abi(_ABIS)


def render(patch, registers):
    return patch(SimpleNamespace(scratch_registers=registers))


class ImplicitLayoutTests(unittest.TestCase):
    def test_memory_history_entry(self):
        self.assertEqual(runtime.MEMORY_HISTORY_ADDR_OFFSET, 0)
        self.assertEqual(runtime.MEMORY_HISTORY_SIZE_WIDTH, 1)
        for isa, names, address_store, size_store in (
                (gtirb.Module.ISA.X64, ("rax", "rbx", "rcx"), r"mov \[rbx\], rax",
                 rf"mov byte ptr \[rbx \+ {runtime.MEMORY_HISTORY_SIZE_OFFSET}\], 8"),
                (gtirb.Module.ISA.ARM64, ("x0", "x1", "x2"), r"str x0, \[x1\]",
                 rf"strb w2, \[x1, #{runtime.MEMORY_HISTORY_SIZE_OFFSET}\]"),
                (gtirb.Module.ISA.RISCV64, ("a0", "a1", "a2"), r"sd a0, 0\(a1\)",
                 rf"sb a2, {runtime.MEMORY_HISTORY_SIZE_OFFSET}\(a1\)")):
            with self.subTest(isa=isa):
                arch, abi = arch_for(isa)
                address, top, data = (abi.get_register(name) for name in names)
                text = arch.memlog_snippet(address, top, data, 8)
                # The address goes to the entry's start; the size is one byte.
                self.assertRegex(text, address_store)
                self.assertRegex(text, size_store)

    def test_checkpoint_target_and_counters(self):
        self.assertEqual(runtime.CHECKPOINT_TARGET_TRAMPOLINE_OFFSET, 0)
        self.assertEqual(runtime.COUNTER_WIDTH, 8)
        block = uuid.UUID(int=1)
        x64, abi = arch_for(gtirb.Module.ISA.X64)
        registers = [abi.get_register(name) for name in ("rbx", "rcx")]
        self.assertRegex(render(x64.checkpoint_patch(block), registers), r"mov checkpoint_target_metadata, rbx")
        # 64-bit memory operands for instruction_cnt.
        text = render(x64.conditional_restore_point_patch(3), registers)
        self.assertRegex(text, rf"cmp qword ptr instruction_cnt, {runtime.ROB_LEN - 3}\n")
        self.assertRegex(text, r"add qword ptr instruction_cnt, 3\n")
        aarch64, abi = arch_for(gtirb.Module.ISA.ARM64)
        self.assertRegex(render(aarch64.checkpoint_patch(block), []), r"str x16, \[x17\]\n")
        riscv64, abi = arch_for(gtirb.Module.ISA.RISCV64)
        self.assertRegex(render(riscv64.checkpoint_patch(block), []), r"sd t0, 0\(t1\)")

    def test_queue_pending_byte(self):
        self.assertGreaterEqual(runtime.DIFT_QUEUE_PENDING_SIZE, 1)
        x64, abi = arch_for(gtirb.Module.ISA.X64)
        rax = abi.get_register("rax")
        self.assertIn("mov byte ptr dift_reg_queue_pending, 1",
                      x64.dift_queue_reg_tag_snippet(None, None, 1, rax))

    def test_report_frames_stay_clear_of_the_runtime(self):
        # x64: the return address and the wrapper's two pushes sit below Teapot's
        # rsp and must end above the runtime's tag spill; Teapot's eight saved
        # registers are the scratchpad's first 64 bytes.
        self.assertGreaterEqual(runtime.X64_REPORT_STACK_OFFSET - 3 * 8, runtime.X64_REPORT_TAG_SPILL_OFFSET + 8)
        self.assertLessEqual(64, runtime.X64_REPORT_CALL_STACK_OFFSET)
        x64, abi = arch_for(gtirb.Module.ISA.X64)
        text = x64.report_gadget_snippet("KASPER_MDS", addr_reg=abi.get_register("rbx"),
                                         tag_reg=abi.get_register("rcx"))
        self.assertIn(f"lea rsp, scratchpad+{runtime.X64_REPORT_STACK_OFFSET}", text)
        saves = sorted(int(offset or 0) for offset in re.findall(r"mov scratchpad(?:\+(\d+))?, r\w+", text))
        self.assertEqual(saves, list(range(0, 64, 8)))
        # AArch64: the call site at the block's start, Teapot's x30 below the
        # runtime's save area.
        self.assertEqual(runtime.AARCH64_REPORT_GADGET_ADDR, 0)
        self.assertLessEqual(runtime.AARCH64_REPORT_LINK_SAVE + 8, runtime.AARCH64_REPORT_RUNTIME_SAVE)
        self.assertLess(runtime.AARCH64_REPORT_TAG, runtime.AARCH64_REPORT_LINK_SAVE)
        aarch64, abi = arch_for(gtirb.Module.ISA.ARM64)
        stack, temp = abi.get_register("x2"), abi.get_register("x3")
        text = aarch64.report_gadget_snippet("KASPER_MDS", abi.get_register("x0"), abi.get_register("x1"),
                                             stack, temp)
        self.assertRegex(text, r"str x3, \[x2\]\n")


if __name__ == "__main__":
    unittest.main()
