"""x64 loads folded into compares, read-modify-write and implicit destinations
get the load policy, and its verdict reaches the result and the port check."""
import re
from types import SimpleNamespace
import unittest
from unittest import mock

from teapot.arch import X64Architecture
from teapot.configs.slots import ScratchpadSlots
from test_x64_mem_policy_fast_path import policy_and_instruction

SOURCE = f"scratchpad+{ScratchpadSlots.X64_MEM_POLICY_SOURCE_TAG}"
PREDICATE = f"scratchpad+{ScratchpadSlots.X64_MEM_POLICY_PREDICATE_TAG}"


def memory_string(block, inst, operand):
    return re.search(r"\w+ ptr \[[^\]]*\]", inst.op_str).group(0)


class FoldedLoadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()

    def policy(self, encoding, *, predicate=False):
        policy, inst = policy_and_instruction(self.arch, encoding, free=())
        policy.write_predicate_tag = predicate
        with mock.patch.object(type(self.arch), "mem_operand_to_str", side_effect=memory_string):
            info = policy._build_policy_patch(inst, 0, 0, None, object())
        if info is None:
            return None, ""
        registers = [self.arch.abi.get_register(name) for name in ("rcx", "rdx", "rsi", "r8", "r9")]
        return info, info.patch(SimpleNamespace(scratch_registers=registers))

    def test_compares_report_and_hand_their_verdict_to_the_port_check(self):
        # cmp byte ptr [rax+rdi], 0x2a; cmp al, byte ptr [rax+rdi]
        for encoding in ("803c382a", "3a0438"):
            with self.subTest(encoding=encoding):
                info, asm = self.policy(encoding, predicate=True)
                self.assertFalse(info.queues_tags or info.queues_source_tag)
                self.assertIn("KASPER_MDS", asm)
                self.assertIn(f"mov byte ptr {PREDICATE}, 0", asm)
                self.assertIn(f"or byte ptr {PREDICATE},", asm)
                self.assertNotIn(SOURCE, asm)
                _, asm = self.policy(encoding)
                self.assertNotIn(PREDICATE, asm)

    def test_results_without_a_register_operand_take_the_verdict(self):
        # add byte ptr [rdi], 1; lock xadd byte ptr [rdx+rdi], al; div qword ptr [rdi]
        for encoding in ("800701", "f00fc0043a", "48f737"):
            with self.subTest(encoding=encoding):
                info, asm = self.policy(encoding)
                self.assertTrue(info.queues_tags and info.queues_source_tag)
                self.assertIn(f"or byte ptr {SOURCE},", asm)

    def test_register_loads_keep_their_queue_and_stores_stay_with_the_store_policy(self):
        info, asm = self.policy("8a07")  # mov al, byte ptr [rdi]
        self.assertTrue(info.queues_tags)
        self.assertFalse(info.queues_source_tag)
        self.assertNotIn(SOURCE, asm)
        for encoding in ("8807", "803d1000000001"):  # mov [rdi], al; cmp byte ptr [rip+0x10], 1
            with self.subTest(encoding=encoding):
                self.assertIsNone(self.policy(encoding)[0])


class FoldedLoadPortTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()

    def port_asm(self, encoding, read_predicate_tag):
        policy, inst = policy_and_instruction(self.arch, encoding)
        port = self.arch.create_transient_port_contention_policy_pass(
            policy.reg_manager, None, None, dift_layout=SimpleNamespace(xor_mask=0))
        port.read_predicate_tag = read_predicate_tag
        with mock.patch.object(type(self.arch), "mem_operand_to_str", side_effect=memory_string):
            patch, _ = port.build_patch(None, inst, 0)
        registers = [self.arch.abi.get_register(name) for name in ("rcx", "rdx", "rsi")]
        return patch(SimpleNamespace(scratch_registers=registers[:patch.constraints.scratch_registers]))

    def test_port_check_reads_the_verdict_of_its_own_load(self):
        self.assertIn(f"byte ptr {PREDICATE}", self.port_asm("803c382a", True))
        self.assertNotIn(PREDICATE, self.port_asm("803c382a", False))
        # A static address gets no load policy, so no verdict is read.
        self.assertNotIn(PREDICATE, self.port_asm("803d1000000001", True))


if __name__ == "__main__":
    unittest.main()
