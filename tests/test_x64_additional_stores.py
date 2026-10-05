"""Architectural stores must be logged even when Capstone omits the write flag."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gtirb
from gtirb_rewriting import InsertionContext, PassManager
from teapot.liveness import LiveRegisterManager

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.passes.common.dift.x64 import X64DiftOperandHelpers
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from test_live_register_preservation import make_module
from runtime_contract_support import fixture_layout


RMW = (("0fb00f", 1), ("660fb10f", 2), ("0fb10f", 4), ("480fb10f", 8),
       ("0fc70f", 8), ("480fc70f", 16))
STORES = tuple((prefix + code, width, True) for code, width in RMW for prefix in ("", "f0")) + (
    ("0fc307", 4, False), ("480fc307", 8, False),
    ("0fae1f", 4, False), ("c5f8ae1f", 4, False))
STATE_SAVES = ("0fae07", "480fae07", "0fae27", "480fae27", "0fae37", "480fae37",
               "0fc727", "480fc727", "0fc72f", "480fc72f")


class X64AdditionalStoreTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = x64_decoder()

    def decode(self, encoded):
        instructions = list(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))
        self.assertEqual(len(instructions), 1)
        return instructions[0]

    def visitor(self, inst):
        block = gtirb.CodeBlock(size=inst.size)
        gtirb.ByteInterval(address=inst.address, contents=bytes(inst.bytes), blocks=[block])
        visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
        visitor.allocate_registers = mock.Mock(return_value=lambda patch: patch)
        visitor.insert_at = mock.Mock()
        visitor._build_memlog_patch = mock.Mock(wraps=visitor._build_memlog_patch)
        visitor.visit_inst(inst, 0, 0, block)
        return visitor, block

    def test_explicit_stores_and_dift_targets(self):
        for encoded, width, read in STORES:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
                self.assertEqual(self.arch.mem_operand_is_read(inst, operand), read)
                self.assertEqual(self.arch.mem_operand_size(inst, operand), width)
                visitor, block = self.visitor(inst)
                self.assertEqual(visitor.insert_at.call_count, 1)
                self.assertEqual(visitor._build_memlog_patch.call_args.args[2], width)
                dift = X64DiftOperandHelpers(SimpleNamespace(abi=self.arch.abi), None, None, self.arch,
                                             dift_layout=fixture_layout('x64'))
                effects = dift._x64_instruction_effects(block, inst)
                self.assertIsNotNone(effects.mem_write_operand_str)
                self.assertEqual(effects.mem_write_size, width)
                self.assertEqual(effects.mem_read_operand_str is not None, read)

    def test_read_only_forms_stay_read_only(self):
        for encoded in ("483907", "488507", "0fae17", "c5f8ae17"):
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertFalse(self.arch.mem_operand_is_write(inst, operand))
                self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
                visitor, _ = self.visitor(inst)
                visitor.insert_at.assert_not_called()

    def test_implicit_stores_use_exact_address_and_extent(self):
        cases = (("3effd0", "[rsp-8]", 8), ("f2ffd0", "[rsp-8]", 8),
                 ("50", "[rsp-8]", 8), ("6650", "[rsp-2]", 2),
                 ("c8100000", "[rsp-8]", 8), ("c8100001", "[rsp-16]", 16),
                 ("c8100003", "[rsp-32]", 32), ("c8100020", "[rsp-8]", 8),
                 ("66c8100000", "[rsp-2]", 2), ("66c8100003", "[rsp-8]", 8),
                 ("660ff7c1", "[rdi]", 16), ("0ff7c1", "[rdi]", 8),
                 ("67660ff7c1", "[edi]", 16), ("64660ff7c1", "fs:[rdi]", 16))
        for encoded, address, width in cases:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                visitor, _ = self.visitor(inst)
                self.assertEqual(visitor.insert_at.call_count, 1)
                self.assertEqual(visitor._build_memlog_patch.call_args.args[1:], (address, width))
        for encoded in ("3effd0", "f2ffd0"):
            self.assertTrue(self.arch.dift_should_skip_instruction(self.decode(encoded)))

    def test_large_state_saves_rollback_instead_of_logging_eight_bytes(self):
        for encoded in STATE_SAVES:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                self.assertTrue(self.arch.instruction_must_rollback(inst))
                visitor, _ = self.visitor(inst)
                visitor.insert_at.assert_not_called()
                code = bytes.fromhex("90" + encoded + "90")
                ir, module, block, abi, _ = make_module(self.arch, gtirb.Module.ISA.X64, code)
                gtirb.Symbol(name="restore_checkpoint_EXT_LIB", module=module,
                             payload=gtirb.ProxyBlock(module=module))
                manager = LiveRegisterManager(module, abi)
                passes = PassManager()
                passes.add(TransientInsertRestorePointsPass(
                    manager, block.section, block.section, manager.decoder, self.arch))
                passes.run(ir)
                interval = next(iter(block.section.byte_intervals))
                rollback = [offset for offset, expr in interval.symbolic_expressions.items()
                            if isinstance(expr, gtirb.SymAddrConst)
                            and expr.symbol.name == "restore_checkpoint_EXT_LIB"]
                self.assertEqual(len(rollback), 1)
                self.assertLess(rollback[0], bytes(interval.contents).index(bytes(inst.bytes)))

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"), "native x64 compiler required")
    def test_native_stores_replay_original_bytes(self):
        for encoded, width, _ in STORES + (("660ff7c1", 16, False), ("0ff7c1", 8, False)):
            # VSTMXCSR needs AVX; classification is tested above on every host.
            if encoded == "c5f8ae1f":
                continue
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)), tempfile.TemporaryDirectory() as directory:
                visitor, _ = self.visitor(inst)
                self.assertEqual(visitor.insert_at.call_count, 1)
                # The patch the pass chose: two registers for one-entry scalar stores.
                call = visitor._build_memlog_patch.call_args
                patch = visitor._build_memlog_patch(*call.args, **call.kwargs)
                allocation = self.arch.abi._allocate_patch_registers(patch.constraints)
                prologue, epilogue, _ = self.arch.abi._create_prologue_and_epilogue(
                    patch.constraints, allocation, True)
                body = patch(InsertionContext(None, None, None, 0,
                                               scratch_registers=allocation.scratch_registers))
                wrapped = (".att_syntax prefix\n" + "\n".join(s.code for s in prologue) +
                           "\n.intel_syntax noprefix\n" + body + "\n.att_syntax prefix\n" +
                           "\n".join(s.code for s in epilogue) + "\n.intel_syntax noprefix\n")
                setup = ("push rbx\nmov rax, 0xa5a5a5a5a5a5a5a5\nmov rdx, rax\n"
                         "mov rcx, 0x12345678\nmov rbx, 0x98765432\n"
                         "pxor xmm0, xmm0\npcmpeqb xmm1, xmm1\n"
                         "pxor mm0, mm0\npcmpeqb mm1, mm1\n")
                if inst.mnemonic.split()[-1] == "movnti":
                    setup += "mov rax, rcx\n"
                operation = ".byte " + ",".join(map(str, bytes(inst.bytes))) + "\nsfence\nemms\npop rbx\nret\n"
                root = Path(directory)
                (root / "stores.S").write_text(
                    ".intel_syntax noprefix\n.text\n.globl run_original\nrun_original:\n" +
                    setup + operation + "\n.globl test_function\ntest_function:\n" +
                    setup + wrapped + operation + '.section .note.GNU-stack,"",@progbits\n')
                (root / "check.c").write_text(r'''
#include <stdint.h>
#include <string.h>
unsigned char scratchpad[1048576] __attribute__((aligned(64)));
uintptr_t old_rsp;
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[8], *memory_history_top = history;
extern void run_original(void *), test_function(void *);
int main(void) {
    unsigned char data[64] __attribute__((aligned(16))), expected[64];
    memset(data, 0xa5, sizeof data); memset(expected, 0xa5, sizeof expected);
    run_original(expected); test_function(data);
    if (memcmp(data, expected, sizeof data)) return 1;
    size_t logged = 0;
    for (struct entry *p = history; p < memory_history_top; p++) {
        if (p->addr != data + logged || !p->size || p->size > 8) return 2;
        logged += p->size;
    }
    if (logged != WIDTH) return 3;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    memset(expected, 0xa5, sizeof expected);
    return memcmp(data, expected, sizeof data) != 0;
}
''')
                built = subprocess.run(["cc", "-O2", "-no-pie", f"-DWIDTH={width}",
                                        str(root / "check.c"), str(root / "stores.S"),
                                        "-o", str(root / "check")], capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stderr)
                ran = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"), "native x64 compiler required")
    def test_enter_and_word_push_restore_the_whole_written_range(self):
        cases = [("50", 8), ("6650", 2)]
        for prefix, width in (("", 8), ("66", 2)):
            for nesting in (0, 1, 3, 31, 32, 33):
                level = nesting & 31
                cases.append((prefix + f"c81000{nesting:02x}", width * (level + 1 if level else 1)))
        for encoded, width in cases:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)), tempfile.TemporaryDirectory() as directory:
                visitor, _ = self.visitor(inst)
                call = visitor._build_memlog_patch.call_args
                patch = visitor._build_memlog_patch(*call.args, **call.kwargs)
                # These are proven scratch registers in this small function;
                # none aliases RAX, RDI, RSP or RBP used by the original store.
                body = patch(SimpleNamespace(scratch_registers=tuple(
                    self.arch.abi.get_register(name)
                    for name in ("r8", "r9", "r10")[:patch.constraints.scratch_registers])))
                assembly = ".intel_syntax noprefix\n.text\n"
                for name, log in (("original", ""), ("rewritten", body)):
                    assembly += f"""
.globl {name}
{name}:
    mov [runner_rsp], rsp
    mov [runner_rbp], rbp
    lea rsp, [rdi+512]
    lea rbp, [rdi+896]
    mov rax, 0x12345678
    {log}
    .byte {','.join(map(str, bytes(inst.bytes)))}
    mov [after_rsp], rsp
    mov [after_rbp], rbp
    mov rsp, [runner_rsp]
    mov rbp, [runner_rbp]
    ret
"""
                assembly += '.section .note.GNU-stack,"",@progbits\n'
                root = Path(directory)
                (root / "stack.S").write_text(assembly)
                (root / "check.c").write_text(r'''
#include <stdint.h>
#include <string.h>
uintptr_t runner_rsp, runner_rbp, after_rsp, after_rbp;
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[64], *memory_history_top = history;
extern void original(void *), rewritten(void *);
int main(void) {
    unsigned char data[1024] __attribute__((aligned(16))), expected[1024];
    memset(data, 0xa5, sizeof data);
    original(data);
    memcpy(expected, data, sizeof data);
    uintptr_t expected_sp = after_rsp, expected_bp = after_rbp;
    memset(data, 0xa5, sizeof data);
    rewritten(data);
    if (memcmp(data, expected, sizeof data)) return 1;
    if (after_rsp != expected_sp || after_rbp != expected_bp) return 2;
    size_t logged = 0;
    for (struct entry *p = history; p < memory_history_top; p++) {
        if (p->addr != data + 512 - WIDTH + logged || !p->size || p->size > 8) return 3;
        logged += p->size;
    }
    if (logged != WIDTH) return 4;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    memset(expected, 0xa5, sizeof expected);
    return memcmp(data, expected, sizeof data) != 0;
}
''')
                built = subprocess.run(["cc", "-O2", "-no-pie", f"-DWIDTH={width}",
                                        str(root / "check.c"), str(root / "stack.S"),
                                        "-o", str(root / "check")], capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stderr)
                ran = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)


if __name__ == "__main__":
    unittest.main()
