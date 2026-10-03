import unittest
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock

import gtirb

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass


class X64SetccMemoryTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = x64_decoder()

    def instructions(self):
        for opcode in range(0x90, 0xa0):
            # Stack, RIP-relative and extended base/index byte destinations.
            for data in (bytes([0x0f, opcode, 0x44, 0x24, 0x38]),
                         bytes([0x0f, opcode, 0x05, 0, 0, 0, 0]),
                         bytes([0x43, 0x0f, opcode, 0x44, 0x4c, 3])):
                yield next(self.decoder.disasm(data, 0x1000))

    def test_all_conditions_write_one_byte_without_reading_destination(self):
        for inst in self.instructions():
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertIsNotNone(operand)
                self.assertEqual(operand.size, 1)
                self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
                self.assertFalse(self.arch.mem_operand_is_read(inst, operand))

    def test_all_conditions_get_unconditional_rollback_logging(self):
        for opcode in range(0x90, 0xa0):
            inst = next(self.decoder.disasm(bytes([0x0f, opcode, 0x07]), 0x1000))
            with self.subTest(mnemonic=inst.mnemonic):
                block = gtirb.CodeBlock(size=inst.size)
                gtirb.ByteInterval(address=0x1000, contents=bytes(inst.bytes), blocks=[block])
                visitor = X64TransientMemlogPass(
                    SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
                visitor.allocate_registers = mock.Mock(return_value=lambda patch: patch)
                visitor.insert_at = mock.Mock()
                visitor._build_memlog_patch = mock.Mock(wraps=visitor._build_memlog_patch)
                visitor.visit_inst(inst, 0, 0, block)
                self.assertEqual(visitor.insert_at.call_count, 1)
                call = visitor._build_memlog_patch.call_args
                self.assertEqual(call.args[2], 1)
                # False SETcc writes zero too; logging must never be predicated.
                self.assertIsNone(call.kwargs["conditional"])

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, compiler and printer")
    def test_rewritten_stores_restore_both_true_and_false_results(self):
        from teapot.liveness import LiveRegisterManager
        from gtirb_rewriting import PassManager
        from test_live_register_preservation import make_module

        stores = b"".join(bytes([0x0f, opcode, 0x47, opcode - 0x90])
                          for opcode in range(0x90, 0xa0))
        ir, module, block, abi, registers = make_module(
            self.arch, gtirb.Module.ISA.X64, stores + b"\xc3")
        entry = next(module.symbols_named("test_function"))
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {entry: (block.size, "FUNC", "GLOBAL", "DEFAULT", 0)},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        for name in ("scratchpad", "old_rsp", "memory_history_top"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        manager = LiveRegisterManager(module, abi)
        for inst in manager.decoder.get_instructions(block):
            module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                block, inst.address - block.address)] = (1 << len(registers)) - 1
        passes = PassManager()
        passes.add(X64TransientMemlogPass(manager, block.section, manager.decoder, self.arch))
        passes.run(ir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / "setcc.gtirb")
            printed = subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                      "--ir", str(root / "setcc.gtirb"), "--asm", str(root / "setcc.S")],
                                     capture_output=True, text=True)
            self.assertEqual(printed.returncode, 0, printed.stderr)
            (root / "runners.S").write_text(
                ".intel_syntax noprefix\n.text\n.globl run_original\nrun_original:\n"
                "push rsi\npopfq\n.byte " + ",".join(map(str, stores)) +
                "\npushfq\npop rax\nret\n.globl run_rewritten\nrun_rewritten:\n"
                "lea rsp, [rsp-8]\npush rsi\npopfq\ncall test_function\n"
                "pushfq\npop rax\nlea rsp, [rsp+8]\nret\n"
                '.section .note.GNU-stack,"",@progbits\n')
            source = Path(__file__).with_name("fixtures") / "x64_setcc_memlog.c"
            compiled = subprocess.run(["cc", "-O2", "-no-pie", str(source),
                                       str(root / "setcc.S"), str(root / "runners.S"),
                                       "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("all SETcc stores and rollback passed", executed.stdout)


    def test_register_destinations_are_not_memory_accesses(self):
        for opcode in range(0x90, 0xa0):
            inst = next(self.decoder.disasm(bytes([0x0f, opcode, 0xc0]), 0x1000))
            with self.subTest(mnemonic=inst.mnemonic):
                self.assertIsNone(self.arch.memory_operand(inst))


if __name__ == "__main__":
    unittest.main()
