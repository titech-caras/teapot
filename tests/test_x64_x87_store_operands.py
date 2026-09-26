import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import capstone_gt
import gtirb

from teapot.arch import X64Architecture
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass


# Encodings use [rdi]; width is architectural, not a decoder assertion.
STORES = (
    ("d917", 4), ("dd17", 8),                         # fst
    ("d91f", 4), ("dd1f", 8), ("db3f", 10),        # fstp
    ("df17", 2), ("db17", 4),                        # fist
    ("df1f", 2), ("db1f", 4), ("df3f", 8),         # fistp
    ("df0f", 2), ("db0f", 4), ("dd0f", 8),         # fisttp
    ("df37", 10), ("d93f", 2), ("dd3f", 2),        # fbstp, fnstcw, fnstsw
)


class X64X87StoreTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
        self.decoder.detail = True

    def decode(self, encoded):
        return next(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def test_x87_destinations_are_write_only(self):
        for encoded, width in STORES:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertEqual(operand.size, width)
                self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
                self.assertFalse(self.arch.mem_operand_is_read(inst, operand))

    def test_x87_reads_are_not_reclassified_as_stores(self):
        for encoded in ("d907", "dd07", "df07", "db07", "df2f", "d92f", "d807", "dc07"):
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
                self.assertFalse(self.arch.mem_operand_is_write(inst, operand))

    def test_x87_stores_get_full_width_rollback_logging(self):
        for encoded, width in STORES:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                block = gtirb.CodeBlock(size=inst.size)
                gtirb.ByteInterval(address=0x1000, contents=bytes(inst.bytes), blocks=[block])
                visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
                visitor.allocate_registers = mock.Mock(return_value=lambda patch: patch)
                visitor.insert_at = mock.Mock()
                visitor._build_memlog_patch = mock.Mock(wraps=visitor._build_memlog_patch)
                visitor.visit_inst(inst, 0, 0, block)
                self.assertEqual(visitor.insert_at.call_count, 1)
                self.assertEqual(visitor._build_memlog_patch.call_args.args[2], width)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, compiler and printer")
    def test_rewritten_x87_values_and_rollback(self):
        from gtirb_live_register_analysis import LiveRegisterManager
        from gtirb_rewriting import PassManager
        from test_live_register_preservation import make_module

        # Reset the x87 stack before each store; use disjoint destinations.
        stores = b""
        ranges = []
        offset = 1
        for encoded, width in STORES:
            opcode, modrm = bytes.fromhex(encoded)
            stores += bytes.fromhex("dbe3 d9e8") + bytes((opcode, modrm | 0x40, offset))
            ranges.append((offset, width))
            offset += width + 1
        code = stores + bytes.fromhex("dbe3 c3")
        ir, module, block, abi, registers = make_module(self.arch, gtirb.Module.ISA.X64, code)
        entry = next(module.symbols_named("test_function"))
        module.aux_data["sectionProperties"] = gtirb.AuxData(
            {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
        module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {entry: (block.size, "FUNC", "GLOBAL", "DEFAULT", 0)},
            "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
        for name in ("scratchpad", "old_rsp", "memory_history_top"):
            gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        manager = LiveRegisterManager(module, abi)
        for inst in manager.analyzer.decoder.get_instructions(block):
            module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                block, inst.address - block.address)] = (1 << len(registers)) - 1
        passes = PassManager()
        passes.add(X64TransientMemlogPass(manager, block.section, manager.analyzer.decoder, self.arch))
        passes.run(ir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ir.save_protobuf(root / "x87.gtirb")
            result = subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                     "--ir", str(root / "x87.gtirb"), "--asm", str(root / "x87.S")],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / "original.S").write_text(
                ".text\n.globl run_original\nrun_original:\n.byte " + ",".join(map(str, code)) +
                '\n.section .note.GNU-stack,"",@progbits\n')
            (root / "ranges.h").write_text("static const unsigned ranges[][2] = {" +
                ",".join("{%d,%d}" % item for item in ranges) + "};\n")
            fixture = Path(__file__).with_name("fixtures") / "x64_x87_memlog.c"
            result = subprocess.run(["cc", "-O2", "-no-pie", "-I", str(root), str(fixture),
                                     str(root / "original.S"), str(root / "x87.S"),
                                     "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("x87 stores and rollback passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
