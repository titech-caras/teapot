import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import capstone
import gtirb

from teapot.arch import X64Architecture
from teapot.passes.common.dift.x64 import X64DiftPropagationPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass


# Encodings use [rdi]; width is architectural, not a decoder assertion.
STORES = (
    ("d917", 4), ("dd17", 8),                         # fst
    ("d91f", 4), ("dd1f", 8), ("db3f", 10),        # fstp
    ("df17", 2), ("db17", 4),                        # fist
    ("df1f", 2), ("db1f", 4), ("df3f", 8),         # fistp
    ("df0f", 2), ("db0f", 4), ("dd0f", 8),         # fisttp
    ("df37", 10), ("d93f", 2), ("dd3f", 2),        # fbstp, fnstcw, fnstsw
    ("d937", 28), ("66d937", 14),                   # fnstenv
    ("dd37", 108), ("66dd37", 94),                  # fnsave
)
READS = (
    ("d907", 4), ("dd07", 8), ("db2f", 10),        # fld
    ("df07", 2), ("db07", 4), ("df2f", 8),         # fild
    ("df27", 10), ("d92f", 2),                      # fbld, fldcw
    ("d807", 4), ("dc07", 8),                       # fadd
    ("d927", 28), ("66d927", 14),                   # fldenv
    ("dd27", 108), ("66dd27", 94),                  # frstor
)


class X64X87StoreTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True

    def decode(self, encoded):
        return next(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def test_x87_destinations_are_write_only(self):
        for encoded, width in STORES:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertEqual(self.arch.mem_operand_size(inst, operand), width)
                self.assertTrue(self.arch.mem_operand_is_write(inst, operand))
                self.assertFalse(self.arch.mem_operand_is_read(inst, operand))

    def test_x87_reads_are_not_reclassified_as_stores(self):
        for encoded, width in READS:
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                operand = self.arch.memory_operand(inst)
                self.assertEqual(self.arch.mem_operand_size(inst, operand), width)
                self.assertTrue(self.arch.mem_operand_is_read(inst, operand))
                self.assertFalse(self.arch.mem_operand_is_write(inst, operand))

    def test_x87_is_not_given_taint_propagation(self):
        encodings = [encoded for encoded, _ in STORES + READS]
        # Register-only arithmetic, FPU initialization, WAIT and FNSTSW AX.
        # Capstone 5 omits the FPU group from the last of these.
        encodings += ["d8c1", "dec1", "dbe3", "d9e8", "9b", "dfe0", "dbf1"]
        for cls in (X64DiftPropagationPass, X64TextDiftPropagationLLVMPass):
            visitor = cls(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
            visitor._x64_instruction_effects = mock.Mock(side_effect=AssertionError("taint requested"))
            visitor.insert_at = mock.Mock()
            for encoded in encodings:
                inst = self.decode(encoded)
                with self.subTest(pass_name=cls.__name__, instruction=str(inst)):
                    self.assertTrue(self.arch.dift_should_skip_instruction(inst))
                    visitor.visit_inst(inst, 0, 0, gtirb.CodeBlock(size=inst.size))
            visitor._x64_instruction_effects.assert_not_called()
            visitor.insert_at.assert_not_called()

    def test_sse_is_not_skipped_with_x87(self):
        for encoded in ("f20f1007", "f20f1107", "f20f58c1"):
            with self.subTest(encoded=encoded):
                self.assertFalse(self.arch.dift_should_skip_instruction(self.decode(encoded)))

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
            if encoded.startswith("66"):
                # The pinned printer loses 66h on FNSTENV/FNSAVE. Exercise
                # those exact encodings in the direct native patch test below,
                # independently of that printer round-trip defect.
                continue
            instruction = bytes.fromhex(encoded)
            # State images contain the last x87 instruction's address. FNINIT
            # clears it, making original/rewrite comparisons independent of
            # their code addresses; scalar stores use ST(0) = 1 instead.
            stores += bytes.fromhex("dbe3")
            if self.decode(encoded).mnemonic not in ("fnstenv", "fnsave"):
                stores += bytes.fromhex("d9e8")
            stores += (instruction[:-1] + bytes((instruction[-1] | 0x80,)) +
                       offset.to_bytes(4, "little"))
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
        # "No taint" must not mean clearing memory tags, nor should stores
        # require a mapped taint shadow just to get rollback logging.
        passes.add(X64DiftPropagationPass(manager, block.section, manager.analyzer.decoder, self.arch))
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
                ",".join("{%d,%d}" % item for item in ranges) + "};\n" +
                f"#define BUFFER_SIZE {offset + 16}\n")
            fixture = Path(__file__).with_name("fixtures") / "x64_x87_memlog.c"
            result = subprocess.run(["cc", "-O2", "-no-pie", "-I", str(root), str(fixture),
                                     str(root / "original.S"), str(root / "x87.S"),
                                     "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("x87 stores and rollback passed", result.stdout)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                         "requires native x64 and compiler")
    def test_16bit_state_store_patches_restore_every_byte(self):
        from gtirb_rewriting import InsertionContext

        visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
        for encoded, width in (("66d937", 14), ("66dd37", 94)):
            with self.subTest(encoded=encoded), tempfile.TemporaryDirectory() as directory:
                inst = self.decode(encoded)
                operand = self.arch.memory_operand(inst)
                patch = visitor._build_memlog_patch(inst, "[rdi]", self.arch.mem_operand_size(inst, operand))
                allocation = self.arch.abi._allocate_patch_registers(patch.constraints)
                prologue, epilogue, _ = self.arch.abi._create_prologue_and_epilogue(
                    patch.constraints, allocation, True)
                body = patch(InsertionContext(None, None, None, 0,
                                               scratch_registers=allocation.scratch_registers))
                wrapped = (".att_syntax prefix\n" + "\n".join(s.code for s in prologue) +
                           "\n.intel_syntax noprefix\n" + body + "\n.att_syntax prefix\n" +
                           "\n".join(s.code for s in epilogue) + "\n.intel_syntax noprefix\n")
                store = ".byte " + ",".join(map(str, bytes.fromhex(encoded))) + "\n"
                root = Path(directory)
                (root / "state.S").write_text(
                    ".intel_syntax noprefix\n.text\n.globl run_original\nrun_original:\n"
                    "fninit\n" + store + "fninit\nret\n.globl test_function\ntest_function:\n"
                    "fninit\n" + wrapped + store + "fninit\nret\n" +
                    '.section .note.GNU-stack,"",@progbits\n')
                (root / "ranges.h").write_text(
                    f"static const unsigned ranges[][2] = {{{{0,{width}}}}};\n#define BUFFER_SIZE 128\n")
                fixture = Path(__file__).with_name("fixtures") / "x64_x87_memlog.c"
                compiled = subprocess.run(["cc", "-O2", "-no-pie", "-I", str(root), str(fixture),
                                           str(root / "state.S"), "-o", str(root / "check")],
                                          capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                executed = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
                self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)


if __name__ == "__main__":
    unittest.main()
