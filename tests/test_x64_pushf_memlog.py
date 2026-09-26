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
from teapot.passes.common.dift.x64 import X64DiftPropagationPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass


class X64PushfMemlogTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
        self.decoder.detail = True

    def decode(self, encoded):
        return next(self.decoder.disasm(bytes.fromhex(encoded), 0x1000))

    def test_implicit_stack_writes_are_logged_at_exact_width(self):
        for encoded, width in (("669c", 2), ("9c", 8), ("489c", 8)):
            inst = self.decode(encoded)
            with self.subTest(instruction=str(inst)):
                block = gtirb.CodeBlock(size=inst.size)
                visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
                visitor.allocate_registers = mock.Mock(return_value=lambda patch: patch)
                visitor.insert_at = mock.Mock()
                visitor._build_memlog_patch = mock.Mock(wraps=visitor._build_memlog_patch)
                visitor.visit_inst(inst, 0, 0, block)
                self.assertEqual(visitor.insert_at.call_count, 1)
                self.assertEqual(visitor._build_memlog_patch.call_args.args[1:], (f"[rsp-{width}]", width))
                self.assertIsNone(visitor._build_memlog_patch.call_args.kwargs["conditional"])

    def test_flag_stack_operations_do_not_propagate_taint(self):
        for cls in (X64DiftPropagationPass, X64TextDiftPropagationLLVMPass):
            visitor = cls(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
            visitor._x64_instruction_effects = mock.Mock(side_effect=AssertionError("taint requested"))
            visitor.insert_at = mock.Mock()
            for encoded in ("9c", "669c", "489c", "9d", "669d"):
                inst = self.decode(encoded)
                with self.subTest(pass_name=cls.__name__, instruction=str(inst)):
                    self.assertTrue(self.arch.dift_should_skip_instruction(inst))
                    visitor.visit_inst(inst, 0, 0, gtirb.CodeBlock(size=inst.size))
            visitor._x64_instruction_effects.assert_not_called()
            visitor.insert_at.assert_not_called()

    def test_pop_flags_has_no_memory_write(self):
        for encoded in ("9d", "669d"):
            inst = self.decode(encoded)
            visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)
            visitor.insert_at = mock.Mock()
            visitor.visit_inst(inst, 0, 0, gtirb.CodeBlock(size=inst.size))
            visitor.insert_at.assert_not_called()

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, compiler and printer")
    def test_rewritten_flags_stack_pointer_and_rollback(self):
        from gtirb_live_register_analysis import LiveRegisterManager
        from gtirb_rewriting import PassManager
        from test_live_register_preservation import make_module

        # Return the flags just pushed, without modifying flags or doing any
        # additional memory stores inside the rewritten function.
        for encoding, width in (("9c58c3", 8), ("669c6658c3", 2)):
            with self.subTest(width=width), tempfile.TemporaryDirectory() as directory:
                code = bytes.fromhex(encoding)
                ir, module, block, abi, registers = make_module(self.arch, gtirb.Module.ISA.X64, code)
                entry = next(module.symbols_named("test_function"))
                module.aux_data["sectionProperties"] = gtirb.AuxData(
                    {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
                module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
                    {entry: (len(code), "FUNC", "GLOBAL", "DEFAULT", 0)},
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
                root = Path(directory)
                ir.save_protobuf(root / "pushf.gtirb")
                printed = subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                          "--ir", str(root / "pushf.gtirb"), "--asm", str(root / "pushf.S")],
                                         capture_output=True, text=True)
                self.assertEqual(printed.returncode, 0, printed.stderr)
                # The test uses a separate application stack so that C test
                # code cannot overwrite a logged slot before it is inspected.
                runners = ".intel_syntax noprefix\n.text\noriginal_function:\n.byte "
                runners += ",".join(map(str, code)) + "\n"
                for name, target in (("run_original", "original_function"), ("run_rewritten", "test_function")):
                    runners += f"""
                    .globl {name}
                    {name}:
                        mov [runner_rsp], rsp
                        push rsi
                        popfq
                        mov rsp, rdi
                        lea rsp, [rsp+256]
                        mov rax, 0
                        call {target}
                        mov [after_rsp], rsp
                        mov rsp, [runner_rsp]
                        cld
                        ret
                    """
                runners += '.section .note.GNU-stack,"",@progbits\n'
                (root / "runners.S").write_text(runners)
                fixture = Path(__file__).with_name("fixtures") / "x64_pushf_memlog.c"
                compiled = subprocess.run(["cc", "-O2", "-no-pie", f"-DWIDTH={width}", str(fixture),
                                           str(root / "runners.S"), str(root / "pushf.S"),
                                           "-o", str(root / "check")], capture_output=True, text=True)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                executed = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
                self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
                self.assertIn("PUSHF flags, stack and rollback passed", executed.stdout)


if __name__ == "__main__":
    unittest.main()
