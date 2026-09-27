from pathlib import Path
import platform
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import warnings
from unittest.mock import Mock

import gtirb
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_functions import Function
from gtirb_rewriting import Pass, PassManager, Patch

from teapot.arch.x64.architecture import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.configs.runtime import ROB_LEN, SCRATCHPAD_SIZE
from teapot.passes.transient.x64_rep import X64TransientRepPass
from teapot.passes.transient.transient_insert_restore_points_pass import TransientInsertRestorePointsPass
from teapot.pipeline import InstrumentationOptions, TeapotPipeline
import test_x64_rep_dift as rep_tests
from test_live_register_preservation import make_module


class X64TransientRepTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.decoder = x64_decoder()

    def test_rep_has_dynamic_not_static_cost(self):
        for code in ("f3a4", "67f348a5", "f2ae", "f3a6"):
            inst = next(self.decoder.disasm(bytes.fromhex(code), 0x1000))
            self.assertEqual(self.arch.static_instruction_cost(inst), 0)
            self.assertFalse(self.arch.instruction_must_rollback(inst))
        inst = next(self.decoder.disasm(bytes.fromhex("4889c0"), 0x1000))
        self.assertEqual(self.arch.static_instruction_cost(inst), 1)

    def test_rep_requires_iteration_budget(self):
        rep = X64TransientRepPass(
            SimpleNamespace(abi=self.arch.abi), None, None, self.arch,
            enable_checkpoints=False)
        for encoding in ("f3a4", "f2a4", "f2ae"):
            with self.subTest(encoding=encoding):
                inst = next(self.decoder.disasm(bytes.fromhex(encoding), 0x1000))
                with self.assertRaisesRegex(ValueError, "0x1000 requires checkpoints"):
                    rep.visit_inst(inst, 0, 0, None)

    def test_noncanonical_rep_warns_once_and_uses_existing_rollback(self):
        for encoding in ("f2a5", "67f2a5", "f2a4", "f248ab", "f2ac"):
            with self.subTest(encoding=encoding):
                code = bytes.fromhex(encoding)
                ir, module, block, abi, _ = make_module(self.arch, gtirb.Module.ISA.X64, code + b"\xc3")
                gtirb.Symbol(name="restore_checkpoint_EXT_LIB", payload=gtirb.ProxyBlock(module=module), module=module)
                manager = LiveRegisterManager(module, abi)
                decoder = manager.analyzer.decoder
                rep = X64TransientRepPass(manager, block.section, decoder, self.arch)
                passes = PassManager()
                passes.add(TransientInsertRestorePointsPass(
                    manager, block.section, block.section, decoder, self.arch))
                passes.add(rep)
                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always")
                    passes.run(ir)
                    # A repeated visit must not repeat the diagnostic or expand
                    # the instruction (no rewriting context remains here).
                    rep.visit_inst(next(self.decoder.disasm(code, 0x1000)), 0, 0, block)
                messages = [str(w.message) for w in captured if "Noncanonical REPNE" in str(w.message)]
                self.assertEqual(len(messages), 1)
                self.assertIn("0x1000", messages[0])
                interval = next(iter(block.section.byte_intervals))
                self.assertIn(code, bytes(interval.contents))
                destinations = [expr.symbol.name for expr in interval.symbolic_expressions.values()
                                if isinstance(expr, gtirb.SymAddrConst)]
                self.assertIn("restore_checkpoint_EXT_LIB", destinations)
                self.assertNotIn("instruction_cnt", destinations)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                         "requires native x64 and C compiler")
    def test_native_iteration_budget_state_tags_and_rollback(self):
        for enable_dift in (False, True):
            with self.subTest(enable_dift=enable_dift):
                self._check_native_matrix(enable_dift)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                         "requires native x64 and C compiler")
    def test_blacklisted_rep_keeps_execution_budget_and_memory_history(self):
        _, module, _, _, _ = make_module(self.arch, gtirb.Module.ISA.X64, b"\xf3\xa4\xc3")
        next(module.symbols_named("test_function")).name = "_start"
        function = next(iter(Function.build_functions(module)))
        self._check_native_matrix(False, function)

    def _check_native_matrix(self, enable_dift, function=None):
        functions, declarations, cases = [], [], []
        for kind, opcode in (("movs", 0xa4), ("stos", 0xaa), ("lods", 0xac),
                             ("cmps", 0xa6), ("scas", 0xae)):
            for width in (1, 2, 4, 8):
                for addr32 in (False, True):
                    for prefix in (0xf2, 0xf3) if kind in {"cmps", "scas"} else (0xf3,):
                        for segment in (False, True) if kind in {"movs", "lods", "cmps"} else (False,):
                            encoding = bytes(([0x65] if segment else []) + ([0x67] if addr32 else []) +
                                             ([0x66] if width == 2 else []) + [prefix] +
                                             ([0x48] if width == 8 else []) + [opcode + (width != 1)])
                            inst = next(self.decoder.disasm(encoding, 0x1000))
                            names = []
                            for mode in ("original", "common", "history"):
                                name = f"run_{len(cases)}_{mode}"
                                names.append(name)
                                before = ""
                                body = encoding
                                if mode != "original":
                                    dift = X64TransientRepPass(
                                        SimpleNamespace(abi=self.arch.abi), None, None, self.arch,
                                        dift_layout=SimpleNamespace(xor_mask=1 << 32),
                                        insert_memlog=mode == "history", enable_mem_policy=False,
                                        enable_port_policy=False, enable_dift=enable_dift or function is not None)
                                    before = rep_tests.wrapped_patch(
                                        self.arch, dift._build_rep_patch(
                                            dift._rep_string_effects(inst), inst, None, function=function))
                                    before = before.replace("__teapot__", "__teapot__" + name)
                                    body = b"\x90"
                                declarations.append(f"extern void {name}(struct state *);")
                                functions.append(rep_tests.runner_function(name, body, before, ""))
                            cases.append("{" + ",".join(names + [str(width), "4" if addr32 else "8",
                                                                 str(int(segment)),
                                                                 f"'{dict(movs='m', stos='s', lods='l', cmps='c', scas='t')[kind]}'"]) + "}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rep.S").write_text(
                ".intel_syntax noprefix\n.text\n" + "\n".join(functions) +
                "\n.globl restore_checkpoint_ROB_LEN\nrestore_checkpoint_ROB_LEN:\n"
                "pushfq\ntest qword ptr [rsp], 0x400\njnz bad_direction\npopfq\n"
                "jmp budget_stop\nbad_direction:\nud2\n" +
                '\n.section .note.GNU-stack,"",@progbits\n')
            (root / "cases.h").write_text("\n".join(declarations) +
                "\nstatic const struct test_case cases[] = {\n" + ",\n".join(cases) + "\n};\n")
            source = Path(__file__).with_name("fixtures") / "x64_transient_rep.c"
            result = subprocess.run([
                "cc", "-O2", "-no-pie", f"-DSCRATCHPAD_SIZE={SCRATCHPAD_SIZE}", f"-DROB_LEN={ROB_LEN}",
                f"-DTEST_DIFT_ENABLED={int(enable_dift)}",
                "-I", str(root), str(source), str(root / "rep.S"), "-o", str(root / "check"),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pipeline_registers_rep_after_all_same_round_insertions(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                ir, module, block, abi, _ = make_module(
                    self.arch, gtirb.Module.ISA.X64, b"\xf3\xa4\xc3")
                pipeline = TeapotPipeline(ir, options=InstrumentationOptions(enable_nested_speculation=nested))
                pipeline.arch = self.arch
                pipeline.reg_manager = LiveRegisterManager(module, abi)
                pipeline.decoder = pipeline.reg_manager.analyzer.decoder
                pipeline.dift_layout = SimpleNamespace(xor_mask=1 << 32, asan_shadow_offset=0x10000000)
                pipeline.text_section = pipeline.transient_section = block.section
                pipeline.guard_section = gtirb.Section(name=".guards", module=module)
                for name in ("text_section_start_symbol", "text_section_end_symbol",
                             "transient_section_start_symbol", "transient_section_end_symbol"):
                    setattr(pipeline, name, gtirb.Symbol(name=name, payload=block, module=module))
                pipeline.checkpoint_spare_registers = {}
                # This fixture bypasses preprocessing and contains no
                # conditional branch, hence no generated trampoline.
                pipeline.checkpoint_block_uuids = set()
                pipeline._run_pass_manager = Mock()
                pipeline._run_transient_passes()
                manager, phase = pipeline._run_pass_manager.call_args.args
                self.assertEqual(phase, "transient")
                self.assertIsInstance(manager._passes[-1], X64TransientRepPass)
                self.assertGreater(len(manager._passes), 6)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, C compiler and printer")
    def test_rewritten_memory_checks_reports_and_tag_flow(self):
        for encoding in ("f3a4", "6567f348a5", "f3ac", "f3aa", "f348a7", "f2ae", "48f3a5", "48f366a5"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                code = bytes.fromhex(encoding)
                inst = next(self.decoder.disasm(code, 0x1000))
                ir, module, block, abi, registers = make_module(self.arch, gtirb.Module.ISA.X64, code + b"\xc3")
                entry = next(module.symbols_named("test_function"))
                module.aux_data["sectionProperties"] = gtirb.AuxData(
                    {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
                module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
                    {entry: (len(code)+1, "FUNC", "GLOBAL", "DEFAULT", 0)},
                    "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
                for name in ("scratchpad", "dift_reg_tags", "dift_reg_queued_tags", "old_rsp", "ordering_seen",
                             "memory_history_top", "instruction_cnt", "restore_checkpoint_ROB_LEN",
                             "report_gadget_KASPER_CACHE", "report_gadget_KASPER_MDS", "report_gadget_KASPER_PORT"):
                    gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
                manager = LiveRegisterManager(module, abi)
                for original in manager.analyzer.decoder.get_instructions(block):
                    module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                        block, original.address - block.address)] = (1 << len(registers)) - 1
                layout = SimpleNamespace(xor_mask=1 << 32, asan_shadow_offset=0x10000000)
                rep = X64TransientRepPass(manager, block.section, manager.analyzer.decoder, self.arch,
                                           dift_layout=layout, insert_memlog=True)
                effects = rep._rep_string_effects(inst)
                passes = PassManager()
                # Other visitors share the original instruction stream. They
                # must not add a second one-element policy/DIFT/history patch.
                passes.add(self.arch.create_transient_mem_operand_policy_pass(
                    manager, block.section, manager.analyzer.decoder, dift_layout=layout, enable_asan_check=True))
                passes.add(self.arch.create_transient_dift_pass(manager, block.section, manager.analyzer.decoder, layout))
                passes.add(self.arch.create_transient_memlog_pass(manager, block.section, manager.analyzer.decoder))

                @self.arch.constraints(clobbers_flags=True)
                def mark(_ctx):
                    return "inc qword ptr [rip+ordering_seen]"

                class BeforeRep(Pass):
                    def begin_module(self, module, functions, context):
                        # A real same-offset insertion must execute once before
                        # the replacement loop, including an empty REP count.
                        context.insert_at(block, 0, Patch.from_function(mark))

                passes.add(BeforeRep())
                passes.add(rep)
                passes.run(ir)
                ir.save_protobuf(root / "rep.gtirb")
                result = subprocess.run([os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                                         "--ir", str(root / "rep.gtirb"), "--asm", str(root / "rep.S")],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                original = rep_tests.runner_function("run_original", code, "", "")
                rewritten = rep_tests.runner_function(
                    "rewritten", b"\x90", "call test_function\nmov qword ptr [rsp-8], 0x12345678\n", "")
                reports = ""
                for kind in ("CACHE", "MDS", "PORT"):
                    reports += f"""
                    .globl report_gadget_KASPER_{kind}
                    report_gadget_KASPER_{kind}:
                        pushfq
                        test qword ptr [rsp], 0x400
                        jnz bad_direction
                        popfq
                        inc qword ptr [rip+reports_{kind}]
                        ret
                    """
                (root / "runners.S").write_text(
                    ".intel_syntax noprefix\n.text\n" + original + rewritten + reports +
                    "\nbad_direction:\nud2\n.globl restore_checkpoint_ROB_LEN\nrestore_checkpoint_ROB_LEN:\nud2\n" +
                    '\n.section .note.GNU-stack,"",@progbits\n')
                kind = dict(movs="m", stos="s", lods="l", cmps="c", scas="t")[effects.kind]
                (root / "cases.h").write_text(
                    "extern void run_original(struct state *), rewritten(struct state *);\n" +
                    "static const struct test_case cases[] = {{run_original, rewritten, rewritten," +
                    f"{effects.width}, {effects.address_size}, {int(bool(effects.source_segment))}, '{kind}'" + "}};\n")
                source = Path(__file__).with_name("fixtures") / "x64_transient_rep_policies.c"
                result = subprocess.run(["cc", "-O2", "-no-pie", f"-DSCRATCHPAD_SIZE={SCRATCHPAD_SIZE}",
                                         "-I", str(root), str(source), str(root / "rep.S"),
                                         str(root / "runners.S"), "-o", str(root / "check")],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
