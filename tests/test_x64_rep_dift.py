from pathlib import Path
from itertools import product
import os
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_rewriting import InsertionContext, RewritingContext

from teapot.arch.x64.architecture import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.passes.common.dift.x64 import X64DiftPropagationPass
from teapot.passes.text.dift.x64 import X64TextDiftPropagationLLVMPass
from test_live_register_preservation import make_module


def wrapped_patch(arch, patch):
    # Exercise the real all-live ABI spill path, not hand-picked scratch GPRs.
    allocation = arch.abi._allocate_patch_registers(patch.constraints)
    prologue, epilogue, _ = arch.abi._create_prologue_and_epilogue(
        patch.constraints, allocation, True)
    body = patch(InsertionContext(None, None, None, 0, scratch_registers=allocation.scratch_registers))
    return (
        ".att_syntax prefix\n" + "\n".join(s.code for s in prologue) +
        "\n.intel_syntax noprefix\n" + body +
        "\n.att_syntax prefix\n" + "\n".join(s.code for s in epilogue) +
        "\n.intel_syntax noprefix\n")


def runner_function(name, encoding, before, after):
    sentinels = ("rdx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
    setup = "\n".join(f"mov {reg}, {0x123400 + i}" for i, reg in enumerate(sentinels))
    save = "\n".join(f"mov [rbx+{40+8*i}], {reg}" for i, reg in enumerate(sentinels))
    redzone = "\n".join(f"mov qword ptr [rsp-{i}], 0x12345678" for i in range(8, 129, 8))
    check_redzone = "\n".join(
        f"mov rax, [rsp-{i}]\nmov [rbx+{120+i}], rax" for i in range(8, 129, 8))
    return f"""
    .globl {name}
    {name}:
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
        mov rbx, rdi
        {setup}
        mov rax, [rbx]
        mov rsi, [rbx+8]
        mov rdi, [rbx+16]
        mov rcx, [rbx+24]
        push qword ptr [rbx+32]
        popfq
        {redzone}
        {before}
        .byte {','.join(map(str, encoding))}
        {after}
        mov [rbx], rax
        mov [rbx+8], rsi
        mov [rbx+16], rdi
        mov [rbx+24], rcx
        {save}
        {check_redzone}
        pushfq
        pop qword ptr [rbx+32]
        cld
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        ret
    """


class X64RepDiftTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.dift = X64DiftPropagationPass(
            SimpleNamespace(abi=self.arch.abi), None, None, self.arch,
            dift_layout=SimpleNamespace(xor_mask=1 << 32))
        self.decoder = x64_decoder()

    def test_only_repeat_string_opcodes_are_classified(self):
        for encoding in ("f3c3", "f390", "f30f1006", "f20f1006", "a4"):
            inst = next(self.decoder.disasm(bytes.fromhex(encoding), 0x1000))
            self.assertIsNone(self.dift._rep_string_effects(inst), inst)

    def test_noncanonical_repeat_forms_keep_text_effects_and_require_rollback(self):
        for encoding in ("f2a5", "67f2a5", "f2a4", "f248ab", "f2ac"):
            inst = next(self.decoder.disasm(bytes.fromhex(encoding), 0x1000))
            self.assertIsNotNone(self.dift._rep_string_effects(inst))
            self.assertTrue(self.arch.instruction_must_rollback(inst))

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc"),
                         "requires native x64 and C compiler")
    def test_native_values_tags_flags_spills_and_history(self):
        source = Path(__file__).with_name("fixtures") / "x64_rep_dift.c"
        cases = []
        functions = []
        declarations = []
        for kind, opcode in (("movs", 0xa4), ("stos", 0xaa), ("lods", 0xac),
                             ("cmps", 0xa6), ("scas", 0xae)):
            for width in (1, 2, 4, 8):
                for address_size in (4, 8):
                    for prefix in (0xf2, 0xf3) if kind in {"cmps", "scas"} else (0xf3,):
                        for segment in (False, True) if kind in {"movs", "lods", "cmps"} else (False,):
                            encoding = bytes(([0x65] if segment else []) +
                                             ([0x67] if address_size == 4 else []) +
                                             ([0x66] if width == 2 else []) + [prefix] +
                                             ([0x48] if width == 8 else []) +
                                             [opcode + (width != 1)])
                            inst = next(self.decoder.disasm(encoding, 0x1000))
                            effects = self.dift._rep_string_effects(inst)
                            self.assertIsNotNone(effects, (encoding.hex(), inst, list(inst.prefix)))
                            self.assertFalse(self.arch.instruction_must_rollback(inst))
                            self.assertEqual((effects.kind, effects.width, effects.address_size),
                                             (kind, width, address_size))
                            names = []
                            for mode in ("original", "common", "history"):
                                name = f"run_{len(cases)}_{mode}"
                                names.append(name)
                                before = after = ""
                                if mode != "original":
                                    dift = X64DiftPropagationPass(
                                        SimpleNamespace(abi=self.arch.abi), None, None, self.arch,
                                        dift_layout=SimpleNamespace(xor_mask=1 << 32),
                                        insert_memlog=mode == "history")
                                    before = wrapped_patch(self.arch, dift._build_rep_capture_patch(effects))
                                    after = wrapped_patch(self.arch, dift._build_rep_tags_patch(effects))
                                    after = after.replace(".L__rep_dift", f".L__rep_dift_{name}")
                                declarations.append(f"extern void {name}(struct state *);")
                                functions.append(runner_function(name, encoding, before, after))
                            cases.append("{" + ",".join(names + [str(width), str(address_size),
                                                                 str(int(segment)),
                                                                 f"'{dict(movs='m', stos='s', lods='l', cmps='c', scas='t')[kind]}'"]) + "}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rep.S").write_text(
                ".intel_syntax noprefix\n.text\n" + "\n".join(functions) +
                '\n.section .note.GNU-stack,"",@progbits\n')
            (root / "cases.h").write_text("\n".join(declarations) +
                "\nstatic const struct test_case cases[] = {\n" + ",\n".join(cases) + "\n};\n")
            result = subprocess.run([
                "cc", "-O2", "-no-pie", f"-DSCRATCHPAD_SIZE={SCRATCHPAD_SIZE}",
                "-I", str(root), str(source), str(root / "rep.S"), "-o", str(root / "check"),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc")
                         and shutil.which(os.environ.get("PPRINTER_PATH", "gtirb-pprinter")),
                         "requires native x64, C compiler and printer")
    def test_rewritten_llvm_batches_observe_rep_tags(self):
        # Values flow into REP, out of REP into ordinary LLVM DIFT, then into
        # another REP. Also exercise a REP ending a physical fallthrough block.
        source = Path(__file__).with_name("fixtures") / "x64_rep_dift_batches.c"
        for cls in (X64DiftPropagationPass, X64TextDiftPropagationLLVMPass):
            for split, adjacent, encoding in product(
                    (False, True), (False, True), ("f3a4", "f3a5", "6567f348a5", "6766f3a5")):
                with self.subTest(mode=cls.__name__, split=split, adjacent=adjacent,
                                  encoding=encoding), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    instruction = bytes.fromhex(encoding)
                    effects = self.dift._rep_string_effects(next(self.decoder.disasm(instruction, 0)))
                    code = (bytes.fromhex("4889d1") + instruction +
                            (b"" if adjacent else bytes.fromhex("8a47ff 4889d1")) +
                            bytes.fromhex("f3aa 8a47ff c3"))
                    ir, module, block, abi, registers = make_module(
                        self.arch, gtirb.Module.ISA.X64, code)
                    entry = next(module.symbols_named("test_function"))
                    module.aux_data["sectionProperties"] = gtirb.AuxData(
                        {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
                    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
                        {entry: (len(code), "FUNC", "GLOBAL", "DEFAULT", 0)},
                        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
                    if split:
                        block.size = 3 + len(instruction)
                        tail = gtirb.CodeBlock(size=len(code)-block.size, offset=block.size,
                                               byte_interval=block.byte_interval)
                        next(iter(module.aux_data["functionBlocks"].data.values())).add(tail)
                        ir.cfg.add(gtirb.Edge(block, tail, gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough)))
                        alternate_entry = gtirb.Symbol(name="tail_entry", payload=tail, module=module)
                        module.aux_data["elfSymbolInfo"].data[alternate_entry] = (
                            tail.size, "FUNC", "GLOBAL", "DEFAULT", 0)
                    for name in ("scratchpad", "dift_reg_tags", "dift_reg_queued_tags", "old_rsp"):
                        gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
                    manager = LiveRegisterManager(module, abi)
                    for part in module.code_blocks:
                        for inst in manager.analyzer.decoder.get_instructions(part):
                            module.aux_data["liveRegisterSets"].data[gtirb.Offset(
                                part, inst.address - part.address)] = (1 << len(registers)) - 1
                    functions = list(Function.build_functions(module))
                    context = RewritingContext(module, functions)
                    dift = cls(manager, block.section, manager.analyzer.decoder, self.arch,
                               dift_layout=SimpleNamespace(xor_mask=1 << 32))
                    dift.begin_module(module, functions, context)
                    context.apply()
                    dift.end_module(module, functions)
                    self.assertEqual(len(ir.modules), 1)
                    self.assertGreater(len(list(module.code_blocks)), 0)
                    ir.save_protobuf(root / "rewritten.gtirb")
                    result = subprocess.run([
                        os.environ.get("PPRINTER_PATH", "gtirb-pprinter"),
                        "--ir", str(root / "rewritten.gtirb"), "--asm", str(root / "rewritten.S"),
                    ], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue((root / "rewritten.S").stat().st_size, result.stdout + result.stderr)
                    result = subprocess.run([
                        "cc", "-O2", "-no-pie", f"-DSCRATCHPAD_SIZE={SCRATCHPAD_SIZE}",
                        f"-DWIDTH={effects.width}", f"-DSOURCE_SEGMENT={int(bool(effects.source_segment))}",
                        f"-DSPLIT={int(split)}", f"-DADJACENT={int(adjacent)}",
                        str(source), str(root / "rewritten.S"), "-o", str(root / "check"),
                    ], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr + (root / "rewritten.S").read_text())
                    result = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
