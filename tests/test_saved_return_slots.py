import io
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis import LiveRegisterManager
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Assembler, PassManager

from teapot.arch import AArch64Architecture, RISCV64Architecture
from teapot.passes.common.asan_stack_pass import AsanStackPass
from teapot.passes.common.return_slot_analysis import ReturnSlotAnalysis, UnsupportedReturnSlot
from teapot.passes.preprocessing.import_symbols_pass import ImportSymbolsPass
from test_live_register_preservation import make_module


class SavedReturnSlotTests(unittest.TestCase):
    def make_function(self, arch, chunks, edges=()):
        isa = gtirb.Module.ISA.ARM64 if arch.name == "aarch64" else gtirb.Module.ISA.ValidButUnsupported
        ir, module, first, abi, registers = make_module(arch, isa, b"\0" * 4)
        interval = first.byte_interval
        contents = bytearray()
        blocks = []
        for index, chunk in enumerate(chunks):
            assembler = Assembler(module)
            assembler.assemble((".option rvc\n" if arch.name == "riscv64" and "c." in chunk else "") + chunk)
            data = assembler.finalize().text_section.data
            block = first if index == 0 else gtirb.CodeBlock(byte_interval=interval)
            block.offset, block.size = len(contents), len(data)
            contents.extend(data)
            blocks.append(block)
        interval.contents = contents
        interval.size = len(contents)
        function_id = next(iter(module.aux_data["functionBlocks"].data))
        module.aux_data["functionBlocks"].data[function_id] = set(blocks)
        for source, target, kind in edges:
            destination = gtirb.ProxyBlock(module=module) if target is None else blocks[target]
            label = kind if isinstance(kind, gtirb.Edge.Label) else gtirb.Edge.Label(kind)
            module.ir.cfg.add(gtirb.Edge(blocks[source], destination, label))
        decoder = CachedGtirbInstructionDecoder(isa)
        manager = LiveRegisterManager(module, abi, decoder, analysis_scope="block")
        manager.analyzer.analyze = Mock(side_effect=AssertionError("Unexpected Python LRA fallback"))
        function = next(iter(Function.build_functions(module)))
        return ir, module, blocks, function, decoder, manager

    def analyze(self, arch, chunks, edges=()):
        _, _, _, function, decoder, _ = self.make_function(arch, chunks, edges)
        return ReturnSlotAnalysis(arch, decoder).analyze(function)

    def test_scalar_pair_and_compressed_slot_positions(self):
        cases = (
            (AArch64Architecture(), "stp x29,x30,[sp,#-32]!\nmov x29,sp\nldp x29,x30,[sp],#32\nret", 1, 8, 2, 8),
            (AArch64Architecture(), "stp x30,x29,[sp,#-16]!\nldp x30,x29,[sp],#16\nret", 1, 0, 1, 0),
            (AArch64Architecture(), "sub sp,sp,#32\nstr x30,[sp,#24]\nadd x29,sp,#32\nldur x30,[x29,#-8]\nadd sp,sp,#32\nret", 2, 24, 3, -8),
            (AArch64Architecture(), "stp x29,x30,[sp,#-16]!\nldr x30,[sp,#8]\nldr x29,[sp],#16\nret", 1, 8, 1, 8),
            (RISCV64Architecture(), "addi sp,sp,-32\nsd ra,24(sp)\nld ra,24(sp)\naddi sp,sp,32\nret", 2, 24, 2, 24),
            (RISCV64Architecture(), "c.addi16sp sp,-32\nc.sdsp ra,24(sp)\nc.ldsp ra,24(sp)\nc.addi16sp sp,32\nret", 2, 24, 2, 24),
            (RISCV64Architecture(), "addi sp,sp,-32\nsd ra,24(sp)\naddi s0,sp,32\nld ra,-8(s0)\naddi sp,sp,32\nret", 2, 24, 3, -8),
        )
        for arch, code, after_save, save_offset, before_load, load_offset in cases:
            with self.subTest(arch=arch.name, code=code):
                sites = self.analyze(arch, [code])
                self.assertEqual([(site.instruction_index, site.displacement, site.poison) for site in sites],
                                 [(after_save, save_offset, True), (before_load, load_offset, False)])

    def test_call_and_multiple_epilogues(self):
        for arch, chunks in (
            (AArch64Architecture(), ["stp x29,x30,[sp,#-16]!\nblr x0",
                                    "nop", "ldp x29,x30,[sp],#16\nret", "ldp x29,x30,[sp],#16\nret"]),
            (RISCV64Architecture(), ["addi sp,sp,-16\nsd ra,8(sp)\njalr ra,a0,0",
                                    "nop", "ld ra,8(sp)\naddi sp,sp,16\nret", "ld ra,8(sp)\naddi sp,sp,16\nret"]),
        ):
            with self.subTest(arch=arch.name):
                sites = self.analyze(arch, chunks, [(0, None, gtirb.Edge.Type.Call),
                    (0, 1, gtirb.Edge.Type.Fallthrough), (1, 2, gtirb.Edge.Type.Branch),
                    (1, 3, gtirb.Edge.Type.Fallthrough)])
                self.assertEqual([site.poison for site in sites], [True, False, False])

    def test_shrink_wrapped_early_return_does_not_invent_a_slot(self):
        arch = AArch64Architecture()
        sites = self.analyze(arch, ["nop", "stp x29,x30,[sp,#-16]!\nldp x29,x30,[sp],#16", "ret"],
                             [(0, 1, gtirb.Edge.Type.Branch), (0, 2, gtirb.Edge.Type.Fallthrough),
                              (1, 2, gtirb.Edge.Type.Fallthrough)])
        self.assertEqual(len(sites), 2)

    def test_noreturn_call_is_not_a_return_slot_exit(self):
        for arch, chunks in (
            (AArch64Architecture(), ["stp x29,x30,[sp,#-16]!", "blr x0",
                                    "ldp x29,x30,[sp],#16\nret"]),
            (RISCV64Architecture(), ["addi sp,sp,-16\nsd ra,8(sp)", "jalr ra,a0,0",
                                    "ld ra,8(sp)\naddi sp,sp,16\nret"]),
        ):
            with self.subTest(arch=arch.name):
                sites = self.analyze(arch, chunks, [(0, 1, gtirb.Edge.Type.Branch),
                    (0, 2, gtirb.Edge.Type.Fallthrough), (1, None, gtirb.Edge.Type.Call)])
                self.assertEqual([site.poison for site in sites], [True, False])

    def test_resolved_indirect_targets_keep_return_slot_lifetime(self):
        indirect = gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False)
        for arch, chunks in (
            (AArch64Architecture(), ["stp x29,x30,[sp,#-16]!\nbr x0",
                                    "ldp x29,x30,[sp],#16\nret", "ldp x29,x30,[sp],#16\nret"]),
            (RISCV64Architecture(), ["addi sp,sp,-16\nsd ra,8(sp)\njr a0",
                                    "ld ra,8(sp)\naddi sp,sp,16\nret", "ld ra,8(sp)\naddi sp,sp,16\nret"]),
        ):
            with self.subTest(arch=arch.name):
                sites = self.analyze(arch, chunks, [(0, 1, indirect), (0, 2, indirect)])
                self.assertEqual([site.poison for site in sites], [True, False, False])
                with self.assertRaisesRegex(UnsupportedReturnSlot, "unresolved indirect branch"):
                    self.analyze(arch, chunks, [(0, 1, indirect), (0, None, indirect)])

    def test_aarch64_small_immediates_are_not_register_reads(self):
        arch = AArch64Architecture()
        for immediate in (2, 3, 5):
            with self.subTest(immediate=immediate):
                _, _, blocks, function, decoder, _ = self.make_function(
                    arch, [f"cmp w1, #{immediate}\nret"])
                inst = next(iter(decoder.get_instructions(blocks[0])))
                reads = arch.access_registers(arch.abi, inst, 0)
                self.assertEqual(reads, {arch.abi.get_register("x1")})
                self.assertEqual(ReturnSlotAnalysis(arch, decoder).analyze(function), ())

    def test_unwind_rows_are_not_an_analysis_gate(self):
        arch = RISCV64Architecture()
        _, module, blocks, function, decoder, _ = self.make_function(arch, [
            "addi sp,sp,-16\nsd ra,8(sp)\nld ra,8(sp)\naddi sp,sp,16\nret"])
        expected = ReturnSlotAnalysis(arch, decoder).analyze(function)
        module.aux_data["cfiDirectives"] = gtirb.AuxData(
            {gtirb.Offset(blocks[0], 0): [(".cfi_startproc", [], module.uuid)]},
            "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>")
        self.assertEqual(ReturnSlotAnalysis(arch, decoder).analyze(function), expected)

    def test_frame_pointer_register_can_hold_an_ordinary_data_pointer(self):
        for arch, code in (
            (RISCV64Architecture(), "addi sp,sp,-32\nsd ra,24(sp)\nsd s0,16(sp)\nmv s0,a0\nld a1,0(s0)\nld ra,24(sp)\nld s0,16(sp)\naddi sp,sp,32\nret"),
            (AArch64Architecture(), "stp x29,x30,[sp,#-32]!\nmov x29,x0\nldr x1,[x29]\nldp x29,x30,[sp],#32\nret"),
        ):
            with self.subTest(arch=arch.name):
                self.assertEqual(len(self.analyze(arch, [code])), 2)

    def test_only_declared_checkpoint_sections_can_enter_an_interior_block(self):
        arch = AArch64Architecture()
        _, module, blocks, function, decoder, _ = self.make_function(arch,
            ["stp x29,x30,[sp,#-16]!", "ldp x29,x30,[sp],#16\nret"],
            [(0, 1, gtirb.Edge.Type.Fallthrough)])
        checkpoint_section = gtirb.Section(name=".teapot_trampolines", module=module)
        source = gtirb.CodeBlock(size=4, byte_interval=gtirb.ByteInterval(
            address=0x8000, contents=b"\0" * 4, section=checkpoint_section))
        module.ir.cfg.add(gtirb.Edge(source, blocks[1], gtirb.Edge.Label(gtirb.Edge.Type.Branch)))
        with self.assertRaisesRegex(UnsupportedReturnSlot, "interior function entry"):
            ReturnSlotAnalysis(arch, decoder).analyze(function)
        self.assertEqual(len(ReturnSlotAnalysis(arch, decoder).analyze(
            function, checkpoint_sources={checkpoint_section})), 2)

    def test_rejects_unproven_lifetimes(self):
        cases = (
            (AArch64Architecture(), "stp x29,x30,[sp,#-32]!\nstr x0,[sp,#8]\nldp x29,x30,[sp],#32\nret", "another instruction"),
            (AArch64Architecture(), "stp x29,x30,[sp,#-32]!\nldr x30,[sp,#24]\nadd sp,sp,#32\nret", "reload does not name"),
            (AArch64Architecture(), "mov x30,x0\nstp x29,x30,[sp,#-16]!\nldp x29,x30,[sp],#16\nret", "incoming LR"),
            (AArch64Architecture(), "paciasp\nstp x29,x30,[sp,#-16]!\nldp x29,x30,[sp],#16\nautiasp\nret", "incoming LR"),
            (AArch64Architecture(), "stp x29,x30,[sp,#-16]!\nsub sp,sp,x0\nldp x29,x30,[sp],#16\nret", "reload does not name"),
            (AArch64Architecture(), "stp x29,x30,[sp,#-32]!\nstp x29,x30,[sp,#16]\nldp x29,x30,[sp],#32\nret", "one memory save"),
            (AArch64Architecture(), "stp x29,x30,[sp,#-16]!\nldp x29,x30,[sp],#16\nblr x0\nret", "exit does not restore"),
            (RISCV64Architecture(), "addi sp,sp,-16\nsd ra,8(sp)\nadd sp,sp,a0\nld ra,8(sp)\nret", "reload does not name"),
            (RISCV64Architecture(), "addi sp,sp,-16\nsd ra,4(sp)\nld ra,4(sp)\naddi sp,sp,16\nret", "unaligned"),
            (RISCV64Architecture(), "mv s0,ra\njalr ra,a0,0\nmv ra,s0\nret", "one memory save"),
        )
        for arch, code, message in cases:
            with self.subTest(arch=arch.name, code=code), self.assertRaisesRegex(UnsupportedReturnSlot, message):
                self.analyze(arch, [code])

    def test_save_must_dominate_each_reload(self):
        with self.assertRaisesRegex(UnsupportedReturnSlot, "dominated"):
            self.analyze(AArch64Architecture(), ["sub sp,sp,#16", "str x30,[sp,#8]",
                "ldr x30,[sp,#8]\nadd sp,sp,#16\nret"], [(0, 1, gtirb.Edge.Type.Branch),
                (0, 2, gtirb.Edge.Type.Fallthrough), (1, 2, gtirb.Edge.Type.Fallthrough)])

    def test_pass_summarizes_omission_reasons_without_changing_code(self):
        arch = AArch64Architecture()
        ir, _, blocks, _, decoder, registers = self.make_function(arch, [
            "mov x30,x0\nstp x29,x30,[sp,#-16]!\nldp x29,x30,[sp],#16\nret"])
        original = bytes(blocks[0].byte_interval.contents)
        stack_pass = AsanStackPass(registers, blocks[0].section, decoder, arch, True)
        passes = PassManager()
        passes.add(stack_pass)
        output = io.StringIO()
        with redirect_stdout(output), self.assertWarnsRegex(RuntimeWarning, "incoming LR"):
            passes.run(ir)
        reason = "save is repeated or no longer holds incoming LR"
        self.assertEqual(stack_pass.unsupported_reasons, {reason: 1})
        self.assertIn(f"saved-return omissions .text: {reason}=1", output.getvalue())
        self.assertEqual(bytes(blocks[0].byte_interval.contents), original)

    def test_pass_inserts_without_spare_registers_and_omits_mte(self):
        for arch, code in (
            (AArch64Architecture(), "stp x29,x30,[sp,#-16]!\nnop\nldp x29,x30,[sp],#16\nret"),
            (RISCV64Architecture(), "addi sp,sp,-16\nsd ra,8(sp)\nnop\nld ra,8(sp)\naddi sp,sp,16\nret"),
        ):
            for storage in (("shadow", "mte") if arch.name == "aarch64" else ("shadow",)):
                with self.subTest(arch=arch.name, storage=storage):
                    ir, module, blocks, _, decoder, registers = self.make_function(arch, [code])
                    original = bytes(blocks[0].byte_interval.contents)
                    stack_pass = AsanStackPass(registers, blocks[0].section, decoder, arch, True,
                        dift_layout=SimpleNamespace(asan_shadow_offset=0), tag_storage=storage)
                    passes = PassManager()
                    passes.add(ImportSymbolsPass(arch.checkpoint_lib_symbols()))
                    passes.add(stack_pass)
                    with redirect_stdout(io.StringIO()):
                        passes.run(ir)
                    if storage == "mte":
                        self.assertEqual(stack_pass.coverage["MTE omitted"], 1)
                        self.assertEqual(bytes(blocks[0].byte_interval.contents), original)
                    else:
                        self.assertEqual(stack_pass.coverage["instrumented"], 1)
                        self.assertTrue(any(symbol.name == "memory_history_top" for symbol in module.symbols))

    def test_poison_clear_and_rollback_change_only_the_saved_slot_tag(self):
        targets = (
            (AArch64Architecture(), "aarch64", ("x0", "x1", "x2", "x3")),
            (RISCV64Architecture(), "riscv64", ("a0", "t0", "t1", "t2")),
        )
        for arch, target, names in targets:
            compiler, qemu = f"{target}-linux-gnu-gcc", f"qemu-{target}"
            if not shutil.which(compiler) or not shutil.which(qemu):
                self.skipTest("requires both RISC cross toolchains and QEMU")
            base, addr, value, top = (arch.abi.get_register(name) for name in names)
            for displacement in (0, 8, -8, 4096, 5000):
                with self.subTest(arch=arch.name, displacement=displacement), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    assembly = [".text"]
                    for name, poison in (("poison_slot", True), ("clear_slot", False)):
                        snippet = arch.asan_stack_poison_snippet(
                            addr, value, top, poison=poison, shadow_offset=0,
                            insert_memlog=True, slot=(base, displacement))
                        assembly.append(f".global {name}\n{name}:\n{snippet}\nret")
                    assembly.append('.section .note.GNU-stack,"",%progbits\n')
                    (root / "patch.S").write_text("\n".join(assembly))
                    (root / "check.c").write_text("""
#include <stdint.h>
#include <string.h>
struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
struct entry history[4], *memory_history_top = history;
unsigned char shadow[128] __attribute__((aligned(16)));
extern void poison_slot(uintptr_t), clear_slot(uintptr_t);
int main(void) {
    memset(shadow, 0x5a, sizeof(shadow));
    uintptr_t address = ((uintptr_t)(shadow + 32) << 3) - DISPLACEMENT;
    poison_slot(address);
    if (shadow[32] != 0xff) return 1;
    clear_slot(address);
    if (shadow[32] != 0 || memory_history_top != history + 2) return 2;
    for (unsigned i = 0; i != 2; ++i)
        if (history[i].addr != shadow + 32 || history[i].size != 1 ||
            (uint8_t)history[i].data != (i ? 0xff : 0x5a)) return 3;
    for (unsigned i = 0; i != sizeof(shadow); ++i)
        if (i != 32 && shadow[i] != 0x5a) return 4;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    for (unsigned i = 0; i != sizeof(shadow); ++i)
        if (shadow[i] != 0x5a) return 5;
    return 0;
}
""")
                    compiled = subprocess.run([compiler, "-O2", "-no-pie", f"-DDISPLACEMENT={displacement}",
                        str(root / "patch.S"), str(root / "check.c"), "-o", str(root / "check")],
                        capture_output=True, text=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    result = subprocess.run([qemu, "-L", f"/usr/{target}-linux-gnu", str(root / "check")],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
