"""Coalescing adjacent x64 patch wrappers removes only saves of values a slot holds and dead reloads.

Each case marks the application's instructions as input, as the pipeline does
when it makes the copy, inserts patches with the real wrapper (gtirb-rewriting
and Teapot's x64 ABI) before them, then runs the coalescing round. Every case
checks the exact instructions removed. The native cases also run both
programs, before and after the round, from the same registers, flags and
spill-area sentinels, on two paths: the registers, flags, spill area and the
patches' stores must match.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

import gtirb
from capstone import CS_GRP_CALL, CS_GRP_JUMP
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Pass, PassManager, Patch, patch_constraints
from gtirb_rewriting.assembly import X86Syntax

from teapot.arch import X64Architecture
from teapot.arch.x64.abi import X64_WRAPPER_AREA
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.liveness import LiveRegisterManager
from teapot.passes.transient.x64_wrapper_coalescing import (
    UNRECOGNIZED, X64WrapperCoalescingPass, input_offsets, mark_input_instructions,
)
from test_live_register_preservation import make_module

S = X64_WRAPPER_AREA.start           # the first slot
GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
PRINTER = os.environ.get("PPRINTER_PATH", "gtirb-pprinter")


def patch(body, *, clobbers=(), flags=False):
    """A patch the wrapper saves clobbers (and the flags) around."""
    @patch_constraints(x86_syntax=X86Syntax.INTEL, clobbers_registers=set(clobbers), clobbers_flags=flags)
    def emit(ctx):
        return body

    return emit


class InsertPatches(Pass):
    def __init__(self, block, patches):
        self.block, self.patches = block, patches

    def begin_module(self, module, functions, rewriting_ctx):
        for emit in self.patches:
            rewriting_ctx.insert_at(self.block, 0, Patch.from_function(emit))


def listing(section):
    """The section's instructions as text, slot operands named S+n."""
    decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)    # uncached: blocks change between listings
    lines = []
    for block in sorted(section.code_blocks, key=lambda b: (b.byte_interval.address or 0) + b.offset):
        interval = block.byte_interval
        for inst in decoder.get_instructions(block):
            start = block.offset + inst.address - block.address
            names = [f"{e.symbol.name}+{e.offset - S}" if e.symbol.name == "scratchpad" and e.offset in
                     X64_WRAPPER_AREA else f"{e.symbol.name}+{e.offset}"
                     for e in (interval.symbolic_expressions.get(o) for o in range(start, start + inst.size))
                     if isinstance(e, gtirb.SymAddrConst)]
            # A branch's encoded target moves with the code before it; name it by its symbol only.
            text = inst.mnemonic if inst.group(CS_GRP_JUMP) or inst.group(CS_GRP_CALL) else \
                f"{inst.mnemonic} {inst.op_str}"
            lines.append(text + (f"  ; {' '.join(names)}" if names else ""))
    return lines


@dataclass
class Case:
    patches: list
    expected: list                  # the removed instructions, in listing order
    application: bytes = b"\x90\xc3"
    prepare: object = None          # prepare(module, block): edits the application before the patches go in
    edit: object = None             # edit(module, section): edits the IR after they went in
    native: bool = True
    marked: bool = True             # whether the application is marked as input, as the pipeline does


def coalesce(case, directory=None):
    """Insert the patches before the first application instruction; return the listings and IR files."""
    arch = X64Architecture()
    CachedGtirbInstructionDecoder.cache.clear()
    ir, module, block, abi, registers = make_module(arch, gtirb.Module.ISA.X64, case.application)
    for name in ("scratchpad", "probe_out", "path_select", "report_stub"):
        gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
    entry = next(module.symbols_named("test_function"))
    module.aux_data["sectionProperties"] = gtirb.AuxData(
        {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
    module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
        {entry: (len(case.application), "FUNC", "GLOBAL", "DEFAULT", 0)},
        "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
    manager = LiveRegisterManager(module, abi)
    offset = 0
    for inst in manager.decoder.get_instructions(block):
        module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, offset)] = (1 << len(registers)) - 1
        offset += inst.size
    section = block.section
    # As the pipeline does when it makes the transient copy.
    if case.marked:
        mark_input_instructions(section, CachedGtirbInstructionDecoder(module.isa))
    if case.prepare is not None:
        case.prepare(module, block)
    passes = PassManager()
    passes.add(InsertPatches(block, case.patches))
    passes.run(ir)
    if case.edit is not None:
        case.edit(module, section)
    before = listing(section)
    if directory is not None:
        ir.save_protobuf(str(directory / "before.gtirb"))
    CachedGtirbInstructionDecoder.cache.clear()
    manager.refresh(preserve_liveness=True)
    coalescing = X64WrapperCoalescingPass(manager, section, CachedGtirbInstructionDecoder(module.isa))
    passes = PassManager()
    passes.add(coalescing)
    passes.run(ir)
    after = listing(section)
    if directory is not None:
        ir.save_protobuf(str(directory / "after.gtirb"))
    return before, after, coalescing.statistics, module


def removed(before, after):
    """The instructions the round removed, in order (after must be a subsequence of before)."""
    gone, rest = [], iter(after)
    expected = next(rest, None)
    for line in before:
        if line == expected:
            expected = next(rest, None)
        else:
            gone.append(line)
    assert expected is None, f"{expected!r} is not in the original listing"
    return gone


# Patches that save rax and rbx, with or without the flags, and their bodies.
A = "mov rax, 0x1111\nmov rbx, 0x2222\nadd rax, rbx\nmov qword ptr probe_out, rax\n"
B = "mov rax, 0x3333\nmov rbx, qword ptr probe_out\nadd rax, rbx\nmov qword ptr probe_out+8, rax\n"
C = "mov rax, qword ptr probe_out+8\nmov qword ptr probe_out+16, rax\n"

def drop_mask(module, block):
    """DDisasm supplied no mask for the application's first instruction (or it was dropped as invalid)."""
    del module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, 0)]


def slot_operand(module, block):
    """The application's own mov [rip + disp32], rax names the first spill slot."""
    scratchpad = next(module.symbols_named("scratchpad"))
    block.byte_interval.symbolic_expressions[block.offset + 3] = gtirb.SymAddrConst(S, scratchpad)


def second_scratchpad(module, section):
    """Rebind the store's slot operand to another symbol named scratchpad, with its own storage."""
    data = gtirb.Section(name=".data_b", module=module, flags={
        gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Initialized})
    other = gtirb.Symbol(name="scratchpad", module=module,
                         payload=gtirb.DataBlock(size=8, byte_interval=gtirb.ByteInterval(
                             section=data, address=0x400000, contents=bytes(8))))
    slots = sorted((interval, offset) for interval in section.byte_intervals
                   for offset, expression in interval.symbolic_expressions.items()
                   if isinstance(expression, gtirb.SymAddrConst) and expression.offset == S)
    interval, offset = slots[1]          # the reload, then the store
    interval.symbolic_expressions[offset] = gtirb.SymAddrConst(S, other)


def input_scratchpad(module, block):
    """The input itself defines scratchpad: the slots would be its memory, not the runtime's."""
    data = gtirb.Section(name=".data", module=module, flags={
        gtirb.Section.Flag.Readable, gtirb.Section.Flag.Writable, gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Initialized})
    next(module.symbols_named("scratchpad")).referent = gtirb.DataBlock(
        size=8, byte_interval=gtirb.ByteInterval(section=data, address=0x400000, contents=bytes(8)))


def store_between(text):
    """Restore rax, an access to the area, save rax again, then overwrite rax."""
    return patch(f"mov rax, qword ptr scratchpad+{S}\n{text}\nmov qword ptr scratchpad+{S}, rax\nmov rax, 7\n"
                 f"mov rcx, qword ptr scratchpad+{S}\nmov qword ptr probe_out, rcx\n")


CASES = {
    # Adjacent patches, flags live. rax's restore stays: B's flag save reads rax. Its second save goes;
    # rbx's restore and second save go together; each flag save's and flag restore's own restore of rax
    # is dead (the body, or the restore after it, writes rax first).
    "adjacent, flags live": Case(
        [patch(A, clobbers=("rax", "rbx"), flags=True), patch(B, clobbers=("rax", "rbx"), flags=True),
         patch(C, clobbers=("rax",))],
        ["mov rax, qword ptr [0]  ; scratchpad+24",       # A's flag save
         "mov rax, qword ptr [0]  ; scratchpad+24",       # A's flag restore
         "mov rbx, qword ptr [0]  ; scratchpad+8",        # A's restore of rbx ...
         "mov qword ptr [0], rax  ; scratchpad+0",        # B's second save of rax (alone)
         "mov qword ptr [0], rbx  ; scratchpad+8",        # ... with B's second save of rbx
         "mov rax, qword ptr [0]  ; scratchpad+24",       # B's flag save
         "mov rax, qword ptr [0]  ; scratchpad+24",       # B's flag restore
         "mov rax, qword ptr [0]  ; scratchpad+0",        # B's restore of rax ...
         "mov qword ptr [0], rax  ; scratchpad+0"]),      # ... with C's second save
    "adjacent, flags dead": Case(
        [patch(A, clobbers=("rax", "rbx")), patch(B, clobbers=("rax", "rbx")), patch(C, clobbers=("rax",))],
        ["mov rbx, qword ptr [0]  ; scratchpad+8", "mov rax, qword ptr [0]  ; scratchpad+0",
         "mov qword ptr [0], rax  ; scratchpad+0", "mov qword ptr [0], rbx  ; scratchpad+8",
         "mov rax, qword ptr [0]  ; scratchpad+0", "mov qword ptr [0], rax  ; scratchpad+0"]),
    # rbx is restored from S+0 and saved to S+8, after rax took S+0: nothing to coalesce.
    "reordered registers share a slot": Case(
        [patch("mov rbx, 5\nmov qword ptr probe_out, rbx\n", clobbers=("rbx",)),
         patch("mov rax, 6\nmov rbx, 7\nadd rax, rbx\nmov qword ptr probe_out+8, rax\n", clobbers=("rax", "rbx"))],
        []),
    "reordered registers share a slot, other order": Case(
        [patch("mov rax, 6\nmov rbx, 7\nadd rax, rbx\nmov qword ptr probe_out+8, rax\n", clobbers=("rax", "rbx")),
         patch("mov rbx, 5\nmov qword ptr probe_out, rbx\n", clobbers=("rbx",))],
        []),
    # Another register's store to the slot comes between: the save of rax is no longer redundant, and the
    # reload it reads must stay with it (the refusal coupling).
    "slot written between restore and save": Case(
        [patch(f"mov rax, qword ptr scratchpad+{S}\nmov qword ptr scratchpad+{S}, rbx\n"
               f"mov qword ptr scratchpad+{S}, rax\nmov rax, 7\nmov rcx, qword ptr scratchpad+{S}\n"
               "mov qword ptr probe_out, rcx\n")],
        []),
    # The register changes between the restore and the save: the save stores a new value.
    "register written between restore and save": Case(
        [patch(f"mov rax, qword ptr scratchpad+{S}\nadd rax, 1\nmov qword ptr scratchpad+{S}, rax\n"
               f"mov rcx, qword ptr scratchpad+{S}\nmov qword ptr probe_out, rcx\n")],
        []),
    # A second entry between the restore and the save: neither goes.
    "alternate entry": Case(
        [patch(f"cmp qword ptr path_select, 0\njne 1f\nmov rax, qword ptr scratchpad+{S}\n1:\n"
               f"mov qword ptr scratchpad+{S}, rax\nmov rax, 5\nmov rcx, qword ptr scratchpad+{S}\n"
               "mov qword ptr probe_out, rcx\nmov qword ptr probe_out+8, rax\n")],
        []),
    # A partial write reads the rest of the register: the restore stays, the save goes.
    "partial write": Case(
        [patch(A, clobbers=("rax", "rbx")), patch("mov al, 1\nmov qword ptr probe_out+8, rax\n", clobbers=("rax",))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    # XOR of a register with itself writes it without reading it; XOR of its low byte only merges.
    "zeroing idiom": Case(
        [patch(A, clobbers=("rax", "rbx")),
         patch("xor eax, eax\nxor bl, bl\nadd rax, rbx\nmov qword ptr probe_out+8, rax\n", clobbers=("rax", "rbx"))],
        ["mov rax, qword ptr [0]  ; scratchpad+0", "mov qword ptr [0], rax  ; scratchpad+0",
         "mov qword ptr [0], rbx  ; scratchpad+8"]),
    # A conditional move reads its destination: the condition fails here, so rax keeps the restored value.
    "conditional move": Case(
        [patch(A, clobbers=("rax",)),
         patch("xor ecx, ecx\ncmp ecx, 1\ncmove rax, rcx\nmov qword ptr probe_out+8, rax\n", clobbers=("rax", "rcx"))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    # The next patch reads the restored register as an address.
    "address register read": Case(
        [patch(A, clobbers=("rax",)),
         patch("lea rbx, [rax + 8]\nmov rax, rbx\nmov qword ptr probe_out+8, rax\n", clobbers=("rax", "rbx"))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    # A report-style save of the register, and a call before the write, end the proof.
    "report scratch use": Case(
        [patch(A, clobbers=("rax",)),
         patch("mov qword ptr scratchpad+24, rax\ncall report_stub\nmov rax, qword ptr scratchpad+24\n"
               "mov qword ptr probe_out+8, rax\n", clobbers=("rax",))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    "call before the write": Case(
        [patch(A, clobbers=("rax",)), patch("call report_stub\nmov rax, 5\nmov qword ptr probe_out+8, rax\n",
                                            clobbers=("rax",))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    "branch before the write": Case(
        [patch(A, clobbers=("rax",)), patch("jmp 1f\n1:\nmov rax, 5\nmov qword ptr probe_out+8, rax\n",
                                            clobbers=("rax",))],
        ["mov qword ptr [0], rax  ; scratchpad+0"]),
    # The application's own write of rbx (mov ebx, 1) does not make the restore before it dead.
    "application write": Case([patch(A, clobbers=("rax", "rbx"))], [], application=bytes.fromhex("bb01000000c3")),
    # Nor when its live-register mask is missing: its input tag makes it input.
    "application write without a mask": Case(
        [patch(A, clobbers=("rax", "rbx"))], [], application=bytes.fromhex("bb01000000c3"), prepare=drop_mask),
    # An application store shaped like a save of the restored register to its slot stays, and so does the
    # restore before it.
    "wrapper-shaped application store": Case(
        [patch(A, clobbers=("rax",))], [], application=bytes.fromhex("48890500000000c3"), prepare=slot_operand),
    # Accesses to the area other than whole, aligned slots end the proof: nothing goes.
    "unaligned slot access": Case([store_between(f"mov qword ptr scratchpad+{S + 4}, rcx")], []),
    "narrow slot access": Case([store_between(f"mov dword ptr scratchpad+{S}, ecx")], []),
    "access overlapping the area from below": Case([store_between(f"mov qword ptr scratchpad+{S - 4}, rcx")], []),
    "slot address taken": Case([store_between(f"lea rcx, scratchpad+{S}")], []),
    # A block that two paths enter, starting with a restore and its second save: both go.
    "block start entered twice": Case(
        [patch(f"cmp qword ptr path_select, 0\njne 1f\nmov rcx, 1\njmp 2f\n1:\nmov rcx, 2\n2:\n"
               f"mov rax, qword ptr scratchpad+{S}\nmov qword ptr scratchpad+{S}, rax\nmov rax, 7\n"
               "mov qword ptr probe_out, rax\nmov qword ptr probe_out+8, rcx\n")],
        ["mov rax, qword ptr [0]  ; scratchpad+0", "mov qword ptr [0], rax  ; scratchpad+0"]),
    # Codex's counterexample: the store names another symbol called scratchpad. The two cannot be told
    # apart by name, so the round does nothing. (Listing only: two definitions of one name do not print.)
    "two symbols named scratchpad": Case(
        [patch(f"mov rax, qword ptr scratchpad+{S}\nmov qword ptr scratchpad+{S}, rax\nmov eax, 7\n")], [],
        edit=second_scratchpad, native=False),
    # The input defines scratchpad: not the runtime's spill area, so the round does nothing.
    "input-defined scratchpad": Case(
        [patch(A, clobbers=("rax", "rbx")), patch(B, clobbers=("rax", "rbx"))], [], prepare=input_scratchpad,
        native=False),
}


class CoalescingListingTests(unittest.TestCase):
    def test_each_case_removes_exactly_the_expected_instructions(self):
        for name, case in CASES.items():
            with self.subTest(case=name):
                before, after, statistics, _ = coalesce(case)
                self.assertEqual(removed(before, after), case.expected, "\n".join(before))

    def test_barriers_are_counted(self):
        def run(name):
            return coalesce(CASES[name])[2]

        self.assertEqual(run("application write").application_writer, 1)
        statistics = run("application write without a mask")
        self.assertEqual((statistics.application_writer, statistics.input_without_mask), (1, 1))
        self.assertEqual(run("wrapper-shaped application store").reloads_kept, {"application instruction": 1})
        for name in ("unaligned slot access", "narrow slot access", "access overlapping the area from below",
                     "slot address taken"):
            with self.subTest(case=name):
                self.assertEqual(run(name).unrecognized, 1)
        for name in ("two symbols named scratchpad", "input-defined scratchpad"):
            with self.subTest(case=name):
                self.assertIsNotNone(run(name).disabled)

    def test_without_input_marks_the_round_does_nothing(self):
        case = CASES["adjacent, flags dead"]
        before, after, statistics, _ = coalesce(Case(case.patches, [], marked=False))
        self.assertEqual(removed(before, after), [])
        self.assertIn("not marked", statistics.disabled)

    def test_accesses_are_recognized_by_the_symbol_not_its_name(self):
        _, _, _, module = coalesce(Case([patch(f"mov rax, qword ptr scratchpad+{S}\n")], []))
        runtime = next(module.symbols_named("scratchpad"))
        namesake = gtirb.Symbol(name="scratchpad", payload=gtirb.ProxyBlock(module=module), module=module)
        block = next(b for b in module.code_blocks if b.size)
        interval = block.byte_interval
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        inst = next(decoder.get_instructions(block))
        offset = block.offset + inst.address - block.address
        access = X64WrapperCoalescingPass.wrapper_access(inst, interval, offset, runtime)
        self.assertEqual((access.reload, access.register, access.slot), (True, "rax", (runtime.uuid, S)))
        self.assertIsNone(X64WrapperCoalescingPass.wrapper_access(inst, interval, offset, namesake))

    def test_the_tags_follow_input_instructions_and_go_away(self):
        _, _, _, module = coalesce(CASES["adjacent, flags dead"])
        self.assertNotIn("comments", module.aux_data)
        ir, module, block, _, _ = make_module(X64Architecture(), gtirb.Module.ISA.X64, bytes.fromhex("bb01000000c3"))
        gtirb.Symbol(name="scratchpad", payload=gtirb.ProxyBlock(module=module), module=module)
        mark_input_instructions(block.section, CachedGtirbInstructionDecoder(module.isa))
        passes = PassManager()
        passes.add(InsertPatches(block, [patch("mov rax, 1\n", clobbers=("rax",))]))
        passes.run(ir)
        tags = input_offsets(module, block.section)
        decoder = GtirbInstructionDecoder(gtirb.Module.ISA.X64)
        tagged = [f"{inst.mnemonic} {inst.op_str}" for b, displacements in tags.items()
                  for inst in decoder.get_instructions(b) if inst.address - b.address in displacements]
        self.assertEqual(tagged, ["mov ebx, 1", "ret "])


DRIVER = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
unsigned char scratchpad[SCRATCHPAD_SIZE] __attribute__((aligned(64)));
uint64_t probe_out[4], path_select, regs_after[15], flags_after, reports;
extern void run_test(uint64_t flags);
void report_stub(void) { reports++; }
int main(void) {
    const uint64_t flag_sets[] = {0x202, 0xad7, 0x246, 0xa97};
    for (unsigned path = 0; path < 2; path++)
    for (unsigned f = 0; f < 4; f++) {
        for (unsigned i = 0; i < 4096; i++) scratchpad[WRAPPER + i] = (unsigned char)(i * 13 + 5);
        memset(probe_out, 0x5a, sizeof probe_out);
        path_select = path;
        reports = 0;
        run_test(flag_sets[f]);
        printf("path %u flags %#lx -> %#lx reports %lu out", path, (unsigned long)flag_sets[f],
               (unsigned long)(flags_after & 0xcd5), (unsigned long)reports);
        for (unsigned i = 0; i < 4; i++) printf(" %016lx", (unsigned long)probe_out[i]);
        printf(" regs");
        for (unsigned i = 0; i < 15; i++) printf(" %016lx", (unsigned long)regs_after[i]);
        uint64_t sum = 1469598103934665603ull;
        for (unsigned i = 0; i < 4096; i++) sum = (sum ^ scratchpad[WRAPPER + i]) * 1099511628211ull;
        printf(" spill-area %016lx\n", (unsigned long)sum);
    }
    return 0;
}
"""


def runner():
    sentinels = "".join(f"movabs {reg}, {0x0123456789abcdef ^ (0x1111111111111111 * (i + 1)) & (2 ** 64 - 1)}\n"
                        for i, reg in enumerate(GPRS) if reg != "rdi")
    saves = "".join(f"mov qword ptr [regs_after + {8 * i}], {reg}\n" for i, reg in enumerate(GPRS))
    return f"""
        .intel_syntax noprefix
        .text
        .globl run_test
        run_test:
            push rbx
            push rbp
            push r12
            push r13
            push r14
            push r15
            push rdi
            popfq
            {sentinels}
            movabs rdi, 0x5555aaaa5555aaaa
            call test_function
            pushfq
            pop qword ptr flags_after
            {saves}
            cld
            pop r15
            pop r14
            pop r13
            pop r12
            pop rbp
            pop rbx
            ret
        .section .note.GNU-stack,"",@progbits
    """


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("cc") and shutil.which(PRINTER),
                     "requires native x64, a C compiler and the printer")
class CoalescingExecutionTests(unittest.TestCase):
    def test_programs_before_and_after_the_round_behave_alike(self):
        native = {name: case for name, case in CASES.items() if case.native}
        self.assertEqual(len(native), 22)
        for name, case in native.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                before, after, _, _ = coalesce(case, directory=root)
                self.assertEqual(len(before) - len(after), len(case.expected))
                (root / "driver.c").write_text(DRIVER)
                (root / "runner.S").write_text(runner())
                outputs = {}
                for variant in ("before", "after"):
                    printed = subprocess.run([PRINTER, "--ir", str(root / f"{variant}.gtirb"),
                                              "--asm", str(root / f"{variant}.S")], capture_output=True, text=True)
                    self.assertEqual(printed.returncode, 0, printed.stderr)
                    build = subprocess.run(
                        ["cc", "-O1", "-no-pie", f"-DSCRATCHPAD_SIZE={SCRATCHPAD_SIZE}", f"-DWRAPPER={S}",
                         str(root / "driver.c"), str(root / "runner.S"), str(root / f"{variant}.S"),
                         "-o", str(root / variant)], capture_output=True, text=True)
                    self.assertEqual(build.returncode, 0, build.stderr[-4000:])
                    run = subprocess.run([str(root / variant)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    outputs[variant] = run.stdout
                self.assertEqual(outputs["before"], outputs["after"])
                self.assertEqual(outputs["after"].count("\n"), 8)


if __name__ == "__main__":
    unittest.main()
