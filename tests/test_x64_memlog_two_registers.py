"""One-entry scalar stores log the same x64 memory-history entry with two scratch registers as with three.

The old value goes to the address register once the address is in the entry.
The reference is the three-register form, which every other store keeps.
"""
from pathlib import Path
import platform
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import gtirb
from gtirb_rewriting import PassManager

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.liveness import LiveRegisterManager
from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, SCRATCHPAD_SIZE
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass
from test_live_register_preservation import make_module
from test_x64_mem_policy_fast_path import wrapped
from test_x64_restore_point import run_with_x64_runtime

NATIVE = platform.machine() == "x86_64" and shutil.which("cc")
GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
SIZES = {1: "byte", 2: "word", 4: "dword", 8: "qword"}
REGISTER_WIDTHS = {1: "8l", 2: "16", 4: "32", 8: "64"}

# (encoding, the operand string the pass derives, access size, two registers?)
ELIGIBILITY = (
    ("48894708", "qword ptr [rdi + 8]", 8, True),               # mov [rdi+8], rax
    ("8907", "dword ptr [rdi]", 4, True),                        # mov [rdi], eax
    ("668907", "word ptr [rdi]", 2, True),                       # mov [rdi], ax
    ("8807", "byte ptr [rdi]", 1, True),                         # mov [rdi], al
    ("89548810", "dword ptr [rax + rcx*4 + 0x10]", 4, True),     # mov [rax+rcx*4+16], edx
    ("890425" "00106000", "dword ptr [0x601000]", 4, True),      # absolute, no base
    ("480fb10f", "qword ptr [rdi]", 8, True),                    # cmpxchg [rdi], rcx
    ("0fc307", "dword ptr [rdi]", 4, True),                      # movnti [rdi], eax
    ("50", "[rsp-8]", 8, True),                                  # push rax
    ("6650", "[rsp-2]", 2, True),                                # push ax
    ("ffd0", "[rsp-8]", 8, True),                                # call rax
    ("9c", "[rsp-8]", 8, True),                                  # pushfq
    ("48890510000000", "qword ptr [rip + 0x10]", 8, False),      # RIP-relative
    ("6448894708", "qword ptr fs:[rdi + 8]", 8, False),          # FS
    ("65488900", "qword ptr gs:[rax]", 8, False),                # GS
    ("0f1107", "xmmword ptr [rdi]", 16, False),                  # movups: two entries
    ("480fc70f", "xmmword ptr [rdi]", 16, False),                # cmpxchg16b
    ("db3f", "xword ptr [rdi]", 10, False),                      # fstp tbyte: two entries
    ("c8100000", "[rsp-8]", 8, False),                           # enter: special address
    ("0ff7c1", "[rdi]", 8, False),                               # maskmovq: special address
)


def memlog_patch(arch, mem_operand_str, width, two_registers):
    visitor = X64TransientMemlogPass(SimpleNamespace(abi=arch.abi), None, None, arch)
    return visitor._build_memlog_patch(None, mem_operand_str, width, reuse_address=two_registers)


class TwoRegisterEligibilityTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()
        self.visitor = X64TransientMemlogPass(SimpleNamespace(abi=self.arch.abi), None, None, self.arch)

    def test_only_one_entry_scalar_stores_at_ordinary_addresses(self):
        for encoding, operand_text, width, expected in ELIGIBILITY:
            inst, = x64_decoder().disasm(bytes.fromhex(encoding), 0x1000)
            with self.subTest(instruction=f"{inst.mnemonic} {inst.op_str}"):
                implicit = self.arch.implicit_memory_write(inst)
                operand = None if implicit is not None else self.arch.memory_operand(inst)
                self.assertEqual(self.visitor.one_entry_scalar_store(inst, operand, operand_text, width), expected)
                patch = memlog_patch(self.arch, operand_text, width, expected)
                self.assertEqual(patch.constraints.scratch_registers, 2 if expected else 3)
                self.assertFalse(patch.constraints.clobbers_flags)

    def test_the_entry_is_published_in_the_old_order(self):
        rax, rbx = (self.arch.abi.get_register(name) for name in ("rax", "rbx"))
        for width in SIZES:
            with self.subTest(width=width):
                text = memlog_patch(self.arch, f"{SIZES[width]} ptr [rdi + 8]", width, True)(
                    SimpleNamespace(scratch_registers=[rax, rbx]))
                lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
                low = format(rbx, REGISTER_WIDTHS[width])
                self.assertEqual(lines, [
                    f"lea rbx, {SIZES[width]} ptr [rdi + 8]",
                    "mov rax, [memory_history_top]",
                    "mov [rax], rbx",                                   # the address, before its register is reused
                    f"mov {low}, {SIZES[width]} ptr [rbx]",             # the old value: the faulting load
                    f"mov {SIZES[width]} ptr [rax + 8], {low}",
                    f"mov byte ptr [rax + 16], {width}",
                    f"lea rax, [rax + {MEMORY_HISTORY_ENTRY_SIZE}]",
                    "mov memory_history_top, rax",                      # a complete entry, then the top
                ])

    def test_other_widths_are_refused_by_the_snippet(self):
        for width in (3, 6, 16):
            with self.subTest(width=width), self.assertRaises(ValueError):
                self.arch.address_reusing_memlog_snippet(*(self.arch.abi.get_register(n) for n in ("rbx", "rax")),
                                                         width)


# (name, base, index, scale, displacement, source): stores whose registers the allocator's spills alias.
FORMS = (
    ("base", "rbx", None, 1, 8, "rdx"),          # the second spilled register is the base
    ("indexed", "rax", "rcx", 4, 16, "rbx"),     # top, the index and the source are all spilled ones
    ("source_is_base", "rax", None, 1, 0, "rax"),
    ("r13", "r13", None, 1, 0, "r12"),
    ("rbp", "rbp", None, 1, -8, "rsi"),
    ("no_base", None, "rcx", 8, "data", "rdi"),  # [rcx*8 + data]
)
FREE = (("r8", "r9", "r10"), ("r8", "r9"), ("r8",), ())


def signed(value):
    return f"- {-value}" if isinstance(value, int) and value < 0 else f"+ {value}"


def operand(width, base, index, scale, displacement):
    text = " + ".join(([base] if base else []) + ([f"{index}*{scale}"] if index else []))
    return f"{SIZES[width]} ptr [{text} {signed(displacement)}]"


def setup_registers(arch, form, width, offset, value, *, address="qword ptr data_address"):
    """Point the form's registers at data+offset and load the stored value; no flag changes."""
    _, base, index, scale, displacement, source = form
    index_value = 1 if index else 0
    text = ""
    if base:
        adjust = offset - index_value * scale - (displacement if isinstance(displacement, int) else 0)
        text += f"mov {base}, {address}\nlea {base}, [{base} {signed(adjust)}]\n"
    if index:
        if base:
            text += f"mov {index}, {index_value}\n"
        else:
            text += f"mov {index}, {(offset) // scale}\n"
    if source not in (base, index):
        text += f"movabs {source}, {value}\n"
    return text


@unittest.skipUnless(NATIVE, "requires native x64 and a C compiler")
class TwoRegisterDifferentialTests(unittest.TestCase):
    """Both forms under the allocator's wrapper: entry bytes, top, data, registers and live flags agree."""

    def test_entries_registers_and_flags_match_the_three_register_form(self):
        arch = X64Architecture()
        functions, calls = [], []
        saves = lambda table: "".join(f"mov qword ptr [{table} + {8 * i}], {reg}\n" for i, reg in enumerate(GPRS))
        for form in FORMS:
            name, base, index, scale, displacement, source = form
            for width in SIZES:
                offset = 16 if index and not base else 8 + width
                text = operand(width, base, index, scale, displacement)
                store = f"mov {text}, {format(arch.abi.get_register(source), REGISTER_WIDTHS[width])}"
                for free in FREE:
                    tag = f"{name}_{width}_{len(free)}"
                    for variant, two in (("old", False), ("new", True)):
                        sentinels = "".join(f"mov {reg}, {0x0101010101010101 * (i + 3) & (2 ** 63 - 1)}\n"
                                            for i, reg in enumerate(GPRS) if reg not in (base, index, source))
                        functions.append(f"""
                            .globl probe_{variant}_{tag}
                            probe_{variant}_{tag}:
                                push rbx
                                push rbp
                                push r12
                                push r13
                                push r14
                                push r15
                                push rdi
                                popfq
                                {sentinels}
                                {setup_registers(arch, form, width, offset, 0x1122334455667788)}
                                {saves("regs_before")}
                                {wrapped(arch, memlog_patch(arch, text, width, two), free)}
                                {store}
                                pushfq
                                pop qword ptr flags_after
                                {saves("regs_after")}
                                pop r15
                                pop r14
                                pop r13
                                pop r12
                                pop rbp
                                pop rbx
                                ret
                        """)
                    clobbered = " | ".join(f"(1u << {GPRS.index(r)})" for r in free) or "0"
                    calls.append(f'run("{tag}", probe_old_{tag}, probe_new_{tag}, {offset}, {width}, '
                                 f'{clobbered});\n')
        source = f"""
            #include <assert.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            unsigned char scratchpad[{SCRATCHPAD_SIZE}] __attribute__((aligned(64)));
            unsigned char data[64] __attribute__((aligned(16)));
            uint64_t data_address, flags_after, regs_before[15], regs_after[15];
            struct entry {{ unsigned char bytes[{MEMORY_HISTORY_ENTRY_SIZE}]; }};
            struct entry history[4], *memory_history_top;
            typedef void (*probe_fn)(uint64_t flags);
            static unsigned long cases;

            static void reset(void) {{
                for (int i = 0; i < 64; i++) data[i] = (unsigned char)(i * 7 + 1);
                memset(history, 0xee, sizeof history);
                memory_history_top = history;
            }}

            static void run(const char *name, probe_fn old, probe_fn new, unsigned offset, unsigned width,
                            unsigned clobbered) {{
                const uint64_t flag_sets[] = {{0x0, 0x8d5, 0x40, 0x895}};
                for (unsigned f = 0; f < 4; f++) {{
                    uint64_t flags = flag_sets[f] | 2;
                    unsigned char a_data[64], initial[64];
                    struct entry a_history[4];
                    reset();
                    memcpy(initial, data, 64);
                    old(flags);
                    assert(memory_history_top == history + 1);
                    assert((flags_after & 0x8d5) == (flags & 0x8d5));
                    for (int r = 0; r < 15; r++)
                        if (!(clobbered >> r & 1)) assert(regs_after[r] == regs_before[r]);
                    memcpy(a_data, data, 64);
                    memcpy(a_history, history, sizeof history);
                    reset();
                    new(flags);
                    assert(memory_history_top == history + 1);
                    assert((flags_after & 0x8d5) == (flags & 0x8d5));
                    for (int r = 0; r < 15; r++)
                        if (!(clobbered >> r & 1)) assert(regs_after[r] == regs_before[r]);
                    if (memcmp(a_history, history, sizeof history) || memcmp(a_data, data, 64)) {{
                        fprintf(stderr, "%s flags %#lx: entries or data differ\\n", name, (unsigned long)flags);
                        assert(0);
                    }}
                    /* The entry: the store's address, its old bytes, its width. */
                    void *address;
                    memcpy(&address, history[0].bytes, 8);
                    assert(address == data + offset && history[0].bytes[16] == width);
                    assert(!memcmp(history[0].bytes + 8, initial + offset, width));
                    /* Replaying it restores the data. */
                    memcpy(data + offset, history[0].bytes + 8, width);
                    assert(!memcmp(data, initial, 64));
                    cases++;
                }}
            }}

            {"".join(f"extern void probe_{v}_{f[0]}_{w}_{len(r)}(uint64_t);"
                     for v in ("old", "new") for f in FORMS for w in SIZES for r in FREE)}

            int main(void) {{
                data_address = (uint64_t)(uintptr_t)data;
                {"".join(calls)}
                printf("%lu memory-log cases\\n", cases);
                return 0;
            }}
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "check.c").write_text(source)
            (root / "check.S").write_text(".intel_syntax noprefix\n.text\n" + "".join(functions)
                                          + '\n.section .note.GNU-stack,"",@progbits\n')
            build = subprocess.run(["cc", "-O2", "-no-pie", str(root / "check.c"), str(root / "check.S"),
                                    "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr[-4000:])
            run = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr[-4000:])
            self.assertIn("memory-log cases", run.stdout)
            print(run.stdout.strip())


# (outer store, inner store, the inner rollback faults, store after the inner rollback): (form, width, offset, value)
NESTED = (
    (("base", 8, 8, 0x1111), ("indexed", 8, 12, 0x2222), False, ("source_is_base", 8, 32, 0x3333)),
    (("indexed", 4, 8, 0x44444444), ("base", 2, 10, 0x5555), True, ("rbp", 1, 40, 0x66)),
    (("r13", 2, 20, 0x7777), ("source_is_base", 2, 21, 0x8888), True, ("no_base", 4, 48, 0x99999999)),
    (("rbp", 1, 9, 0xaa), ("base", 1, 9, 0xbb), False, ("indexed", 2, 24, 0xcccc)),
)


@unittest.skipUnless(NATIVE and shutil.which("cmake"), "requires native x64, a C compiler and cmake")
class TwoRegisterNestedRollbackTests(unittest.TestCase):
    """Both forms in nested checkpoints of the real runtime, with old-value load faults on its SIGSEGV path."""

    def test_nested_rollbacks_restore_the_same_bytes(self):
        arch = X64Architecture()
        forms = {form[0]: form for form in FORMS}

        def store(variant, spec, *, fault=False):
            name, width, offset, value = spec
            form = forms[name]
            text = operand(width, *form[1:5])
            register = format(arch.abi.get_register(form[5]), REGISTER_WIDTHS[width])
            # The null page: the old-value load faults before the entry is published.
            address = "0x40" if fault else "qword ptr data_address"
            if fault and not form[1]:
                raise AssertionError("a faulting store needs a base register")
            return (setup_registers(arch, form, width, offset, value, address=address) +
                    wrapped(arch, memlog_patch(arch, text, width, variant == "new"), ()) +
                    f"mov {text}, {register}\n")

        def snapshot(index):
            return f"""
                lea rsi, [rip + data]
                lea rdi, [rip + snapshots + {64 * index}]
                mov ecx, 8
                rep movsq
                mov rax, qword ptr memory_history_top
                lea rcx, [rip + memory_history]
                sub rax, rcx
                mov qword ptr [rip + entries + {8 * index}], rax
            """

        def checkpoint(label, name):
            return f"""
                lea rax, [rip + .L{label}_speculative_{name}]
                mov qword ptr checkpoint_target_metadata, rax
                lea rax, [rip + .L{label}_restored_{name}]
                mov qword ptr [checkpoint_target_metadata + 8], rax
                lea rax, [rip + branch_counter]
                mov qword ptr [checkpoint_target_metadata + 16], rax
                jmp make_checkpoint_integer
            """

        probes, cases = [], []
        initial = [(i * 7 + 1) & 0xff for i in range(64)]
        for index, (outer, inner, faults, after) in enumerate(NESTED):
            for variant in ("old", "new"):
                name = f"chain_{variant}_{index}"
                inner_end = (store(variant, ("base", 8, 0, 0), fault=True) + "ud2\n" if faults
                             else "jmp restore_checkpoint_ROB_LEN\n")
                probes.append(f"""
                    .globl {name}
                    {name}:
                        push rbx
                        push rbp
                        push r12
                        push r13
                        push r14
                        push r15
                        {checkpoint("outer", name)}
                    .Louter_speculative_{name}:
                        {store(variant, outer)}
                        {snapshot(0)}
                        {checkpoint("inner", name)}
                    .Linner_speculative_{name}:
                        {store(variant, inner)}
                        {inner_end}
                    .Linner_restored_{name}:
                        {snapshot(1)}
                        {store(variant, after)}
                        jmp restore_checkpoint_ROB_LEN
                    .Louter_restored_{name}:
                        {snapshot(2)}
                        pop r15
                        pop r14
                        pop r13
                        pop r12
                        pop rbp
                        pop rbx
                        ret
                """)
            _, width, offset, value = outer
            after_outer = list(initial)
            after_outer[offset:offset + width] = value.to_bytes(width, "little")
            expected = [after_outer, after_outer, initial]
            rows = ", ".join("{" + ", ".join(map(str, snap)) + "}" for snap in expected)
            entries = ", ".join(str(n * MEMORY_HISTORY_ENTRY_SIZE) for n in (1, 1, 0))
            cases.append(f'{{"chain {index}", chain_old_{index}, chain_new_{index}, {{{rows}}}, {{{entries}}}, '
                         f'{int(faults)}}}')
        header = "".join(f"extern void chain_{variant}_{index}(void);\n"
                         for index in range(len(NESTED)) for variant in ("old", "new"))
        header += "static const struct chain chains[] = {\n" + ",\n".join(cases) + "\n};\n"
        with tempfile.TemporaryDirectory() as directory:
            output = run_with_x64_runtime(self, Path(directory), "x64_memlog_nested.c", probes, header, "chains")
        self.assertIn(f"{len(NESTED)} nested memory-log chains passed", output)
        print(output.strip())


PRINTER = os.environ.get("PPRINTER_PATH", "gtirb-pprinter")


@unittest.skipUnless(NATIVE and shutil.which(PRINTER), "requires native x64, a C compiler and the printer")
class TwoRegisterCallTests(unittest.TestCase):
    """Real calls through the pass, the allocator's wrapper and the printer: the return-address slot replays."""

    def test_direct_and_register_calls_log_their_return_slot(self):
        # call callee; call rax; call rbx; ret. With every register live the wrapper spills rax and rbx (two
        # registers) or rax, rbx and rcx (three), so the call registers are the log's own scratch registers.
        code = bytes.fromhex("e800000000" "ffd0" "ffd3" "c3")
        for two in (True, False):
            with self.subTest(two_registers=two), tempfile.TemporaryDirectory() as directory:
                arch = X64Architecture()
                ir, module, block, abi, registers = make_module(arch, gtirb.Module.ISA.X64, code)
                entry = next(module.symbols_named("test_function"))
                module.aux_data["sectionProperties"] = gtirb.AuxData(
                    {block.section: (1, 6)}, "mapping<UUID,tuple<uint64_t,uint64_t>>")
                module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
                    {entry: (len(code), "FUNC", "GLOBAL", "DEFAULT", 0)},
                    "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")
                for name in ("scratchpad", "old_rsp", "memory_history_top"):
                    gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
                callee = gtirb.Symbol(name="callee", payload=gtirb.ProxyBlock(module=module), module=module)
                block.byte_interval.symbolic_expressions[block.offset + 1] = gtirb.SymAddrConst(0, callee)
                manager = LiveRegisterManager(module, abi)
                offset = 0
                for inst in manager.decoder.get_instructions(block):
                    module.aux_data["liveRegisterSets"].data[gtirb.Offset(block, offset)] = \
                        (1 << len(registers)) - 1
                    offset += inst.size
                visitor = X64TransientMemlogPass(manager, block.section, manager.decoder, arch)
                chosen = []
                decide = visitor.one_entry_scalar_store
                with mock.patch.object(visitor, "one_entry_scalar_store",
                                       side_effect=lambda *a: chosen.append(decide(*a) and two) or chosen[-1]):
                    passes = PassManager()
                    passes.add(visitor)
                    passes.run(ir)
                self.assertEqual(chosen, [two] * 3)
                root = Path(directory)
                ir.save_protobuf(str(root / "calls.gtirb"))
                printed = subprocess.run([PRINTER, "--ir", str(root / "calls.gtirb"), "--asm", str(root / "calls.S")],
                                         capture_output=True, text=True)
                self.assertEqual(printed.returncode, 0, printed.stderr)
                (root / "runner.S").write_text("""
                    .intel_syntax noprefix
                    .text
                    .globl callee
                    callee:
                        mov r11, qword ptr calls
                        mov r10, qword ptr [rsp]
                        mov qword ptr [return_addresses + r11*8], r10
                        inc qword ptr calls
                        ret
                    .globl run_rewritten
                    run_rewritten:
                        push rbx
                        mov qword ptr runner_rsp, rsp
                        mov rsp, rdi
                        lea rax, [rip + callee]
                        mov rbx, rax
                        call test_function
                        mov qword ptr after_rsp, rsp
                        mov rsp, qword ptr runner_rsp
                        pop rbx
                        ret
                    .section .note.GNU-stack,"",@progbits
                """)
                build = subprocess.run(["cc", "-O2", "-no-pie", str(Path(__file__).with_name("fixtures") /
                                                                    "x64_call_memlog.c"),
                                        str(root / "runner.S"), str(root / "calls.S"), "-o", str(root / "calls")],
                                       capture_output=True, text=True)
                self.assertEqual(build.returncode, 0, build.stderr[-4000:])
                run = subprocess.run([str(root / "calls")], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn("CALL return slots logged and replayed", run.stdout)


if __name__ == "__main__":
    unittest.main()
