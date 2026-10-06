"""The x64 restore point compares before it adds: the same window rule, no scratch register.

The reference is the register form it replaces (mov r, instruction_cnt; add r, n;
cmp r, ROB_LEN; jge; mov instruction_cnt, r). Both run under the allocator's
wrapper; the nested case links the real runtime.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from gtirb_rewriting import patch_constraints
from gtirb_rewriting.assembly import X86Syntax

from teapot.arch import X64Architecture
from teapot.configs.runtime import ROB_LEN, SCRATCHPAD_SIZE
from test_x64_mem_policy_fast_path import wrapped

GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
COSTS = (0, 1, 6, 49, ROB_LEN - 1, ROB_LEN, ROB_LEN + 1, 1000, 2 ** 31 - 1)
NATIVE = platform.machine() == "x86_64" and shutil.which("cc")


def register_restore_point(instruction_count):
    """The restore point before this change, as the reference."""
    @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=1, clobbers_flags=True)
    def patch(ctx):
        r = ctx.scratch_registers[0]
        return f"""
            mov {r}, instruction_cnt
            add {r}, {instruction_count}
            cmp {r}, {ROB_LEN}
            jge restore_checkpoint_ROB_LEN
            mov instruction_cnt, {r}
        """

    return patch


def counters(instruction_count):
    """Counter values below, at and above this cost's threshold, and the domain's edges."""
    values = {0, 1, 17, ROB_LEN - 2, ROB_LEN - 1, ROB_LEN, ROB_LEN + 5, 1 << 40}
    values.update(ROB_LEN - instruction_count + d for d in (-1, 0, 1))
    return sorted(value for value in values if value >= 0)


class RestorePointShapeTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()

    def render(self, instruction_count):
        return self.arch.conditional_restore_point_patch(instruction_count)(SimpleNamespace(scratch_registers=[]))

    def test_no_scratch_register_and_flags_through_the_allocator(self):
        patch = self.arch.conditional_restore_point_patch(6)
        self.assertEqual(patch.constraints.scratch_registers, 0)
        self.assertTrue(patch.constraints.clobbers_flags)
        self.assertFalse(patch.constraints.clobbers_registers)
        lines = [line.strip() for line in self.render(6).strip().splitlines()]
        self.assertEqual(lines, [f"cmp qword ptr instruction_cnt, {ROB_LEN - 6}",
                                 "jge restore_checkpoint_ROB_LEN",
                                 "add qword ptr instruction_cnt, 6"])

    def test_the_counter_is_stored_only_after_the_rollback_branch(self):
        for count in COSTS:
            with self.subTest(count=count):
                text = self.render(count)
                branch = text.index("jge restore_checkpoint_ROB_LEN")
                self.assertNotIn("instruction_cnt,", text[:branch].replace("cmp qword ptr instruction_cnt,", ""))
                if count:
                    self.assertIn(f"add qword ptr instruction_cnt, {count}", text[branch:])
                else:
                    self.assertNotIn("add", text)    # nothing to charge: compare only

    def test_costs_beyond_the_immediates_are_refused(self):
        self.render(2 ** 31 - 1)
        for count in (2 ** 31, -1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.arch.conditional_restore_point_patch(count)


def probe_functions(arch, name, patch, free, flags_live):
    """probe_NAME(counter, flags): run the wrapped patch with sentinel registers; 0 if it fell through."""
    saves = lambda table: "".join(f"mov qword ptr [{table} + {8 * i}], {reg}\n" for i, reg in enumerate(GPRS))
    sentinels = "".join(f"mov {reg}, {0x0101010101010101 * (i + 3) & (2 ** 63 - 1)}\n" for i, reg in enumerate(GPRS))
    return f"""
        .globl probe_{name}
        probe_{name}:
            push rbx
            push rbp
            push r12
            push r13
            push r14
            push r15
            mov qword ptr probe_rsp, rsp
            mov qword ptr instruction_cnt, rdi
            push rsi
            popfq
            {sentinels}
            {saves("regs_before")}
            {wrapped(arch, patch, free, flags_live=flags_live)}
            pushfq
            pop qword ptr flags_after
            {saves("regs_after")}
            xor eax, eax
            jmp probe_return
    """


@unittest.skipUnless(NATIVE, "requires native x64 and a C compiler")
class RestorePointDifferentialTests(unittest.TestCase):
    """Old and new points under the real wrapper: rollback, counter, live flags read right after, registers."""

    def test_window_rule_counter_flags_and_registers_match_the_register_form(self):
        arch = X64Architecture()
        functions, calls = [], []
        for flags_live in (True, False):
            for free in (("rcx",), ()):
                for count in COSTS:
                    tag = f"{int(flags_live)}_{len(free)}_{count}"
                    functions.append(probe_functions(arch, f"old_{tag}", register_restore_point(count), free,
                                                     flags_live))
                    functions.append(probe_functions(arch, f"new_{tag}", arch.conditional_restore_point_patch(count),
                                                     free, flags_live))
                    values = ", ".join(f"{value}ull" for value in counters(count))
                    calls.append(f"""{{ const uint64_t values[] = {{{values}}};
                        run("{tag}", probe_old_{tag}, probe_new_{tag}, {count}ull, values,
                            sizeof values / sizeof *values, {int(flags_live)}, {GPRS.index(free[0]) if free else -1});
                    }}""")
        source = f"""
            #include <assert.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            unsigned char scratchpad[{SCRATCHPAD_SIZE}] __attribute__((aligned(64)));
            uint64_t instruction_cnt, probe_rsp, flags_after, regs_before[15], regs_after[15];
            typedef uint64_t (*probe_fn)(uint64_t counter, uint64_t flags);
            static unsigned long cases, rejections;

            static void run(const char *name, probe_fn old, probe_fn new, uint64_t count, const uint64_t *values,
                            unsigned n_values, int flags_live, int free_register) {{
                const uint64_t flag_sets[] = {{0x0, 0x8d5, 0x40, 0x895, 0x1, 0x800}};
                for (unsigned v = 0; v < n_values; v++)
                for (unsigned f = 0; f < sizeof flag_sets / sizeof *flag_sets; f++) {{
                    uint64_t counter = values[v], flags = flag_sets[f] | 2;
                    uint64_t a_rejected = old(counter, flags), a_counter = instruction_cnt;
                    uint64_t a_flags = flags_after & 0x8d5, a_regs[15];
                    memcpy(a_regs, regs_after, sizeof a_regs);
                    uint64_t b_rejected = new(counter, flags), b_counter = instruction_cnt;
                    uint64_t b_flags = flags_after & 0x8d5;
                    /* The window rule: roll back when counter + cost reaches ROB_LEN; else charge the cost. */
                    int expected = (int64_t)(counter + count) >= {ROB_LEN};
                    if (a_rejected != (uint64_t)expected || b_rejected != (uint64_t)expected ||
                            a_counter != b_counter || b_counter != (expected ? counter : counter + count)) {{
                        fprintf(stderr, "%s: counter %lu flags %#lx: rejected %lu/%lu counter %lu/%lu\\n", name,
                                (unsigned long)counter, (unsigned long)flags, (unsigned long)a_rejected,
                                (unsigned long)b_rejected, (unsigned long)a_counter, (unsigned long)b_counter);
                        assert(0);
                    }}
                    rejections += expected;
                    cases++;
                    if (expected) continue;   /* rollback restores registers and flags from the checkpoint */
                    if (flags_live) {{
                        assert(a_flags == (flags & 0x8d5));
                        assert(b_flags == (flags & 0x8d5));
                    }}
                    for (int r = 0; r < 15; r++) {{
                        assert(regs_after[r] == regs_before[r]);   /* the new point touches no register */
                        if (r != free_register) assert(a_regs[r] == regs_before[r]);
                    }}
                }}
            }}

            {"".join(f"extern uint64_t probe_{v}_{int(fl)}_{nf}_{c}(uint64_t, uint64_t);"
                     for v in ("old", "new") for fl in (True, False) for nf in (1, 0) for c in COSTS)}

            int main(void) {{
                {"".join(calls)}
                printf("%lu restore point cases, %lu rolled back\\n", cases, rejections);
                return 0;
            }}
        """
        stub = """
            .globl restore_checkpoint_ROB_LEN
            restore_checkpoint_ROB_LEN:
                mov eax, 1
            probe_return:
                mov rsp, qword ptr probe_rsp
                pop r15
                pop r14
                pop r13
                pop r12
                pop rbp
                pop rbx
                ret
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "check.c").write_text(source)
            (root / "check.S").write_text(".intel_syntax noprefix\n.text\n" + stub + "".join(functions)
                                          + '\n.section .note.GNU-stack,"",@progbits\n')
            build = subprocess.run(["cc", "-O2", "-no-pie", str(root / "check.c"), str(root / "check.S"),
                                    "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr[-4000:])
            run = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr[-4000:])
            self.assertIn("restore point cases", run.stdout)
            print(run.stdout.strip())


# (start counter, points before the inner checkpoint, points inside it, points after its rollback). The inner
# and the after-rollback lists end at a rollback; each list's costs place points below, at and above the
# threshold, cost 0, and costs of ROB_LEN or more.
CHAINS = (
    (17, (6,), (6, 0, 49, ROB_LEN), (1, 0, ROB_LEN)),
    (17, (6,), (ROB_LEN - 24, 1), (ROB_LEN - 24, 0, 1)),    # 249 falls through, 250 rolls back
    (0, (ROB_LEN - 1,), (2,), (0, ROB_LEN + 1)),             # 251 rolls back; 0 at 249 falls through
    (ROB_LEN - 7, (6,), (0, 1), (1,)),
    (ROB_LEN - 6, (6,), (1,), (1,)),                         # the outer point rolls back at 250
    (0, (1000,), (1,), (1,)),                                # a block costing more than the window
    (3, (0, 0), (2 ** 31 - 1,), (ROB_LEN,)),
)
FLAG_PATTERNS = (0x8d5, 0x0, 0x40, 0x895, 0x1, 0x800)
SLOTS, INNER_COUNTER, INNER_DEPTH, OUTER_COUNTER, OUTER_DEPTH = 64, 60, 61, 62, 63


def chain_model(start, before, inner, after):
    """The records of one chain: the counter after each point that falls through, after each rollback."""
    trace, counter, index = {}, start, 0
    for count in before:
        if counter + count >= ROB_LEN:
            trace[OUTER_COUNTER], trace[OUTER_DEPTH] = start, 1
            return trace
        counter += count
        trace[index] = counter
        index += 1
    inner_start, index = counter, len(before)
    for count in inner:
        if counter + count >= ROB_LEN:
            counter = inner_start
            trace[INNER_COUNTER], trace[INNER_DEPTH] = counter, 2
            break
        counter += count
        trace[index] = counter
        index += 1
    else:
        raise AssertionError("the inner points must end in a rollback")
    index = len(before) + len(inner)
    for count in after:
        if counter + count >= ROB_LEN:
            trace[OUTER_COUNTER], trace[OUTER_DEPTH] = start, 1
            return trace
        counter += count
        trace[index] = counter
        index += 1
    raise AssertionError("the points after the inner rollback must end in a rollback")


def chain_probe(arch, name, make_point, chain):
    _, before, inner, after = chain
    points = iter(range(SLOTS))

    def point(count):
        k = next(points)
        return f"""
            mov rax, {FLAG_PATTERNS[k % len(FLAG_PATTERNS)] | 2}
            push rax
            popfq
            {wrapped(arch, make_point(count), ())}
            pushfq
            pop qword ptr [ftrace + {8 * k}]
            mov rax, qword ptr instruction_cnt
            mov qword ptr [trace + {8 * k}], rax
        """

    def checkpoint(label):
        return f"""
            lea rax, [rip + .L{label}_speculative_{name}]
            mov qword ptr checkpoint_target_metadata, rax
            lea rax, [rip + .L{label}_restored_{name}]
            mov qword ptr [checkpoint_target_metadata + 8], rax
            lea rax, [rip + branch_counter]
            mov qword ptr [checkpoint_target_metadata + 16], rax
            jmp make_checkpoint_integer
        """

    def record(counter_slot, depth_slot):
        return f"""
            mov rax, qword ptr instruction_cnt
            mov qword ptr [trace + {8 * counter_slot}], rax
            mov rax, qword ptr checkpoint_cnt
            mov qword ptr [trace + {8 * depth_slot}], rax
        """

    return f"""
        .globl {name}
        {name}:
            push rbx
            push rbp
            push r12
            push r13
            push r14
            push r15
            {checkpoint("outer")}
        .Louter_speculative_{name}:
            {"".join(point(count) for count in before)}
            {checkpoint("inner")}
        .Linner_speculative_{name}:
            {"".join(point(count) for count in inner)}
            ud2
        .Linner_restored_{name}:
            {record(INNER_COUNTER, INNER_DEPTH)}
            {"".join(point(count) for count in after)}
            ud2
        .Louter_restored_{name}:
            {record(OUTER_COUNTER, OUTER_DEPTH)}
            pop r15
            pop r14
            pop r13
            pop r12
            pop rbp
            pop rbx
            ret
    """


def run_with_x64_runtime(test, root, fixture, probes, header, name):
    """Link a fixture, probe assembly and cases.h with the real nested x64 runtime; return its output.

    The runtime is configured only for its contract record, then compiled with
    the nested capability and without DIFT shadow setup, as the RISC nested
    checkpoint test does.
    """
    runtime = Path(__file__).resolve().parents[1] / "libcheckpoint"
    contract = root / "contract-build"
    configure = subprocess.run(
        ["cmake", "-S", str(runtime), "-B", str(contract), "-DBUILD_TESTING=OFF",
         "-DCMAKE_C_COMPILER=cc", "-DCMAKE_ASM_COMPILER=cc", "-DCHECKPOINT_ARCH=x86_64"],
        text=True, capture_output=True)
    test.assertEqual(configure.returncode, 0, configure.stdout + configure.stderr)
    (root / "cases.h").write_text(header)
    (root / "probe.S").write_text(".intel_syntax noprefix\n.text\n" + "".join(probes) +
                                  '\n.section .note.GNU-stack,"",@progbits\n')
    command = ["cc", "-O2", "-no-pie", "-DENABLE_NESTED_SPECULATION", "-DDISABLE_DIFT_RUNTIME",
               "-DDIFT_XOR_MASK=0", "-DTEAPOT_X64_VECTOR_MODE=0", "-fno-stack-protector",
               "-DTEAPOT_SHADOW_MAPPING_ENFORCEMENT=1",
               "-I", str(root), "-I", str(runtime / "include"), "-I", str(contract / "include"),
               str(Path(__file__).with_name("fixtures") / fixture),
               str(root / "probe.S"), str(runtime / "asm/checkpoint_x64.S"),
               str(runtime / "asm/storage.S"), str(contract / "contract/runtime_contract_record.S"),
               str(runtime / "tests/contract_module_record.c")]
    command += [str(runtime / "src" / source) for source in (
        "checkpoint.c", "signal_handler.c", "fault_sites.c", "fault_x64.c", "dift_support.c", "shadow_mapping.c", "report_gadget.c",
        "dift_wrappers/dift_wrappers.c")]
    build = subprocess.run(command + ["-o", str(root / name), "-lm"], text=True, capture_output=True)
    test.assertEqual(build.returncode, 0, build.stderr[-4000:])
    result = subprocess.run([str(root / name)], text=True, capture_output=True, timeout=60)
    test.assertEqual(result.returncode, 0, result.stdout + result.stderr)
    return result.stdout


@unittest.skipUnless(NATIVE and shutil.which("cmake"), "requires native x64, a C compiler and cmake")
class RestorePointNestedCheckpointTests(unittest.TestCase):
    """Both forms in nested checkpoints of the real runtime: the counter each rollback restores is the same."""

    def test_nested_checkpoints_restore_the_same_counter(self):
        arch = X64Architecture()
        probes, cases = [], []
        for index, chain in enumerate(CHAINS):
            for form, make_point in (("old", register_restore_point), ("new", arch.conditional_restore_point_patch)):
                probes.append(chain_probe(arch, f"chain_{form}_{index}", make_point, chain))
            expected = chain_model(*chain)
            records = ", ".join(f"{expected[i]}ull" if i in expected else "UNSET" for i in range(SLOTS))
            flags = ", ".join(f"{FLAG_PATTERNS[i % len(FLAG_PATTERNS)]}ull" for i in range(SLOTS))
            cases.append(f'{{"chain {index}", chain_old_{index}, chain_new_{index}, {chain[0]}ull, '
                         f'{{{records}}}, {{{flags}}}}}')
        header = "".join(f"extern void chain_{form}_{index}(void);\n"
                         for index in range(len(CHAINS)) for form in ("old", "new"))
        header += "static const struct chain chains[] = {\n" + ",\n".join(cases) + "\n};\n"
        with tempfile.TemporaryDirectory() as directory:
            output = run_with_x64_runtime(self, Path(directory), "x64_restore_point_nested.c", probes, header,
                                          "chains")
        self.assertIn(f"{len(CHAINS)} nested restore point chains passed", output)
        print(output.strip())


if __name__ == "__main__":
    unittest.main()
