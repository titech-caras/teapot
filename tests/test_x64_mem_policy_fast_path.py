"""The x64 load policy's one-register fast path decides exactly as the full policy."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from teapot.arch import X64Architecture
from teapot.arch.decoders import x64_decoder
from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.configs.slots import ScratchpadSlots
from teapot.configs.tags import TAG_ATTACKER, TAG_ATTACKER_INDIRECT, TAG_SECRET, TAG_SECRET_INDIRECT

# (name, encoding, setup turning the address argument in rdi into the operand's registers)
FORMS = (
    ("mov_rax_rdi", "488b07", ""),                                  # mov rax, [rdi]
    ("mov_rax_index", "488b44f710", "lea rdi, [rdi-16]\nxor esi, esi\n"),  # mov rax, [rdi+rsi*8+16]
    ("cmove_rax_rdi", "480f4407", ""),                              # cmove rax, [rdi]
    ("mov_rdi_rdi", "488b3f", ""),                                  # mov rdi, [rdi]: address is destination
    ("add_rax_rbx", "48034310", "lea rbx, [rdi-16]\n"),             # add rax, [rbx+0x10]
)
GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
FAST_REGISTER = "rcx"
OLD_SCRATCH = ("r8", "r9", "r10", "r11", "rdx")


def policy_and_instruction(arch, encoding, *, free=(FAST_REGISTER,), enable_asan_check=True, shadow_offset=0):
    inst, = x64_decoder().disasm(bytes.fromhex(encoding), 0)
    reg_manager = SimpleNamespace(
        abi=arch.abi, free_registers=lambda function, block, idx: {arch.abi.get_register(n) for n in free})
    policy = arch.create_transient_mem_operand_policy_pass(
        reg_manager, None, None, dift_layout=SimpleNamespace(asan_shadow_offset=shadow_offset),
        enable_asan_check=enable_asan_check)
    return policy, inst


def build(policy, arch, inst, block, *, function=object()):
    with mock.patch.object(type(arch), "mem_operand_to_str",
                           side_effect=lambda block, inst, operand: inst.op_str.split(",", 1)[1].strip()):
        return policy._build_policy_patch(inst, 0, 0, block, function)


class FastPathSelectionTests(unittest.TestCase):
    def setUp(self):
        self.arch = X64Architecture()

    def test_eligible_load_needs_one_register_and_spills_only_when_cold(self):
        policy, inst = policy_and_instruction(self.arch, "488b07")
        info = build(policy, self.arch, inst, None)
        self.assertEqual(info.patch.constraints.scratch_registers, 1)
        asm = info.patch(SimpleNamespace(scratch_registers=(self.arch.abi.get_register(FAST_REGISTER),)))
        hot, cold = asm.split("_slow:", 1)
        self.assertNotIn("scratchpad", hot)                  # no spill before the branch
        self.assertIn(f"scratchpad+{ScratchpadSlots.X64_MEM_POLICY_COLD_SPILL}", cold)
        self.assertNotIn("set", hot.split("test byte ptr dift_reg_tags", 1)[0])   # no CMOV here

    def test_cmov_condition_is_captured_once_before_the_tests(self):
        policy, inst = policy_and_instruction(self.arch, "480f4407")
        info = build(policy, self.arch, inst, None)
        asm = info.patch(SimpleNamespace(scratch_registers=(self.arch.abi.get_register(FAST_REGISTER),)))
        self.assertTrue(asm.lstrip().startswith("sete byte ptr scratchpad+"))
        self.assertEqual(asm.count("sete "), 1)

    def test_ineligible_accesses_keep_todays_patch_byte_for_byte(self):
        cases = (("no free register", "488b07", dict(free=())),
                 ("4-byte load", "8b07", {}),
                 ("FS segment", "64488b07", {}),
                 ("ASan off", "488b07", dict(enable_asan_check=False)),
                 ("shadow offset beyond disp32", "488b07", dict(shadow_offset=1 << 44)))
        for name, encoding, options in cases:
            with self.subTest(name):
                policy, inst = policy_and_instruction(self.arch, encoding, **options)
                info = build(policy, self.arch, inst, None)
                operand = self.arch.memory_operand(inst)
                with mock.patch.object(type(self.arch), "mem_operand_to_str",
                                       side_effect=lambda block, inst, op: inst.op_str.split(",", 1)[1].strip()):
                    reference = policy._build_patch(
                        inst, inst.op_str.split(",", 1)[1].strip(), operand.size,
                        conditional=self.arch.conditional_move_suffix(inst), mem_operand=operand,
                        write_reg=self.arch.register_from_name(
                            self.arch.abi, inst.reg_name(inst.operands[0].reg)))
                registers = tuple(self.arch.abi.get_register(n) for n in OLD_SCRATCH)
                self.assertEqual(info.patch.constraints.scratch_registers,
                                 reference.constraints.scratch_registers)
                self.assertEqual(info.patch(SimpleNamespace(scratch_registers=registers)),
                                 reference(SimpleNamespace(scratch_registers=registers)))

    def test_without_liveness_the_policy_keeps_todays_patch(self):
        policy, inst = policy_and_instruction(self.arch, "488b07")
        self.assertEqual(build(policy, self.arch, inst, None, function=None).patch.constraints.scratch_registers, 5)


def report_stub(kind, *, addr_reg=None, tag_reg=None):
    """Record the report's kind, tag and address in order, preserving every register and the flags."""
    kinds = {"KASPER_CACHE": 1, "KASPER_MDS": 2, "KASPER_PORT": 3}
    tmp = next(n for n in ("r11", "r12", "r13", "r14") if n not in (str(addr_reg), str(tag_reg)))
    return f"""
        pushfq
        push {tmp}
        mov {tmp}, qword ptr report_count
        mov byte ptr [report_kind + {tmp}], {kinds[kind]}
        mov byte ptr [report_tag + {tmp}], {tag_reg:8l}
        mov qword ptr [report_addr + {tmp}*8], {addr_reg}
        inc qword ptr report_count
        pop {tmp}
        popfq
    """


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("gcc"), "requires native x64 compiler")
class FastPathDifferentialTests(unittest.TestCase):
    def test_fast_and_full_policies_report_and_queue_identically(self):
        arch = X64Architecture()
        functions, calls = [], []
        for name, encoding, setup in FORMS:
            policy, inst = policy_and_instruction(arch, encoding)
            with mock.patch.object(type(arch), "report_gadget_snippet", side_effect=report_stub):
                info = build(policy, arch, inst, None)
                new = info.patch(SimpleNamespace(scratch_registers=(arch.abi.get_register(FAST_REGISTER),)))
                operand = arch.memory_operand(inst)
                old = policy._build_patch(
                    inst, inst.op_str.split(",", 1)[1].strip(), operand.size,
                    conditional=arch.conditional_move_suffix(inst), mem_operand=operand,
                    write_reg=arch.register_from_name(arch.abi, inst.reg_name(inst.operands[0].reg)))(
                    SimpleNamespace(scratch_registers=tuple(arch.abi.get_register(n) for n in OLD_SCRATCH)))
            address_registers = {reg.name for reg in arch.mem_operand_registers(arch.abi, inst, operand)}
            for variant, body in (("old", old), ("new", new)):
                # The rewriter scopes each patch's labels; one test file must rename them.
                body = body.replace(".L__mem_operand_policy", f".L__{variant}_{name}_policy")
                sentinels = "".join(f"mov {reg}, {0x1111111111111111 * (index + 1) & (2**63 - 1)}\n"
                                    for index, reg in enumerate(GPRS) if reg not in address_registers)
                saves = lambda table: "".join(f"mov qword ptr [{table} + {8 * index}], {reg}\n"
                                              for index, reg in enumerate(GPRS))
                functions.append(f"""
                    .globl {variant}_{name}
                    {variant}_{name}:
                        push rbx
                        push rbp
                        push r12
                        push r13
                        push r14
                        push r15
                        mov eax, esi
                        {setup}
                        cmp eax, 1
                        {sentinels}
                        {saves("regs_before")}
                        {body}
                        {saves("regs_after")}
                        pop r15
                        pop r14
                        pop r13
                        pop r12
                        pop rbp
                        pop rbx
                        ret
                """)
            ids = {reg: arch.dift_register_id(arch.abi.get_register(reg)) for reg in ("rax", "rdi", "rsi", "rbx")}
            first = sorted(address_registers)[0]
            second = sorted(address_registers)[1] if len(address_registers) > 1 else None
            calls.append(f"""
                run("{name}", old_{name}, new_{name}, {ids[first]}, {ids[second] if second else -1},
                    {int(name.startswith("cmov"))});
            """)
        fast = GPRS.index(FAST_REGISTER)
        source = f"""
            #include <assert.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            unsigned char scratchpad[{SCRATCHPAD_SIZE}], dift_reg_tags[48], dift_reg_queued_tags[48];
            unsigned char dift_reg_queue_pending[8];
            uint64_t report_count, report_addr[16], regs_before[15], regs_after[15];
            unsigned char report_kind[16], report_tag[16];
            struct outcome {{ uint64_t count, addr[16]; unsigned char kind[16], tag[16], queued[48], pending; }};
            static unsigned char shadow[16] __attribute__((aligned(16)));
            typedef void (*check_fn)(uintptr_t, int);

            static void reset(int tag_first, int id_first, int tag_second, int id_second) {{
                memset(dift_reg_tags, 0, sizeof dift_reg_tags);
                dift_reg_tags[0] = {TAG_SECRET};        /* rax's own tag must not matter */
                dift_reg_tags[id_first] = tag_first;
                if (id_second >= 0) dift_reg_tags[id_second] = tag_second;
                memset(dift_reg_queued_tags, 0, sizeof dift_reg_queued_tags);
                dift_reg_queue_pending[0] = 0;
                scratchpad[{ScratchpadSlots.X64_MEM_POLICY_CONDITION}] = 0xaa;   /* pre-dirtied */
                report_count = 0;
                memset(report_kind, 0, sizeof report_kind);
                memset(report_tag, 0, sizeof report_tag);
                memset(report_addr, 0, sizeof report_addr);
            }}

            static struct outcome capture(void) {{
                struct outcome o;
                memset(&o, 0, sizeof o);
                o.count = report_count;
                memcpy(o.addr, report_addr, sizeof o.addr);
                memcpy(o.kind, report_kind, sizeof o.kind);
                memcpy(o.tag, report_tag, sizeof o.tag);
                memcpy(o.queued, dift_reg_queued_tags, sizeof o.queued);
                o.pending = dift_reg_queue_pending[0];
                return o;
            }}

            static unsigned long cases, fast_cases;
            static void run(const char *name, check_fn old, check_fn new, int id_first, int id_second, int cmov) {{
                const int tags[] = {{0, {TAG_ATTACKER}, {TAG_ATTACKER_INDIRECT}, {TAG_ATTACKER}|{TAG_ATTACKER_INDIRECT},
                    {TAG_SECRET}, {TAG_SECRET}|{TAG_ATTACKER}, {TAG_SECRET}|{TAG_ATTACKER_INDIRECT},
                    {TAG_SECRET}|{TAG_ATTACKER}|{TAG_ATTACKER_INDIRECT}, {TAG_SECRET_INDIRECT},
                    {TAG_SECRET_INDIRECT}|{TAG_ATTACKER}, {TAG_SECRET_INDIRECT}|{TAG_ATTACKER_INDIRECT},
                    {TAG_SECRET_INDIRECT}|{TAG_ATTACKER}|{TAG_ATTACKER_INDIRECT},
                    {TAG_SECRET}|{TAG_SECRET_INDIRECT}, {TAG_SECRET}|{TAG_SECRET_INDIRECT}|{TAG_ATTACKER},
                    {TAG_SECRET}|{TAG_SECRET_INDIRECT}|{TAG_ATTACKER_INDIRECT}, 0x33}};
                const int seconds[] = {{0, {TAG_ATTACKER}, {TAG_SECRET}, {TAG_ATTACKER_INDIRECT}}};
                const unsigned char granule0[] = {{0, 1, 3, 7, 0x80, 0xf9, 0xff}};
                const unsigned char granule1[] = {{0, 2, 0xfa}};
                for (unsigned t = 0; t < sizeof tags / sizeof *tags; t++)
                for (unsigned u = 0; u < (id_second >= 0 ? 4u : 1u); u++)
                for (unsigned g0 = 0; g0 < sizeof granule0; g0++)
                for (unsigned g1 = 0; g1 < sizeof granule1; g1++)
                for (unsigned offset = 0; offset < 8; offset++)
                for (int condition = 0; condition < (cmov ? 2 : 1); condition++) {{
                    uintptr_t address = ((uintptr_t)shadow << 3) + offset;
                    shadow[0] = granule0[g0];
                    shadow[1] = granule1[g1];
                    reset(tags[t], id_first, seconds[u], id_second);
                    old(address, cmov ? condition : 1);
                    struct outcome a = capture();
                    reset(tags[t], id_first, seconds[u], id_second);
                    new(address, cmov ? condition : 1);
                    struct outcome b = capture();
                    if (memcmp(&a, &b, sizeof a)) {{
                        fprintf(stderr, "%s: tag %#x second %#x shadow %#x/%#x offset %u condition %d: "
                                "reports %lu/%lu pending %u/%u\\n", name, tags[t], seconds[u], granule0[g0],
                                granule1[g1], offset, condition, (unsigned long)a.count, (unsigned long)b.count,
                                a.pending, b.pending);
                        assert(0);
                    }}
                    for (int reg = 0; reg < 15; reg++)
                        if (reg != {fast}) assert(regs_before[reg] == regs_after[reg]);
                    cases++;
                    fast_cases += !((tags[t] | (id_second >= 0 ? seconds[u] : 0)) & 0x32) && !offset && !granule0[g0];
                }}
            }}

            {"".join(f"extern void old_{n}(uintptr_t, int); extern void new_{n}(uintptr_t, int);" for n, _, _ in FORMS)}

            int main(void) {{
                {"".join(calls)}
                printf("%lu cases, %lu on the fast path\\n", cases, fast_cases);
                return 0;
            }}
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "check.c").write_text(source)
            (root / "check.S").write_text(".intel_syntax noprefix\n.text\n" + "".join(functions)
                                          + '\n.section .note.GNU-stack,"",@progbits\n')
            build_run = subprocess.run(["gcc", "-O2", "-no-pie", str(root / "check.c"), str(root / "check.S"),
                                        "-o", str(root / "check")], capture_output=True, text=True)
            self.assertEqual(build_run.returncode, 0, build_run.stderr[-4000:])
            run = subprocess.run([str(root / "check")], capture_output=True, text=True, timeout=300)
            self.assertEqual(run.returncode, 0, run.stderr[-4000:])
            self.assertIn("on the fast path", run.stdout)
            print(run.stdout.strip())


BUF = 0x10000000
PROBE_SHADOW_OFFSET = 0x7fff8000


def wrapped(arch, patch, free, *, flags_live=True):
    """The patch as the allocator emits it: free registers handed out first, the rest spilled by the ABI's
    prologue/epilogue, and the flags saved around it when live (allocate_registers + gtirb-rewriting)."""
    import copy
    constraints = copy.deepcopy(patch.constraints)
    assigned = [arch.abi.get_register(name) for name in free][:constraints.scratch_registers]
    constraints.scratch_registers -= len(assigned)
    constraints.reads_registers.update(reg.name for reg in assigned)
    constraints.clobbers_flags = constraints.clobbers_flags and flags_live
    allocation = arch.abi._allocate_patch_registers(constraints)
    prologue, epilogue, _ = arch.abi._create_prologue_and_epilogue(constraints, allocation, False)
    body = patch(SimpleNamespace(scratch_registers=list(allocation.scratch_registers) + assigned,
                                 stack_adjustment=0))
    att = lambda snippets: "".join(f".att_syntax\n{snippet.code}\n.intel_syntax noprefix\n" for snippet in snippets)
    return att(prologue) + body + att(epilogue)


@unittest.skipUnless(platform.machine() == "x86_64" and shutil.which("gcc"), "requires native x64 compiler")
class FastPathWrapperProbeTests(unittest.TestCase):
    """Old and new policies under the real allocator wrapper and the real report snippet, followed by the original
    load or CMOV itself: live flags, both CMOV outcomes, RCX or RSI (the report snippet special-cases RSI as the
    tag register) as the fast register, and a capture-slot sentinel above the report words 0-63."""

    def test_wrapped_policies_agree_on_flags_loads_reports_and_registers(self):
        arch = X64Architecture()
        functions, calls = [], []
        for scratch in ("rcx", "rsi"):
            for name, encoding, original in (("mov", "488b07", "mov rax, qword ptr [rdi]"),
                                             ("cmove", "480f4407", "cmove rax, qword ptr [rdi]")):
                policy, inst = policy_and_instruction(arch, encoding, free=(scratch,),
                                                      shadow_offset=PROBE_SHADOW_OFFSET)
                info = build(policy, arch, inst, None)
                self.assertEqual(info.patch.constraints.scratch_registers, 1)
                operand = arch.memory_operand(inst)
                old_patch = policy._build_patch(
                    inst, inst.op_str.split(",", 1)[1].strip(), operand.size,
                    conditional=arch.conditional_move_suffix(inst), mem_operand=operand,
                    write_reg=arch.abi.get_register("rax"))
                for variant, patch in (("old", old_patch), ("new", info.patch)):
                    label = f"{variant}_{scratch}_{name}"
                    asm = wrapped(arch, patch, (scratch,)).replace(".L__mem_operand_policy", f".L__{label}_policy")
                    saves = lambda table: "".join(f"mov qword ptr [{table} + {8 * i}], {reg}\n"
                                                  for i, reg in enumerate(GPRS))
                    sentinels = "".join(f"mov {reg}, {0x0101010101010101 * (i + 3) & (2**63 - 1)}\n"
                                        for i, reg in enumerate(GPRS) if reg not in ("rdi", "rax", "r15"))
                    functions.append(f"""
                        .globl probe_{label}
                        probe_{label}:
                            push rbx
                            push rbp
                            push r12
                            push r13
                            push r14
                            push r15
                            mov r15, rsi
                            mov rax, rdx
                            {sentinels}
                            {saves("regs_before")}
                            push r15
                            popfq
                            {asm}
                            {original}
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
                calls.append(f'run("{scratch} {name}", probe_old_{scratch}_{name}, probe_new_{scratch}_{name}, '
                             f'{GPRS.index(scratch)}, {int(name == "cmove")});')
        reporters = "".join(f"""
            .globl report_gadget_{kind}
            report_gadget_{kind}:
                push rax
                mov rax, qword ptr report_count
                mov qword ptr [report_addr + rax*8], rsi
                mov byte ptr [report_tag + rax], dl
                mov byte ptr [report_kind + rax], {index}
                inc qword ptr report_count
                pop rax
                ret
        """ for index, kind in enumerate(("KASPER_CACHE", "KASPER_MDS", "KASPER_PORT"), 1))
        rdi = arch.dift_register_id(arch.abi.get_register("rdi"))
        rax = arch.dift_register_id(arch.abi.get_register("rax"))
        source = f"""
            #include <assert.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            #include <sys/mman.h>
            unsigned char scratchpad[{SCRATCHPAD_SIZE}] __attribute__((aligned(64)));
            unsigned char dift_reg_tags[48], dift_reg_queued_tags[48], dift_reg_queue_pending[8];
            uint64_t old_rsp, report_count, report_addr[16], regs_before[15], regs_after[15], flags_after;
            unsigned char report_kind[16], report_tag[16];
            typedef void (*probe_fn)(uintptr_t address, uint64_t flags, uint64_t rax);
            struct outcome {{ uint64_t flags, rax, count, addr[16], regs[15], sentinel;
                             unsigned char kind[16], tag[16], queued[48], pending; }};
            static unsigned char *shadow;

            static struct outcome go(probe_fn probe, uintptr_t address, uint64_t flags, int tag, int scratch) {{
                memset(dift_reg_tags, 0, sizeof dift_reg_tags);
                dift_reg_tags[{rdi}] = tag;
                memset(dift_reg_queued_tags, 0, sizeof dift_reg_queued_tags);
                dift_reg_queue_pending[0] = 0;
                memset(scratchpad, 0x5a, 4096);
                memcpy(scratchpad + 64, "CAPTURE!", 8);          /* a pending capture slot */
                report_count = 0;
                memset(report_kind, 0, 16); memset(report_tag, 0, 16); memset(report_addr, 0, sizeof report_addr);
                probe(address, flags, 0x1111111111111111);
                struct outcome o;
                memset(&o, 0, sizeof o);
                o.flags = flags_after & 0x8d5;                    /* CF PF AF ZF SF OF */
                o.rax = regs_after[0];
                o.count = report_count;
                memcpy(o.addr, report_addr, sizeof o.addr);
                memcpy(o.kind, report_kind, 16); memcpy(o.tag, report_tag, 16);
                memcpy(o.queued, dift_reg_queued_tags, 48);
                o.pending = dift_reg_queue_pending[0];
                memcpy(&o.sentinel, scratchpad + 64, 8);
                for (int r = 0; r < 15; r++)                       /* changed registers, apart from rax */
                    o.regs[r] = (r == 0 || r == scratch) ? 0 : regs_after[r] ^ regs_before[r];
                assert((o.flags & ~0x8d5) == 0);
                return o;
            }}

            static unsigned long cases;
            static void run(const char *name, probe_fn old, probe_fn new, int scratch, int cmov) {{
                const uint64_t flag_sets[] = {{0x0, 0x8d5, 0x40, 0x895}};
                const int tags[] = {{0, {TAG_ATTACKER}, {TAG_ATTACKER_INDIRECT}, {TAG_SECRET}}};
                const unsigned offsets[] = {{0x100, 0x103}};
                const unsigned char poison[] = {{0, 0xfa}};
                for (unsigned f = 0; f < 4; f++) for (unsigned t = 0; t < 4; t++)
                for (unsigned o = 0; o < 2; o++) for (unsigned p = 0; p < 2; p++) {{
                    uintptr_t address = {BUF}ul + offsets[o];
                    memset(shadow, 0, 4096);
                    shadow[(offsets[o] >> 3)] = poison[p];
                    struct outcome a = go(old, address, flag_sets[f] | 2, tags[t], scratch);
                    struct outcome b = go(new, address, flag_sets[f] | 2, tags[t], scratch);
                    if (memcmp(&a, &b, sizeof a)) {{
                        fprintf(stderr, "%s: flags %#lx tag %#x offset %#x poison %#x: flags %#lx/%#lx rax %#lx/%#lx "
                                "reports %lu/%lu sentinel %#lx/%#lx\\n", name, (unsigned long)flag_sets[f], tags[t],
                                offsets[o], poison[p], (unsigned long)a.flags, (unsigned long)b.flags,
                                (unsigned long)a.rax, (unsigned long)b.rax, (unsigned long)a.count,
                                (unsigned long)b.count, (unsigned long)a.sentinel, (unsigned long)b.sentinel);
                        for (int r = 0; r < 15; r++) if (a.regs[r] != b.regs[r]) fprintf(stderr, "  register %d\\n", r);
                        assert(0);
                    }}
                    assert(b.flags == (flag_sets[f] & 0x8d5));      /* the application's flags survive */
                    assert(!memcmp(&b.sentinel, "CAPTURE!", 8));
                    uint64_t loaded;
                    memcpy(&loaded, (void *)address, 8);
                    int taken = !cmov || (flag_sets[f] & 0x40);
                    assert(b.rax == (taken ? loaded : 0x1111111111111111ull));
                    cases++;
                }}
            }}

            {"".join(f"extern void probe_{v}_{s}_{n}(uintptr_t, uint64_t, uint64_t);"
                     for v in ("old", "new") for s in ("rcx", "rsi") for n in ("mov", "cmove"))}

            int main(void) {{
                unsigned char *buf = mmap((void *){BUF}ul, 4096, PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                assert(buf == (void *){BUF}ul);
                for (int i = 0; i < 4096; i++) buf[i] = (unsigned char)(i * 7 + 1);
                uintptr_t shadow_page = ((uintptr_t){BUF}ul >> 3) + (uintptr_t){PROBE_SHADOW_OFFSET}ul;
                shadow = mmap((void *)shadow_page, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
                assert(shadow == (void *)shadow_page);
                {"".join(calls)}
                printf("%lu wrapped cases\\n", cases);
                return 0;
            }}
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.c").write_text(source)
            (root / "probe.S").write_text(".intel_syntax noprefix\n.text\n" + reporters + "".join(functions)
                                          + '\n.section .note.GNU-stack,"",@progbits\n')
            build_run = subprocess.run(["gcc", "-O2", "-no-pie", str(root / "probe.c"), str(root / "probe.S"),
                                        "-o", str(root / "probe")], capture_output=True, text=True)
            self.assertEqual(build_run.returncode, 0, build_run.stderr[-4000:])
            run = subprocess.run([str(root / "probe")], capture_output=True, text=True, timeout=300)
            self.assertEqual(run.returncode, 0, run.stderr[-4000:])
            print(run.stdout.strip())


if __name__ == "__main__":
    unittest.main()
