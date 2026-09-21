from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import capstone_gt
import gtirb
import llvmlite.binding as llvm

from teapot.arch import AArch64Architecture
from teapot.configs.slots import AARCH64_SHADOW_STACK_SIZE
from teapot.passes.common.dift.aarch64 import AArch64DiftPropagationPass
from teapot.passes.text.dift.aarch64 import AArch64TextDiftPropagationLLVMPass


class AArch64PairDiftTests(unittest.TestCase):
    def _check_cases(self, cases, *, paired):
        compiler = shutil.which("aarch64-linux-gnu-gcc")
        qemu = shutil.which("qemu-aarch64")
        if compiler is None or qemu is None:
            self.skipTest("AArch64 compiler and QEMU required")
        arch = AArch64Architecture()
        decoder = capstone_gt.Cs(
            capstone_gt.CS_ARCH_ARM64, capstone_gt.CS_MODE_ARM)
        decoder.detail = True
        manager = SimpleNamespace(abi=arch.abi)
        layout = SimpleNamespace(xor_mask=0)
        common = AArch64DiftPropagationPass(
            manager, None, None, arch, dift_layout=layout)
        text = AArch64TextDiftPropagationLLVMPass(
            manager, None, None, arch, dift_layout=layout)
        for encoding, mnemonic, width, store in cases:
            instruction = bytes.fromhex(encoding)
            inst = next(decoder.disasm(instruction, 0x1000))
            self.assertEqual(inst.mnemonic, mnemonic)
            block = gtirb.CodeBlock(size=len(instruction))
            gtirb.ByteInterval(address=0x1000, contents=instruction, blocks=[block])
            effects = text._instruction_effects(block, inst)
            word = int.from_bytes(instruction, "little")
            first_reg, second_reg, base_reg = word & 31, (word >> 10) & 31, (word >> 5) & 31
            displacement = (effects.mem_read or effects.mem_write).mem.disp
            if base_reg == 31:
                base_setup = f"sub x10, x0, #{displacement}\nmov sp, x10"
            else:
                base_setup = (
                    f"{'sub' if displacement >= 0 else 'add'} x{base_reg}, x0, #{abs(displacement)}\n"
                    f"{arch.load_address('x10', 'test_stack_top')}\nmov sp, x10")
            patch = common._build_patch(
                inst, effects.regs_read, effects.regs_write,
                clear_dest_tags=effects.clear_dest_tags,
                mem_read=effects.mem_read, mem_write=effects.mem_write,
                mem_write_size=effects.mem_write_size)
            text._reset()
            text._build_dift_patch(
                block, inst, 0, effects.regs_read, effects.regs_write,
                clear_dest_tags=effects.clear_dest_tags,
                mem_read=effects.mem_read, mem_write=effects.mem_write,
                mem_write_size=effects.mem_write_size,
                scratch_plan=text._scratch_plan(None, block, 0))
            self.assertEqual(text.scratchpad_offset, 1)
            ir = text._format_llvm_ir(
                "\n".join(text.llvm_ir), target_triple=text.target_triple)
            for optimize in (False, True):
                with self.subTest(instruction=inst.op_str, mnemonic=mnemonic, width=width, optimize=optimize):
                    parsed = (text._parse_and_optimize_llvm(ir) if optimize
                              else llvm.parse_assembly(ir))
                    parsed.verify()
                    assembly = text.target_machine.emit_assembly(parsed)
                    self.assertFalse(re.search(r"\b[qvdhsb][0-9]+\b", assembly), assembly)
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / "llvm.S").write_text(assembly)
                        (root / "common.S").write_text(f"""
                            .text
                            .global common_update
                        common_update:
                            mov x9, sp
                            {base_setup}
                            {patch(SimpleNamespace(stack_adjustment=0))}
                            mov sp, x9
                            ret
                            .bss
                            .balign 4096
                            .skip {AARCH64_SHADOW_STACK_SIZE + 4096}
                            .global memory_tags
                        memory_tags:
                            .skip 8192
                        test_stack_top:
                            .skip 3072
                            .section .note.GNU-stack,"",%progbits
                        """)
                        (root / "check.c").write_text(self._CHECK_SOURCE)
                        built = subprocess.run(
                            [compiler, "-O2", "-no-pie", f"-DWIDTH={width}",
                             f"-DELEMENTS={2 if paired else 1}",
                             f"-DSTORE={int(store)}", f"-DFIRST={first_reg}", f"-DSECOND={second_reg}",
                             f"-DBASE={base_reg}", str(root / "check.c"),
                             str(root / "common.S"), str(root / "llvm.S"),
                             "-o", str(root / "check")],
                            capture_output=True, text=True)
                        self.assertEqual(built.returncode, 0, built.stderr)
                        ran = subprocess.run(
                            [qemu, "-L", "/usr/aarch64-linux-gnu", str(root / "check")],
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_common_and_llvm_keep_pair_elements_distinct(self):
        self._check_cases((
            ("400440a9", "ldp", 8, False),
            ("40044029", "ldp", 4, False),
            ("40044069", "ldpsw", 4, False),
            ("400440a8", "ldnp", 8, False),
            ("400400a9", "stp", 8, True),
            ("40040029", "stp", 4, True),
            ("400400a8", "stnp", 8, True),
            ("5f0440a9", "ldp", 8, False),  # first result discarded
            ("407c40a9", "ldp", 8, False),  # second result discarded
            ("5f0400a9", "stp", 8, True),
            ("407c00a9", "stp", 8, True),
            ("420440a9", "ldp", 8, False),  # first destination is the address base
            ("400840a9", "ldp", 8, False),  # second destination is the address base
            ("420400a9", "stp", 8, True),
            ("4004c1a9", "ldp", 8, False),  # pre-indexed +16
            ("4004bfa9", "stp", 8, True),   # pre-indexed -16
            ("4004c1a8", "ldp", 8, False),  # post-indexed +16
            ("400481a8", "stp", 8, True),
            ("e08740a9", "ldp", 8, False),  # SP-relative +8
            ("e08700a9", "stp", 8, True),
            ("5d7840a9", "ldp", 8, False),  # fp/lr register aliases
            ("5d7800a9", "stp", 8, True),
            ("504440a9", "ldp", 8, False),  # scratch-register destinations
            ("504400a9", "stp", 8, True),
            ("000640a9", "ldp", 8, False),  # base x16 is preserved during first spill
            ("200640a9", "ldp", 8, False),  # base x17
        ), paired=True)

    def test_scalar_writeback_keeps_address_and_data_tags_distinct(self):
        self._check_cases((
            ("40144038", "ldrb", 1, False),  # post-indexed +1
            ("40140038", "strb", 1, True),
            ("401c4038", "ldrb", 1, False),  # pre-indexed +1
            ("401c0038", "strb", 1, True),
            ("40244078", "ldrh", 2, False),
            ("40240078", "strh", 2, True),
            ("404440b8", "ldr", 4, False),
            ("404400b8", "str", 4, True),
            ("408440f8", "ldr", 8, False),
            ("408400f8", "str", 8, True),
            ("40148038", "ldrsb", 1, False),
            ("5f144038", "ldrb", 1, False),  # zero-register transfer
            ("5f140038", "strb", 1, True),
            ("508440f8", "ldr", 8, False),  # scratch data register x16
            ("508400f8", "str", 8, True),
            ("00164038", "ldrb", 1, False),  # scratch base register x16
            ("00160038", "strb", 1, True),
            ("e08740f8", "ldr", 8, False),  # SP-relative writeback
            ("e08700f8", "str", 8, True),
            ("40004039", "ldrb", 1, False),  # no-writeback controls
            ("40000039", "strb", 1, True),
        ), paired=False)

    _CHECK_SOURCE = """
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
extern uint64_t scratchpad[];
extern unsigned char dift_reg_tags[48];
unsigned char dift_reg_queued_tags[48];
extern void common_update(unsigned char *);
extern void func(void);
extern unsigned char memory_tags[8192];
static unsigned char *tags;
static void reset(size_t offset) {
    tags = memory_tags + offset;
    memset(dift_reg_tags, 0, 48);
    dift_reg_tags[0] = 0x11;
    dift_reg_tags[1] = 0x22;
    dift_reg_tags[2] = 0x04;
    dift_reg_tags[16] = 0x08;
    dift_reg_tags[17] = 0x20;
    dift_reg_tags[29] = 0x80;
    dift_reg_tags[30] = 0x10;
    dift_reg_tags[31] = 0x40; // SP tags are ignored; zero registers have no tag.
    memset(memory_tags, 0x31, 8192);
    memset(tags, 0, ELEMENTS * WIDTH);
    if (ELEMENTS == 2) {
        tags[WIDTH - 1] = 1;
        tags[2 * WIDTH - 1] = 2;
    } else {
        // Scalar loads still sample only the first byte, not the tail tag.
        if (WIDTH > 1) tags[WIDTH - 1] = 2;
        tags[0] = 1;
    }
    scratchpad[0] = (uintptr_t)tags;
}
static int check(void) {
    unsigned char old[48] = {
        [0] = 0x11, [1] = 0x22, [2] = 4, [16] = 8, [17] = 0x20,
        [29] = 0x80, [30] = 0x10, [31] = 0x40};
    unsigned char expected_regs[48];
    memcpy(expected_regs, old, 48);
    unsigned char address_tag = BASE == 31 ? 0 : old[BASE];
    unsigned char first = address_tag | (FIRST == 31 ? 0 : old[FIRST]);
    unsigned char second = address_tag | (SECOND == 31 ? 0 : old[SECOND]);
    if (!STORE) {
        if (FIRST != 31) expected_regs[FIRST] = address_tag | 1;
        if (ELEMENTS == 2 && SECOND != 31) expected_regs[SECOND] = address_tag | 2;
    }
    size_t offset = (size_t)(tags - memory_tags);
    for (size_t i = 0; i < 8192; i++) {
        unsigned char expected = 0x31;
        if (i >= offset && i < offset + ELEMENTS * WIDTH) {
            size_t index = i - offset;
            expected = STORE ? (index < WIDTH ? first : second) : ELEMENTS == 2 ?
                       (index == WIDTH - 1 ? 1 : index == 2 * WIDTH - 1 ? 2 : 0) :
                       (index == 0 ? 1 : index == WIDTH - 1 ? 2 : 0);
        }
        if (memory_tags[i] != expected) return 1;
    }
    for (unsigned i = 0; i < 48; i++)
        if (dift_reg_tags[i] != expected_regs[i]) return 2;
    return 0;
}
int main(void) {
    for (unsigned crossing = 0; crossing < (BASE == 31 ? 2 : 3); crossing++) {
        size_t offset = crossing == 2 ? 4096 - ELEMENTS * WIDTH :
                        crossing ? 4096 - 8 : BASE == 31 ? 8 : 0;
        reset(offset);
        if (crossing == 2 && mprotect(memory_tags + 4096, 4096, PROT_NONE)) return 10;
        common_update(tags);
        if (crossing == 2 && mprotect(memory_tags + 4096, 4096, PROT_READ | PROT_WRITE)) return 11;
        int common = check();
        reset(offset);
        if (crossing == 2 && mprotect(memory_tags + 4096, 4096, PROT_NONE)) return 12;
        func();
        if (crossing == 2 && mprotect(memory_tags + 4096, 4096, PROT_READ | PROT_WRITE)) return 13;
        int text = check();
        printf("crossing=%u common=%d llvm=%d tags=%u,%u,%u memory=%u,%u\\n",
               crossing, common, text, dift_reg_tags[0], dift_reg_tags[1],
               dift_reg_tags[2], tags[WIDTH - 1], tags[2 * WIDTH - 1]);
        if (common || text) return common ? 1 : 2;
    }
    return 0;
}
"""
