"""Exercise operand consumers with the Register objects real patches receive."""
from types import SimpleNamespace
import unittest
from uuid import uuid4

import gtirb
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting import Assembler

from teapot.arch import AArch64Architecture, RISCV64Architecture, X64Architecture
from teapot.passes.transient.memlog.aarch64 import AArch64TransientMemlogPass
from teapot.passes.transient.memlog.riscv64 import RISCV64TransientMemlogPass
from teapot.passes.transient.memlog.x64 import X64TransientMemlogPass
from test_live_register_preservation import make_module


class AllocatedRegisterOperandTests(unittest.TestCase):
    def fixture(self, arch, assembly):
        isa = {"x64": gtirb.Module.ISA.X64, "aarch64": gtirb.Module.ISA.ARM64,
               "riscv64": gtirb.Module.ISA.ValidButUnsupported}[arch.name]
        _, module, block, _, _ = make_module(arch, isa, b"")
        result = self.assemble(arch, module, assembly)
        block.byte_interval.contents = result.text_section.data
        block.byte_interval.size = block.size = len(result.text_section.data)
        decoder = CachedGtirbInstructionDecoder(module.isa)
        return module, block, list(decoder.get_instructions(block))

    def assemble(self, arch, module, assembly):
        prefix = ".intel_syntax noprefix\n" if arch.name == "x64" else ""
        if arch.name == "riscv64":
            prefix = ".option norvc\n"
        assembler = Assembler(module, allow_undef_symbols=True)
        assembler.assemble(prefix + assembly)
        return assembler.finalize()

    def test_riscv_indirect_real_forms_with_allocated_registers(self):
        arch = RISCV64Architecture()
        regs = tuple(arch.abi.get_register(name) for name in ("t3", "t4", "t5"))
        symbols = [gtirb.Symbol(name=name) for name in ("start", "end", "text_start", "text_end")]
        for assembly, kind, operand in (
                ("jr a0", gtirb.Edge.Type.Branch, "0(a0)"),
                ("jalr a0", gtirb.Edge.Type.Call, "0(a0)"),
                ("jalr zero, -8(a0)", gtirb.Edge.Type.Branch, "-8(a0)"),
                ("ret", gtirb.Edge.Type.Return, "ra")):
            with self.subTest(assembly=assembly):
                module, _, instructions = self.fixture(arch, assembly)
                inst, = instructions
                actual = arch.indirect_branch_operand(kind, inst)
                # Capstone may spell the displacement in hexadecimal; test its
                # parsed value through the emitted instruction, not its spelling.
                if "-8" not in operand:
                    self.assertEqual(actual, operand)
                else:
                    self.assertEqual(inst.operands[-1].imm, -8)
                patch = arch.indirect_branch_check_patch(actual, *symbols)
                output = patch(SimpleNamespace(scratch_registers=regs))
                self.assertTrue(self.assemble(arch, module, output).text_section.data)
        for base in ("t3", arch.abi.get_register("t3")):
            self.assertEqual(arch.add_constant_from_base(regs[0], base, regs[1], 0), "")
        self.assertEqual(arch.add_constant_from_base(regs[0], "a0", regs[1], 0), "mv t3, a0\n")

    def test_riscv_retargets_decoded_branch_and_jump_aliases(self):
        arch = RISCV64Architecture()
        for original, expected in (("beqz a0", "beq"), ("bnez a0", "bne"),
                                   ("beq a0, a1", "beq"), ("j", "jal"), ("jal", "jal")):
            with self.subTest(original=original):
                separator = ", " if original.startswith("b") else " "
                module, _, instructions = self.fixture(
                    arch, original + separator + ".Lold\n.Lold:\nnop")
                inst = instructions[0]
                self.assertEqual(inst.mnemonic, expected)
                retargeted = arch.retarget_last_operand(inst.mnemonic, inst.op_str, ".Lnew")
                result = self.assemble(arch, module, retargeted + "\n.Lnew:\nnop")
                self.assertTrue(result.text_section.data)
                if expected in {"beq", "bne"}:
                    regs = tuple(arch.abi.get_register(name) for name in ("t3", "t4", "t5"))
                    patch = arch.trampoline_patch(
                        uuid4(), uuid4(), inst.mnemonic, inst.op_str, "taken", "fallthrough",
                        use_long_jumps=True, checkpoint_spare_registers=regs)
                    output = patch(SimpleNamespace(scratch_registers=regs))
                    self.assertTrue(self.assemble(arch, module, output).text_section.data)

    def test_riscv_real_li_and_mv_keep_distinct_register_effects(self):
        arch = RISCV64Architecture()
        for original, source, constant in (("li a0, 3", None, True),
                                            ("mv a0, a1", "a1", False),
                                            ("mv sp, s0", "s0", False)):
            with self.subTest(original=original):
                _, _, instructions = self.fixture(arch, original)
                inst, = instructions
                self.assertEqual(inst.mnemonic, "addi")
                self.assertEqual(arch.dift_clears_destination_tags(inst), constant)
                assignment = arch.stack_register_assignment(inst)
                if source is None:
                    self.assertIsNone(assignment)
                else:
                    self.assertEqual(assignment[1], arch.abi.get_register(source))
                    self.assertEqual(assignment[2], 0)

    def test_decoded_memory_builders_use_real_scratch_registers(self):
        for arch, instructions, names, pass_type in (
                (X64Architecture(), ("mov [rdi+8], rax", "mov fs:[rdi+8], rax"),
                 ("r8", "r9", "r10"), X64TransientMemlogPass),
                (AArch64Architecture(), ("str x0, [x1, #8]", "str x0, [sp, #16]!"),
                 ("x8", "x9", "x10"), AArch64TransientMemlogPass),
                (RISCV64Architecture(), ("sd a0, 8(a1)", "sd a0, -8(sp)"),
                 ("t3", "t4", "t5"), RISCV64TransientMemlogPass)):
            regs = tuple(arch.abi.get_register(name) for name in names)
            for original in instructions:
                with self.subTest(arch=arch.name, original=original):
                    module, block, decoded = self.fixture(arch, original)
                    inst, = decoded
                    operand = arch.memory_operand(inst)
                    width = arch.mem_operand_size(inst, operand)
                    memlog = pass_type(SimpleNamespace(abi=arch.abi), None, None, arch)
                    if arch.name == "x64":
                        text = arch.mem_operand_to_str(block, inst, operand)
                        patch = memlog._build_memlog_patch(inst, text, width)
                    else:
                        patch = memlog._build_patch(inst, operand, width)
                        if arch.name == "riscv64":
                            address_names = arch.mem_operand_register_names(arch.abi, inst, operand)
                            self.assertTrue(all(isinstance(name, str) for name in address_names))
                    output = patch(SimpleNamespace(scratch_registers=regs, stack_adjustment=0))
                    self.assertTrue(self.assemble(arch, module, output).text_section.data)

    def test_risc_stack_poison_patches_use_register_objects(self):
        for arch, names in ((AArch64Architecture(), ("x8", "x9", "x10")),
                            (RISCV64Architecture(), ("t3", "t4", "t5"))):
            regs = tuple(arch.abi.get_register(name) for name in names)
            module, _, _ = self.fixture(arch, "nop")
            for base in ("sp", "x29" if arch.name == "aarch64" else "s0"):
                for displacement in (0, 16):
                    with self.subTest(arch=arch.name, base=base, displacement=displacement):
                        patch = arch.asan_stack_patch(
                            arch.abi, poison=True, insert_memlog=True, shadow_offset=0,
                            slot=(arch.abi.get_register(base), displacement))
                        output = patch(SimpleNamespace(scratch_registers=regs, stack_adjustment=16))
                        self.assertTrue(self.assemble(arch, module, output).text_section.data)


if __name__ == "__main__":
    unittest.main()
