import re
from dataclasses import dataclass
from typing import Optional, Set

import gtirb
from capstone_gt import CsInsn
from gtirb_rewriting import InsertionContext, patch_constraints
from gtirb_rewriting.assembly import Register, X86Syntax

from teapot.configs.runtime import SCRATCHPAD_SIZE
from teapot.passes.common.dift.x64 import X64DiftPropagationPass
from teapot.passes.text.dift.base import TextDiftInstructionEffects, TextDiftLLVMBase


@dataclass(frozen=True)
class X64LLVMRegisterUsage:
    registers: Set[Register]
    has_reg_spill: bool


class X64TextDiftPropagationLLVMPass(TextDiftLLVMBase, X64DiftPropagationPass):
    EXPECTED_ARCH = "x64"
    ALLOCATE_INST_PATCH_REGISTERS = True
    ALLOCATE_BLOCK_PATCH_REGISTERS = True
    """
    LLVM optimized version of x64 text-section DIFT propagation.

    x64 still has target-specific operand capture: memory operands are captured
    with x86 addressing syntax and the generated LLVM assembly is remapped onto
    scratch registers selected by the live-register manager.
    """

    def __init__(self, reg_manager, section, decoder, arch, *, dift_layout=None):
        super().__init__(reg_manager, section, decoder, arch, dift_layout=dift_layout, insert_memlog=False)
        assert not self.insert_memlog
        self._init_llvm_native()

    def __del__(self):
        self._shutdown_llvm()

    def _instruction_effects(self, block: gtirb.CodeBlock, inst: CsInsn):
        effects = self._x64_instruction_effects(block, inst)
        if effects is None:
            return None

        return TextDiftInstructionEffects(
            regs_read=effects.regs_read,
            regs_write=effects.regs_write,
            clear_dest_tags=effects.clear_dest_tags,
            mem_read=effects.mem_read_operand_str,
            mem_write=effects.mem_write_operand_str,
            mem_write_size=effects.mem_write_size,
            conditional=effects.conditional)

    @staticmethod
    def _should_skip_effects(effects: TextDiftInstructionEffects) -> bool:
        if TextDiftLLVMBase._should_skip_effects(effects):
            return True
        return (
            not effects.clear_dest_tags
            and effects.mem_read == effects.mem_write
            and len(effects.regs_read) == 0
            and len(effects.regs_write) == 0
        )

    def _get_register_usage(self, asm):
        regs = {
            self.rewriting_ctx._abi.get_register(r)
            for r in re.findall("%([0-9a-zA-Z]+)", asm)
            if r not in ("rip", "rsp")
        }

        has_reg_spill = "%rsp" in asm or "push" in asm
        return X64LLVMRegisterUsage(regs, has_reg_spill)

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional: Optional[str] = None, conditional_slot: Optional[int] = None):
        scratch_registers = 1 if capture_operands else 0
        asm = ""

        def store_r1(scratchpad_idx: int):
            return f"mov scratchpad+{scratchpad_idx * 8}, {{0}}\n"

        if conditional:
            asm += f"mov qword ptr scratchpad+{conditional_slot * 8}, 0\n"
            asm += f"set{conditional} byte ptr scratchpad+{conditional_slot * 8}\n"

        for scratchpad_idx, mem_operand_str, _ in capture_operands:
            asm += f"lea {{0}}, {mem_operand_str}\n"
            asm += store_r1(scratchpad_idx)

        @patch_constraints(x86_syntax=X86Syntax.INTEL, scratch_registers=scratch_registers)
        def patch(ctx: InsertionContext):
            if not (capture_operands or conditional):
                return ""
            if not capture_operands:
                return asm

            r1: Register = ctx.scratch_registers[0]
            return asm.format(r1.name, r1.sizes["8l"])

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers: X64LLVMRegisterUsage, *,
                                           scratch_plan=None):
        @patch_constraints(scratch_registers=len(registers.registers), clobbers_flags=True)
        def patch(ctx: InsertionContext):
            asm = assembly.strip()
            if asm.endswith("retq"):
                asm = asm[:-4]

            if registers.has_reg_spill:
                asm = f"""
                    movq %rsp, old_rsp
                    leaq scratchpad+{SCRATCHPAD_SIZE - 16}, %rsp
                """ + asm

            for reg_idx, register in enumerate(registers.registers):
                for size, name in register.sizes.items():
                    asm = asm.replace(f"%{name}", f"%tmpr{reg_idx}:{size}")

            for reg_idx, register in enumerate(ctx.scratch_registers):
                for size, name in register.sizes.items():
                    asm = asm.replace(f"%tmpr{reg_idx}:{size}", f"%{name}")

            if "retq" in asm:
                asm = asm.replace("retq", "jmp .Lfunc_end0")
                asm += """
                .Lfunc_end0:
                    nop
                """

            if registers.has_reg_spill:
                asm += """
                    movq old_rsp, %rsp
                """

            return asm

        return patch
