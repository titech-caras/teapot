import re
from dataclasses import dataclass
from typing import Optional, Tuple

from capstone_gt import CsInsn
from gtirb_rewriting import InsertionContext
from gtirb_rewriting.assembly import Register

from teapot.configs.slots import (
    AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
    AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
)
from teapot.passes.common.dift.aarch64 import AArch64DiftPropagationPass
from teapot.passes.text.dift.base import (
    TextDiftLLVMBase,
    TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT,
    TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET,
    TEXT_DIFT_LLVM_STACK_SP_OFFSET,
)
from teapot.utils.registers import registers_in_abi_order


@dataclass(frozen=True)
class AArch64TextDiftScratchPlan:
    base_register: Optional[Register]
    addr_reg: Register
    tmp_reg: Register
    saved_regs: Tuple[Register, ...]
    stack_save_fixed_regs: bool = False


class AArch64TextDiftPropagationLLVMPass(TextDiftLLVMBase, AArch64DiftPropagationPass):
    EXPECTED_ARCH = "aarch64"
    TARGET_TRIPLE = "aarch64-unknown-linux-gnu"

    def _scratch_plan(self, function, block, inst_idx):
        addr_reg = self.reg_manager.abi.get_register("x16")
        tmp_reg = self.reg_manager.abi.get_register("x17")
        return AArch64TextDiftScratchPlan(
            None,
            addr_reg,
            tmp_reg,
            (addr_reg, tmp_reg),
            stack_save_fixed_regs=True,
        )

    def _get_register_usage(self, asm: str):
        regs = {}
        for width, number in re.findall(r"\b([wx])([0-9]|[12][0-9]|3[01])\b", asm):
            if number == "31":
                continue
            reg = self.reg_manager.abi.get_register(f"x{number}")
            regs[reg.name] = reg
        return registers_in_abi_order(self.reg_manager.abi, regs.values())

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional=None, conditional_slot=None):
        if not capture_operands:
            @self.arch.constraints()
            def empty_patch(ctx: InsertionContext):
                return ""

            return empty_patch

        if not isinstance(scratch_plan, AArch64TextDiftScratchPlan):
            raise TypeError("AArch64 text DIFT capture requires an AArch64 scratch plan")

        fixed_regs = scratch_plan.saved_regs
        addr_reg = scratch_plan.addr_reg
        tmp_reg = scratch_plan.tmp_reg
        saved_reg_offsets = self.arch.fixed_scratch_offsets(
            (reg.name for reg in fixed_regs), AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET)

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_shadow_stack(
                fixed_regs,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
                preserve_sp=True,
            )
            for scratchpad_idx, mem_operand, mem_symexpr in capture_operands:
                asm += self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi,
                    inst,
                    addr_reg,
                    tmp_reg,
                    mem_operand,
                    ctx.stack_adjustment,
                    mem_symexpr=mem_symexpr,
                    saved_reg_offsets=saved_reg_offsets,
                    saved_reg_base="shadow_sp",
                )
                asm += self.arch.load_address(tmp_reg, f"scratchpad+{scratchpad_idx * 8}")
                asm += f"str {addr_reg}, [{tmp_reg}]\n"

            asm += self.arch.restore_regs_from_shadow_stack(
                fixed_regs,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
                preserve_sp=True,
            )
            return asm

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        if not isinstance(scratch_plan, AArch64TextDiftScratchPlan):
            raise TypeError("AArch64 text DIFT replay requires an AArch64 scratch plan")

        saved_regs = [
            reg for reg in registers
            if reg.name not in {"x16", "x17", "x31", "sp", "wsp", "xzr", "wzr"}
        ]
        fixed_regs = scratch_plan.saved_regs
        stack_delta = TEXT_DIFT_LLVM_STACK_SP_OFFSET - TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_shadow_stack(
                fixed_regs,
                save_flags=True,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
                preserve_sp=True,
            )
            asm += self.arch.load_address("x16", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            for idx, reg in enumerate(saved_regs):
                asm += f"str {reg}, [x16, #{idx * 8}]\n"
            asm += f"""
                mov x17, sp
                str x17, [x16, #{TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}]
                {self.arch.add_sub_constant_from_base("add", "x17", "x16", "x17", stack_delta)}
                mov sp, x17
            """
            asm += assembly.strip() + "\n"
            asm += self.arch.load_address("x16", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            asm += f"""
                ldr x17, [x16, #{TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}]
                mov sp, x17
            """
            for idx, reg in reversed(list(enumerate(saved_regs))):
                asm += f"ldr {reg}, [x16, #{idx * 8}]\n"
            asm += self.arch.restore_regs_from_shadow_stack(
                fixed_regs,
                save_flags=True,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
                preserve_sp=True,
            )
            return asm

        return patch
