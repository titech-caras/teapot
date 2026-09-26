import re

from capstone import CsInsn
from gtirb_rewriting import InsertionContext

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


class AArch64TextDiftPropagationLLVMPass(TextDiftLLVMBase, AArch64DiftPropagationPass):
    EXPECTED_ARCH = "aarch64"
    ASM_RETURN_BRANCH = "b"
    TARGET_TRIPLE = "aarch64-unknown-linux-gnu"
    TARGET_FEATURES = "+neon,+fp-armv8"

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

        if scratch_plan is None:
            scratch_plan = self._plan_scratch_registers(2)
        addr_reg, tmp_reg = scratch_plan.registers
        saved_reg_offsets = self.arch.fixed_scratch_offsets(
            scratch_plan.saved_regs, AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET)

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_shadow_stack(
                scratch_plan.saved_regs,
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
                scratch_plan.saved_regs,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET,
                preserve_sp=True,
            )
            return asm

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        if scratch_plan is None:
            scratch_plan = self._plan_scratch_registers(2)
        addr_reg, tmp_reg = scratch_plan.registers
        save_flags = self.reg_manager.abi.flag_register() in scratch_plan.live_registers
        clobbered_regs = list(registers)
        # LLVM can vectorize integer tag operations. Preserve full Q registers,
        # including the upper halves that the ordinary calling convention omits.
        simd_regs = sorted({int(number) for number in re.findall(
            r"\b[vqdsbh]([0-9]|[12][0-9]|3[01])\b", assembly)})
        if re.search(r"(?m)^\s*(?:bl|blr)\s+", assembly):
            clobbered_regs.extend(
                self.reg_manager.abi.get_register(f"x{idx}")
                for idx in (*range(19), 30))
            simd_regs = list(range(32))
        # The frontend masks track GPRs/NZCV only. Keep SIMD and FP-control
        # preservation independent of this GPR save-elimination decision.
        saved_regs = [reg for reg in dict.fromkeys(clobbered_regs)
                      if reg in scratch_plan.live_registers and reg not in scratch_plan.registers
                      and reg.name not in {"x31", "sp", "wsp", "xzr", "wzr"}]
        simd_offset = (len(saved_regs) * 8 + 15) & -16
        control_offset = simd_offset + len(simd_regs) * 16
        assert control_offset + 16 <= TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT
        stack_delta = TEXT_DIFT_LLVM_STACK_SP_OFFSET - TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_shadow_stack(
                scratch_plan.saved_regs,
                save_flags=save_flags,
                flag_reg=tmp_reg,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
                preserve_sp=True,
            )
            asm += self.arch.load_address(addr_reg, f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            for idx, reg in enumerate(saved_regs):
                asm += f"str {reg}, [{addr_reg}, #{idx * 8}]\n"
            for idx, reg in enumerate(simd_regs):
                asm += f"str q{reg}, [{addr_reg}, #{simd_offset + idx * 16}]\n"
            if simd_regs:
                asm += f"""
                    mrs {tmp_reg}, fpcr
                    str {tmp_reg}, [{addr_reg}, #{control_offset}]
                    mrs {tmp_reg}, fpsr
                    str {tmp_reg}, [{addr_reg}, #{control_offset + 8}]
                """
            asm += f"""
                mov {tmp_reg}, sp
                str {tmp_reg}, [{addr_reg}, #{TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}]
                {self.arch.add_sub_constant_from_base("add", tmp_reg, addr_reg, tmp_reg, stack_delta)}
                mov sp, {tmp_reg}
            """
            asm += assembly.strip() + "\n"
            asm += self.arch.load_address(addr_reg, f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            asm += f"""
                ldr {tmp_reg}, [{addr_reg}, #{TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}]
                mov sp, {tmp_reg}
            """
            for idx, reg in reversed(list(enumerate(saved_regs))):
                asm += f"ldr {reg}, [{addr_reg}, #{idx * 8}]\n"
            for idx, reg in enumerate(simd_regs):
                asm += f"ldr q{reg}, [{addr_reg}, #{simd_offset + idx * 16}]\n"
            if simd_regs:
                asm += f"""
                    ldr {tmp_reg}, [{addr_reg}, #{control_offset}]
                    msr fpcr, {tmp_reg}
                    ldr {tmp_reg}, [{addr_reg}, #{control_offset + 8}]
                    msr fpsr, {tmp_reg}
                """
            asm += self.arch.restore_regs_from_shadow_stack(
                scratch_plan.saved_regs,
                save_flags=save_flags,
                flag_reg=tmp_reg,
                frame_offset=AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET,
                preserve_sp=True,
            )
            return asm

        return patch
