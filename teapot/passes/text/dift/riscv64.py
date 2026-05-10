import re

from capstone_gt import CsInsn
from gtirb_rewriting import InsertionContext

from teapot.configs.slots import (
    RISCV64_ORIGINAL_TP_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)
from teapot.passes.common.dift.riscv64 import RISCV64DiftPropagationPass
from teapot.passes.text.dift.base import (
    TextDiftLLVMBase,
    TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT,
    TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET,
    TEXT_DIFT_LLVM_STACK_SP_OFFSET,
)


class RISCV64TextDiftPropagationLLVMPass(TextDiftLLVMBase, RISCV64DiftPropagationPass):
    EXPECTED_ARCH = "riscv64"
    TARGET_TRIPLE = "riscv64-unknown-linux-gnu"

    def _get_register_usage(self, asm: str):
        regs = {}
        for name in re.findall(
                r"\b(zero|ra|sp|gp|tp|t[0-6]|s(?:[0-9]|1[01])|a[0-7]|x(?:[0-9]|[12][0-9]|3[01]))\b",
                asm):
            normalized = self.reg_manager.abi.normalize_register_name(name)
            if normalized != "zero":
                regs[normalized] = self.reg_manager.abi.register_from_name(normalized)
        return self.reg_manager.abi.sort_registers(regs.values())

    def _build_store_values_patch(self, inst: CsInsn, capture_operands, scratch_plan=None,
                                  conditional=None, conditional_slot=None):
        if not capture_operands:
            @self.arch.constraints()
            def empty_patch(ctx: InsertionContext):
                return ""

            return empty_patch

        fixed_regs = self.arch.fixed_spill_registers(self.reg_manager.abi, 2)
        saved_reg_offsets = {
            reg.name: SCRATCHPAD_FIRST_SPILL_OFFSET + idx * 8
            for idx, reg in enumerate(fixed_regs)
        }

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_first_spill(fixed_regs)
            for scratchpad_idx, mem_operand, _ in capture_operands:
                asm += self.arch.mem_operand_address_snippet(
                    self.reg_manager.abi,
                    inst,
                    "t0",
                    "t1",
                    mem_operand,
                    ctx.stack_adjustment,
                    saved_reg_offsets=saved_reg_offsets,
                )
                asm += self.arch.load_address("t1", f"scratchpad+{scratchpad_idx * 8}")
                asm += f"sd {fixed_regs[0]}, 0({fixed_regs[1]})\n"
            asm += self.arch.restore_regs_from_first_spill(fixed_regs)
            return asm

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        saved_regs = []
        primary_scratch = self.arch.fixed_spill_registers(self.reg_manager.abi, 1)[0]
        for reg in (primary_scratch, *registers):
            if reg.name in {"zero", "sp", "tp"} or reg in saved_regs:
                continue
            saved_regs.append(reg)
        stack_delta = TEXT_DIFT_LLVM_STACK_SP_OFFSET - TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            for idx, reg in enumerate(saved_regs):
                asm += f"sd {reg}, {idx * 8}(tp)\n"
            asm += f"""
                li t0, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add t0, tp, t0
                sd sp, 0(t0)
                li t0, {stack_delta}
                add sp, tp, t0
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            asm += assembly.strip() + "\n"
            asm += self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            asm += f"""
                li t0, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add t0, tp, t0
                ld sp, 0(t0)
            """
            for idx, reg in reversed(list(enumerate(saved_regs))):
                asm += f"ld {reg}, {idx * 8}(tp)\n"
            asm += f"""
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            return asm

        return patch
