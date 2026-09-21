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
    # Keep patch instructions four bytes wide: implicit compression breaks the
    # rewriter's padding alignment, independently of the input binary's ISA.
    TARGET_FEATURES = "+m,+a,+f,+d"
    LLVM_CALLER_SAVED_GPRS = (
        "ra",
        "t0", "t1", "t2", "t3", "t4", "t5", "t6",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    )

    def _get_register_usage(self, asm: str):
        regs = {}
        for name in re.findall(
                r"\b(zero|ra|sp|gp|tp|t[0-6]|s(?:[0-9]|1[01])|a[0-7]|x(?:[0-9]|[12][0-9]|3[01]))\b",
                asm):
            normalized = self.reg_manager.abi.normalize_register_name(name)
            if normalized != "zero":
                regs[normalized] = self.reg_manager.abi.register_from_name(normalized)

        # Libcall clobbers are implicit and absent from the assembly scan.
        if re.search(r"(?m)^\s*call\s+", asm):
            for name in self.LLVM_CALLER_SAVED_GPRS:
                reg = self.reg_manager.abi.register_from_name(name)
                regs[reg.name] = reg
        return self.reg_manager.abi.sort_registers(regs.values())

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
        saved_reg_offsets = {
            reg.name: SCRATCHPAD_FIRST_SPILL_OFFSET + idx * 8
            for idx, reg in enumerate(scratch_plan.saved_regs)
        }

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            asm = self.arch.save_regs_to_first_spill(scratch_plan.saved_regs)
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
                )
                asm += self.arch.load_address(tmp_reg, f"scratchpad+{scratchpad_idx * 8}")
                asm += f"sd {addr_reg}, 0({tmp_reg})\n"
            asm += self.arch.restore_regs_from_first_spill(scratch_plan.saved_regs)
            return asm

        return patch

    def _build_optimized_dift_values_patch(self, assembly: str, registers, *, scratch_plan=None):
        if scratch_plan is None:
            scratch_plan = self._plan_scratch_registers(2)
        saved_regs = []
        primary_scratch = scratch_plan.registers[0]
        for reg in (primary_scratch, *registers):
            if (reg.name in {"zero", "sp", "tp"} or reg in saved_regs
                    or reg not in scratch_plan.live_registers):
                continue
            saved_regs.append(reg)
        stack_delta = TEXT_DIFT_LLVM_STACK_SP_OFFSET - TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET
        float_regs = sorted(set(re.findall(
            r"\b(?:f[ts](?:[0-9]|1[01])|fa[0-7]|f(?:[0-9]|[12][0-9]|3[01]))\b",
            assembly)))
        if re.search(r"(?m)^\s*call\s+", assembly):
            float_regs = [f"f{idx}" for idx in range(32)]
        float_offset = len(saved_regs) * 8
        control_offset = float_offset + len(float_regs) * 8
        assert control_offset + 8 <= TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT

        @self.arch.constraints()
        def patch(ctx: InsertionContext):
            # mcasm starts at RV64I. Match LLVM's features for this assembly
            # transaction, including FP state saves around generated calls.
            asm = '.attribute arch, "rv64imafd"\n'
            asm += self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            for idx, reg in enumerate(saved_regs):
                asm += f"sd {reg}, {idx * 8}(tp)\n"
            for idx, reg in enumerate(float_regs):
                asm += f"fsd {reg}, {float_offset + idx * 8}(tp)\n"
            if float_regs:
                asm += f"frcsr {primary_scratch}\nsd {primary_scratch}, {control_offset}(tp)\n"
            asm += f"""
                li {primary_scratch}, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add {primary_scratch}, tp, {primary_scratch}
                sd sp, 0({primary_scratch})
                li {primary_scratch}, {stack_delta}
                add sp, tp, {primary_scratch}
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            asm += assembly.strip() + "\n"
            asm += self.arch.load_address("tp", f"scratchpad+{TEXT_DIFT_LLVM_SCRATCH_SAVE_OFFSET}")
            asm += f"""
                li {primary_scratch}, {TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT}
                add {primary_scratch}, tp, {primary_scratch}
                ld sp, 0({primary_scratch})
            """
            for idx, reg in enumerate(float_regs):
                asm += f"fld {reg}, {float_offset + idx * 8}(tp)\n"
            if float_regs:
                asm += f"ld {primary_scratch}, {control_offset}(tp)\nfscsr {primary_scratch}\n"
            for idx, reg in reversed(list(enumerate(saved_regs))):
                asm += f"ld {reg}, {idx * 8}(tp)\n"
            asm += f"""
                {self.arch.load_address("tp", f"scratchpad+{RISCV64_ORIGINAL_TP_OFFSET}")}
                ld tp, 0(tp)
            """
            return asm

        return patch
