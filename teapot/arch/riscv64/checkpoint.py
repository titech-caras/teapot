from uuid import UUID

from gtirb_rewriting import InsertionContext

from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.utils.misc import generate_distinct_label_name


class RISCV64CheckpointPatchesMixin:
    CHECKPOINT_PATCH_USES_LIVE_REGISTERS = False
    RESTORE_POINT_PATCH_USES_LIVE_REGISTERS = False

    def checkpoint_patch(self, block_uuid: UUID, use_scratch_registers: bool = True):
        @self.constraints(scratch_registers=0)
        def patch(ctx: InsertionContext):
            trampoline_landing = generate_distinct_label_name(".__trampoline_landing_", block_uuid)
            branch_counter = generate_distinct_label_name(".__branch_counter_", block_uuid)
            return_landing = generate_distinct_label_name(".__return_landing_", block_uuid)
            after_checkpoint = f".L__after_checkpoint{SYMBOL_SUFFIX}"
            return f"""
                {self.save_regs_to_first_spill(self.FIRST_SPILL_T0_T1)}
                {self.load_address("t0", trampoline_landing)}
                {self.load_address("t1", "checkpoint_target_metadata")}
                sd t0, 0(t1)
                {self.load_address("t0", return_landing)}
                sd t0, 8(t1)
                {self.load_address("t0", branch_counter)}
                sd t0, 16(t1)
                {self.jump_symbol("make_checkpoint_riscv64", "t0")}
            {return_landing}:
                {self.load_address("t0", "checkpoint_target_metadata")}
                ld t0, {self.CHECKPOINT_TARGET_SCRATCH_REG_ADDR}(t0)
            {after_checkpoint}:
                nop
            """

        return patch

    def init_library_patch(self):
        return self.constraints()(lambda ctx: f"""
            addi sp, sp, -32
            sd a0, 0(sp)
            sd a1, 8(sp)
            sd ra, 16(sp)
            {self.call_symbol("libcheckpoint_enable")}
            ld ra, 16(sp)
            ld a1, 8(sp)
            ld a0, 0(sp)
            addi sp, sp, 32
        """)

    def fini_library_patch(self):
        return self.constraints()(lambda ctx: f"""
            addi sp, sp, -16
            sd a0, 0(sp)
            sd ra, 8(sp)
            {self.call_symbol("libcheckpoint_disable")}
            ld ra, 8(sp)
            ld a0, 0(sp)
            addi sp, sp, 16
        """)

    def conditional_restore_point_patch(self, instruction_count: int, use_scratch_registers: bool = True):
        @self.constraints(scratch_registers=2 if use_scratch_registers else 0)
        def patch(ctx: InsertionContext):
            counter_reg, limit_reg = ctx.scratch_registers[:2] if use_scratch_registers else ("t0", "t1")
            prologue = "" if use_scratch_registers else self.save_regs_to_first_spill(
                self.FIRST_SPILL_T0_T1)
            success_epilogue = "" if use_scratch_registers else self.restore_regs_from_first_spill(
                self.FIRST_SPILL_T0_T1)
            rollback_epilogue = "" if use_scratch_registers else self.restore_regs_from_first_spill(
                self.FIRST_SPILL_T0_T1)
            rollback_reg = counter_reg if use_scratch_registers else "t0"
            return f"""
                {prologue}
                {self.load_address(limit_reg, "instruction_cnt")}
                ld {counter_reg}, 0({limit_reg})
                li {limit_reg}, {instruction_count}
                add {counter_reg}, {counter_reg}, {limit_reg}
                li {limit_reg}, {ROB_LEN}
                bgeu {counter_reg}, {limit_reg}, 1f
                {self.load_address(limit_reg, "instruction_cnt")}
                sd {counter_reg}, 0({limit_reg})
                {success_epilogue}
                j 2f
            1:
                {rollback_epilogue}
                {self.jump_symbol("restore_checkpoint_ROB_LEN", rollback_reg)}
            2:
                nop
            """

        return patch

    def unconditional_restore_point_patch(self):
        return self.constraints()(lambda ctx: self.jump_symbol("restore_checkpoint_EXT_LIB", "t0"))
