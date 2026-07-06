from uuid import UUID

from gtirb_rewriting import InsertionContext

from teapot.configs.runtime import ROB_LEN, SYMBOL_SUFFIX
from teapot.utils.misc import generate_distinct_label_name


class X64CheckpointPatchesMixin:
    def can_insert_restore_point(self, reg_manager, function, block, instruction_idx) -> bool:
        return "rflags" not in (r.name for r in reg_manager.live_registers(function, block, instruction_idx))

    def checkpoint_patch(self, block_uuid: UUID, use_scratch_registers: bool = True):
        @self.constraints(scratch_registers=1 if use_scratch_registers else 0)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0] if use_scratch_registers else "rax"
            prologue = "" if use_scratch_registers else "mov scratchpad, rax"
            epilogue = "" if use_scratch_registers else "mov rax, scratchpad"
            return f"""
                {prologue}
                lea {r}, [rip+{generate_distinct_label_name(".__trampoline_", block_uuid)}]
                mov checkpoint_target_metadata, {r}
                lea {r}, [rip+.L__after_checkpoint{SYMBOL_SUFFIX}]
                mov [checkpoint_target_metadata+8], {r}
                lea {r}, [rip+{generate_distinct_label_name(".__branch_counter_", block_uuid)}]
                mov [checkpoint_target_metadata+16], {r}
                {epilogue}
                jmp make_checkpoint_x64
            .L__after_checkpoint{SYMBOL_SUFFIX}:
                nop
            """

        return patch

    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str):
        return self.constraints()(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {mnemonic} {conditional_target_symbol_name}
            jmp {non_conditional_target_symbol_name}
        """)

    def init_library_patch(self):
        return self.constraints()(lambda ctx: """
            push rdi
            push rsi
            push rdx
            call libcheckpoint_enable
            pop rdx
            pop rsi
            pop rdi
        """)

    def fini_library_patch(self):
        return self.constraints()(lambda ctx: """
            push rax
            call libcheckpoint_disable
            pop rax
        """)

    def conditional_restore_point_patch(self, instruction_count: int):
        @self.constraints(scratch_registers=1, clobbers_flags=True)
        def patch(ctx: InsertionContext):
            r = ctx.scratch_registers[0]
            return f"""
                mov {r}, instruction_cnt
                add {r}, {instruction_count}
                cmp {r}, {ROB_LEN}
                jge restore_checkpoint_ROB_LEN
                mov instruction_cnt, {r}
            """

        return patch

    def unconditional_restore_point_patch(self):
        return self.constraints()(lambda ctx: "jmp restore_checkpoint_EXT_LIB")
