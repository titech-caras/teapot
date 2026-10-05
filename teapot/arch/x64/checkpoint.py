from uuid import UUID

from gtirb_rewriting import InsertionContext

from teapot.configs.runtime import (
    CHECKPOINT_TARGET_BRANCH_COUNTER_OFFSET,
    CHECKPOINT_TARGET_RETURN_OFFSET,
    ROB_LEN,
    SYMBOL_SUFFIX,
)
from teapot.utils.misc import generate_distinct_label_name


class X64CheckpointPatchesMixin:
    def static_instruction_cost(self, instruction) -> int:
        # The transient REP loop charges each executed element separately.
        return 0 if self.rep_string_kind(instruction) is not None else 1

    def can_insert_restore_point(self, live_registers) -> bool:
        return live_registers is None or "rflags" not in (r.name for r in live_registers)

    def checkpoint_patch(self, block_uuid: UUID, *, use_scratch_registers: bool = True,
                         save_df=False, vector_case=2):
        entry = ('make_checkpoint_integer', 'make_checkpoint_xmm', 'make_checkpoint_x64')[vector_case]
        if save_df:
            entry = 'make_checkpoint_df' if vector_case == 2 else entry + '_df'
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
                mov [checkpoint_target_metadata+{CHECKPOINT_TARGET_RETURN_OFFSET}], {r}
                lea {r}, [rip+{generate_distinct_label_name(".__branch_counter_", block_uuid)}]
                mov [checkpoint_target_metadata+{CHECKPOINT_TARGET_BRANCH_COUNTER_OFFSET}], {r}
                {epilogue}
                jmp {entry}
            .L__after_checkpoint{SYMBOL_SUFFIX}:
                nop
            """

        return patch

    def trampoline_patch(self, block_uuid: UUID, transient_block_uuid: UUID, mnemonic: str, op_str: str,
                         conditional_target_symbol_name: str, non_conditional_target_symbol_name: str,
                         checkpoint_spare_registers=()):
        return self.constraints()(lambda ctx: f"""
        {generate_distinct_label_name(".__trampoline_", block_uuid)}:
        {generate_distinct_label_name(".__trampoline_", transient_block_uuid)}:
            {mnemonic} {conditional_target_symbol_name}
            jmp {non_conditional_target_symbol_name}
        """)

    def init_library_patch(self, vector_state=None):
        select = (f'mov edi, {vector_state}\ncall libcheckpoint_set_vector_state\n'
                  'mov rdi, [rsp+16]\nmov rsi, [rsp+8]' if vector_state is not None else '')
        return self.constraints()(lambda ctx: f"""
            push rdi
            push rsi
            push rdx
            {select}
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
        """Charge the code since the last point to the speculation window, or roll back.

        The window rule is unchanged: with the 64-bit counter c, the point rolls
        back when c + n >= ROB_LEN (signed) and otherwise stores c + n. It now
        compares c with ROB_LEN - n before adding n in memory, so it needs no
        scratch register. As before, a rejection leaves the counter unchanged;
        the runtime replaces it with the checkpoint's value. The two compares
        agree while c + n does not overflow: the counter only grows by checked
        steps from a checkpoint's value below ROB_LEN, and n is a block's cost.
        The flags still go through the allocator (clobbers_flags), which saves
        them only where they are live.
        """
        threshold = ROB_LEN - instruction_count
        if not (0 <= instruction_count < 2 ** 31 and -2 ** 31 <= threshold < 2 ** 31):
            # Both are sign-extended 32-bit immediates.
            raise ValueError(f"restore point cost {instruction_count} does not fit the counter's immediates")

        @self.constraints(clobbers_flags=True)
        def patch(ctx: InsertionContext):
            asm = f"""
                cmp qword ptr instruction_cnt, {threshold}
                jge restore_checkpoint_ROB_LEN
            """
            if instruction_count:
                asm += f"add qword ptr instruction_cnt, {instruction_count}\n"
            return asm

        return patch

    def unconditional_restore_point_patch(self):
        # Rollback enters C, including when an unsupported string operation is
        # reached with the application's DF set. The checkpoint owns its flags.
        return self.constraints()(lambda ctx: "cld\njmp restore_checkpoint_EXT_LIB")
