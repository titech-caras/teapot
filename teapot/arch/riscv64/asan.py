from teapot.configs.runtime import ASAN_TAG_STORAGE_SHADOW, SYMBOL_SUFFIX


class RISCV64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg, scratch_reg,
                           tag_storage: str = ASAN_TAG_STORAGE_SHADOW, end_reg=None) -> str:
        if access_size <= 0:
            raise ValueError("RV64 ASan check access size must be positive")
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")
        if access_size > 8:
            return self._shadow_check_loop_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_offset=shadow_offset, shadow_reg=shadow_reg,
                scratch_reg=scratch_reg, end_reg=end_reg)

        asm = f"""
            srli {scratch_reg}, {addr_reg}, 3
            li {shadow_reg}, {shadow_offset}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            lbu {shadow_reg}, 0({scratch_reg})
            beqz {shadow_reg}, {check_ok_label}
        """
        if access_size < 8:
            asm += f"""
                sltiu {scratch_reg}, {shadow_reg}, 8
                beqz {scratch_reg}, .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
                andi {scratch_reg}, {addr_reg}, 7
                addi {scratch_reg}, {scratch_reg}, {access_size - 1}
                bltu {scratch_reg}, {shadow_reg}, {check_ok_label}
            .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
            """
        return asm

    def _shadow_check_loop_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                                   shadow_offset: int, shadow_reg, scratch_reg, end_reg) -> str:
        if end_reg is None:
            raise ValueError("wide RV64 ASan checks require an end_reg scratch register")

        return f"""
            srli {scratch_reg}, {addr_reg}, 3
            {self.add_constant_from_base(end_reg, addr_reg, shadow_reg, access_size - 1)}
            srli {end_reg}, {end_reg}, 3
            li {shadow_reg}, {shadow_offset}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            add {end_reg}, {end_reg}, {shadow_reg}
        .L__asan_shadow_check_loop{SYMBOL_SUFFIX}:
            lbu {shadow_reg}, 0({scratch_reg})
            beq {scratch_reg}, {end_reg}, .L__asan_shadow_check_last{SYMBOL_SUFFIX}
            bnez {shadow_reg}, .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            addi {scratch_reg}, {scratch_reg}, 1
            j .L__asan_shadow_check_loop{SYMBOL_SUFFIX}
        .L__asan_shadow_check_last{SYMBOL_SUFFIX}:
            beqz {shadow_reg}, {check_ok_label}
            sltiu {end_reg}, {shadow_reg}, 8
            beqz {end_reg}, .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            andi {end_reg}, {addr_reg}, 7
            {self.add_constant_from_base(end_reg, end_reg, scratch_reg, access_size - 1)}
            andi {end_reg}, {end_reg}, 7
            bltu {end_reg}, {shadow_reg}, {check_ok_label}
        .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
        """

    def asan_stack_poison_snippet(self, addr_reg, value_reg, top_reg, *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool,
                                  tag_storage: str = ASAN_TAG_STORAGE_SHADOW) -> str:
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")

        value = 0xff if poison else 0
        memlog = self.memlog_snippet(addr_reg, top_reg, value_reg, 1) if insert_memlog else ""
        return f"""
            mv {addr_reg}, sp
            addi {addr_reg}, {addr_reg}, -8
            srli {addr_reg}, {addr_reg}, 3
            li {value_reg}, {shadow_offset}
            add {addr_reg}, {addr_reg}, {value_reg}
            {memlog}
            li {value_reg}, {value}
            sb {value_reg}, 0({addr_reg})
        """

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = ASAN_TAG_STORAGE_SHADOW):
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")

        scratch_count = 3 if insert_memlog else 2

        @self.constraints(scratch_registers=scratch_count)
        def patch(ctx):
            addr_reg, value_reg = ctx.scratch_registers[:2]
            top_reg = ctx.scratch_registers[2] if insert_memlog else None
            return f"""
                {self.asan_stack_poison_snippet(
                    addr_reg, value_reg, top_reg, poison=poison,
                    shadow_offset=shadow_offset, insert_memlog=insert_memlog,
                    tag_storage=tag_storage)}
            """

        return patch
