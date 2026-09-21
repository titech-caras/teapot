from teapot.configs.runtime import ASAN_TAG_STORAGE_SHADOW, SYMBOL_SUFFIX


class RISCV64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg, scratch_reg,
                           tag_storage: str = ASAN_TAG_STORAGE_SHADOW, end_reg=None) -> str:
        if access_size <= 0:
            raise ValueError("RV64 ASan check access size must be positive")
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")
        if access_size > 1:
            return self._shadow_range_check_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_offset=shadow_offset, shadow_reg=shadow_reg,
                scratch_reg=scratch_reg, end_reg=end_reg)

        return f"""
            srli {scratch_reg}, {addr_reg}, 3
            li {shadow_reg}, {shadow_offset}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            lbu {shadow_reg}, 0({scratch_reg})
            beqz {shadow_reg}, {check_ok_label}
            sltiu {scratch_reg}, {shadow_reg}, 8
            beqz {scratch_reg}, .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            andi {scratch_reg}, {addr_reg}, 7
            bltu {scratch_reg}, {shadow_reg}, {check_ok_label}
        .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
        """

    def _shadow_range_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                                   shadow_offset: int, shadow_reg, scratch_reg, end_reg) -> str:
        if end_reg is None:
            raise ValueError("multi-byte RV64 ASan checks require an end_reg scratch register")

        next_granule = (f"j .L__asan_shadow_check_loop{SYMBOL_SUFFIX}" if access_size > 8
                        else f"lbu {shadow_reg}, 0({scratch_reg})")

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
            {next_granule}
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
                                  tag_storage: str = ASAN_TAG_STORAGE_SHADOW, slot=None) -> str:
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")
        if slot is None:
            raise ValueError("RV64 saved-return poisoning requires a verified stack slot")

        base, displacement = slot
        value = 0xff if poison else 0
        memlog = self.memlog_snippet(addr_reg, top_reg, value_reg, 1) if insert_memlog else ""
        return f"""
            {self.add_constant_from_base(addr_reg, base, value_reg, displacement)}
            srli {addr_reg}, {addr_reg}, 3
            li {value_reg}, {shadow_offset}
            add {addr_reg}, {addr_reg}, {value_reg}
            {memlog}
            li {value_reg}, {value}
            sb {value_reg}, 0({addr_reg})
        """

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = ASAN_TAG_STORAGE_SHADOW, slot=None):
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("RV64 only supports ASan shadow tag storage")
        if slot is None:
            raise ValueError("RV64 saved-return poisoning requires a verified stack slot")

        scratch_count = 3 if insert_memlog else 2

        @self.constraints(scratch_registers=scratch_count, reads_registers={slot[0].name})
        def patch(ctx):
            addr_reg, value_reg = ctx.scratch_registers[:2]
            top_reg = ctx.scratch_registers[2] if insert_memlog else None
            base, displacement = slot
            if base == abi.get_register("sp"):
                displacement += ctx.stack_adjustment or 0
            return self.asan_stack_poison_snippet(
                addr_reg, value_reg, top_reg, poison=poison,
                shadow_offset=shadow_offset, insert_memlog=insert_memlog,
                tag_storage=tag_storage, slot=(base, displacement))

        return patch
