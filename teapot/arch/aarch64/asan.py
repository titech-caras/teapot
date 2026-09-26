from teapot.configs.runtime import (
    ASAN_TAG_STORAGE_MTE,
    ASAN_TAG_STORAGE_SHADOW,
    SYMBOL_SUFFIX,
)


class AArch64AsanPatchesMixin:
    MTE_ARCH_DIRECTIVE = ".arch armv8.5-a+memtag"

    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg, scratch_reg,
                           tag_storage: str = ASAN_TAG_STORAGE_SHADOW, end_reg=None) -> str:
        if access_size <= 0:
            raise ValueError("AArch64 ASan check access size must be positive")
        if tag_storage == ASAN_TAG_STORAGE_MTE:
            return self._mte_check_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_reg=shadow_reg, scratch_reg=scratch_reg, end_reg=end_reg)
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError(f"Unsupported AArch64 tag storage: {tag_storage}")

        if access_size > 1:
            return self._shadow_range_check_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_offset=shadow_offset, shadow_reg=shadow_reg,
                scratch_reg=scratch_reg, end_reg=end_reg)

        return f"""
            lsr {scratch_reg}, {addr_reg}, #3
            {self.mov_u64(shadow_reg, shadow_offset)}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            ldrb {shadow_reg:32}, [{scratch_reg}]
            cbz {shadow_reg:32}, {check_ok_label}
            cmp {shadow_reg:32}, #8
            b.hs .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            and {scratch_reg:32}, {addr_reg:32}, #7
            cmp {scratch_reg:32}, {shadow_reg:32}
            b.lo {check_ok_label}
        .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
        """

    def _shadow_range_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                                   shadow_offset: int, shadow_reg, scratch_reg, end_reg) -> str:
        if end_reg is None:
            raise ValueError("multi-byte AArch64 ASan checks require an end_reg scratch register")

        next_granule = (f"b .L__asan_shadow_check_loop{SYMBOL_SUFFIX}" if access_size > 8
                        else f"ldrb {shadow_reg:32}, [{scratch_reg}]")

        return f"""
            lsr {scratch_reg}, {addr_reg}, #3
            {self.add_sub_constant_from_base("add", end_reg, addr_reg, shadow_reg, access_size - 1)}
            lsr {end_reg}, {end_reg}, #3
            {self.mov_u64(shadow_reg, shadow_offset)}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            add {end_reg}, {end_reg}, {shadow_reg}
        .L__asan_shadow_check_loop{SYMBOL_SUFFIX}:
            ldrb {shadow_reg:32}, [{scratch_reg}]
            cmp {scratch_reg}, {end_reg}
            b.eq .L__asan_shadow_check_last{SYMBOL_SUFFIX}
            cbnz {shadow_reg:32}, .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            add {scratch_reg}, {scratch_reg}, #1
            {next_granule}
        .L__asan_shadow_check_last{SYMBOL_SUFFIX}:
            cbz {shadow_reg:32}, {check_ok_label}
            cmp {shadow_reg:32}, #8
            b.hs .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
            and {end_reg:32}, {addr_reg:32}, #7
            {self.add_sub_constant_from_base("add", end_reg, end_reg, scratch_reg, access_size - 1)}
            and {end_reg:32}, {end_reg:32}, #7
            cmp {end_reg:32}, {shadow_reg:32}
            b.lo {check_ok_label}
        .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
        """

    @staticmethod
    def _mte_load_tag_snippet(tag_reg, addr_reg) -> str:
        return f"""
            {AArch64AsanPatchesMixin.MTE_ARCH_DIRECTIVE}
            ldg {tag_reg}, [{addr_reg}]
            ubfx {tag_reg}, {tag_reg}, #56, #4
        """

    def _mte_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_reg, scratch_reg, end_reg) -> str:
        if access_size <= 0:
            raise ValueError("AArch64 MTE ASan check access size must be positive")
        fail_label = f".L__asan_mte_check_fail{SYMBOL_SUFFIX}"

        if access_size == 1:
            return f"""
                mov {scratch_reg}, {addr_reg}
                bic {scratch_reg}, {scratch_reg}, #0xf
                {self._mte_compare_tag_snippet(shadow_reg, scratch_reg, fail_label)}
                b {check_ok_label}
            {fail_label}:
            """

        if end_reg is None:
            raise ValueError("multi-granule AArch64 MTE ASan checks require an end_reg scratch register")

        if access_size <= 16:
            return f"""
                mov {scratch_reg}, {addr_reg}
                {self.add_sub_constant_from_base("add", end_reg, addr_reg, shadow_reg, access_size - 1)}
                bic {scratch_reg}, {scratch_reg}, #0xf
                bic {end_reg}, {end_reg}, #0xf
                {self._mte_compare_tag_snippet(shadow_reg, scratch_reg, fail_label)}
                cmp {scratch_reg}, {end_reg}
                b.eq {check_ok_label}
                {self._mte_compare_tag_snippet(shadow_reg, end_reg, fail_label)}
                b {check_ok_label}
            {fail_label}:
            """

        return f"""
            mov {scratch_reg}, {addr_reg}
            {self.add_sub_constant_from_base("add", end_reg, addr_reg, shadow_reg, access_size - 1)}
            bic {scratch_reg}, {scratch_reg}, #0xf
            bic {end_reg}, {end_reg}, #0xf
        .L__asan_mte_check_loop{SYMBOL_SUFFIX}:
            {self._mte_compare_tag_snippet(shadow_reg, scratch_reg, fail_label)}
            cmp {scratch_reg}, {end_reg}
            b.eq {check_ok_label}
            add {scratch_reg}, {scratch_reg}, #16
            b .L__asan_mte_check_loop{SYMBOL_SUFFIX}
        {fail_label}:
        """

    def _mte_compare_tag_snippet(self, tag_reg, addr_reg, fail_label: str) -> str:
        return f"""
            {self._mte_load_tag_snippet(tag_reg, addr_reg)}
            lsl {tag_reg}, {tag_reg}, #56
            eor {tag_reg}, {tag_reg}, {addr_reg}
            tst {tag_reg}, #0x0f00000000000000
            b.ne {fail_label}
        """

    def asan_stack_poison_snippet(self, addr_reg, value_reg, top_reg, *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool,
                                  tag_storage: str = ASAN_TAG_STORAGE_SHADOW, slot=None) -> str:
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("AArch64 saved-return poisoning requires shadow tag storage")
        if slot is None:
            raise ValueError("AArch64 saved-return poisoning requires a verified stack slot")

        base, displacement = slot
        value = 0xff if poison else 0
        memlog = self.memlog_snippet(addr_reg, top_reg, value_reg, 1) if insert_memlog else ""
        return f"""
            {self.add_sub_constant_from_base('sub' if displacement < 0 else 'add',
                                            addr_reg, base, value_reg, abs(displacement))}
            lsr {addr_reg}, {addr_reg}, #3
            {self.mov_u64(value_reg, shadow_offset)}
            add {addr_reg}, {addr_reg}, {value_reg}
            {memlog}
            mov {value_reg}, #{value}
            strb {value_reg:32}, [{addr_reg}]
        """

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = ASAN_TAG_STORAGE_SHADOW, slot=None):
        if slot is None:
            raise ValueError("AArch64 saved-return poisoning requires a verified stack slot")
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
