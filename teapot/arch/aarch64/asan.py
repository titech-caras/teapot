from teapot.configs.runtime import (
    ASAN_TAG_STORAGE_MTE,
    ASAN_TAG_STORAGE_SHADOW,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_MTE_TAG_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
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

        if access_size > 8:
            return self._shadow_check_loop_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_offset=shadow_offset, shadow_reg=shadow_reg,
                scratch_reg=scratch_reg, end_reg=end_reg)

        asm = f"""
            lsr {scratch_reg}, {addr_reg}, #3
            {self.mov_u64(shadow_reg, shadow_offset)}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            ldrb {shadow_reg:32}, [{scratch_reg}]
            cbz {shadow_reg:32}, {check_ok_label}
        """
        if access_size < 8:
            asm += f"""
                cmp {shadow_reg:32}, #8
                b.hs .L__asan_shadow_check_fail{SYMBOL_SUFFIX}
                and {scratch_reg:32}, {addr_reg:32}, #7
                add {scratch_reg:32}, {scratch_reg:32}, #{access_size - 1}
                cmp {scratch_reg:32}, {shadow_reg:32}
                b.lo {check_ok_label}
            .L__asan_shadow_check_fail{SYMBOL_SUFFIX}:
            """
        return asm

    def _shadow_check_loop_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                                   shadow_offset: int, shadow_reg, scratch_reg, end_reg) -> str:
        if end_reg is None:
            raise ValueError("wide AArch64 ASan checks require an end_reg scratch register")

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
            b .L__asan_shadow_check_loop{SYMBOL_SUFFIX}
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

    @staticmethod
    def _mte_store_tag_snippet(tag_reg, addr_reg, value: int) -> str:
        return f"""
            {AArch64AsanPatchesMixin.MTE_ARCH_DIRECTIVE}
            mov {tag_reg}, #{value & 0xf}
            lsl {tag_reg}, {tag_reg}, #56
            orr {tag_reg}, {addr_reg}, {tag_reg}
            stg {tag_reg}, [{addr_reg}]
        """

    def _mte_memlog_tag_snippet(self, addr_reg, top_reg, data_reg) -> str:
        return f"""
            {self.load_address(top_reg, "memory_history_top")}
            ldr {top_reg}, [{top_reg}]
            str {addr_reg}, [{top_reg}]
            {self._mte_load_tag_snippet(data_reg, addr_reg)}
            strb {data_reg:32}, [{top_reg}, #8]
            mov {data_reg:32}, #{MEMORY_HISTORY_MTE_TAG_SIZE}
            strb {data_reg:32}, [{top_reg}, #{MEMORY_HISTORY_SIZE_OFFSET}]
            add {top_reg}, {top_reg}, #{MEMORY_HISTORY_ENTRY_SIZE}
            {self.load_address(data_reg, "memory_history_top")}
            str {top_reg}, [{data_reg}]
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
                                  tag_storage: str = ASAN_TAG_STORAGE_SHADOW) -> str:
        if tag_storage == ASAN_TAG_STORAGE_MTE:
            value = 0xf if poison else 0
            memlog = self._mte_memlog_tag_snippet(addr_reg, top_reg, value_reg) if insert_memlog else ""
            return f"""
                mov {addr_reg}, sp
                sub {addr_reg}, {addr_reg}, #8
                bic {addr_reg}, {addr_reg}, #0xf
                {memlog}
                {self._mte_store_tag_snippet(value_reg, addr_reg, value)}
            """
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError(f"Unsupported AArch64 tag storage: {tag_storage}")

        value = 0xff if poison else 0
        memlog = self.memlog_snippet(addr_reg, top_reg, value_reg, 1) if insert_memlog else ""
        return f"""
            mov {addr_reg}, sp
            sub {addr_reg}, {addr_reg}, #8
            lsr {addr_reg}, {addr_reg}, #3
            {self.mov_u64(value_reg, shadow_offset)}
            add {addr_reg}, {addr_reg}, {value_reg}
            {memlog}
            mov {value_reg}, #{value}
            strb {value_reg:32}, [{addr_reg}]
        """

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = ASAN_TAG_STORAGE_SHADOW):
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
