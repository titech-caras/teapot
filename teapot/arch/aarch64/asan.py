from teapot.configs.slots import AARCH64_SHADOW_STACK_ASAN_OFFSET


class AArch64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg, scratch_reg) -> str:
        asm = f"""
            lsr {scratch_reg}, {addr_reg}, #3
            {self.mov_u64(shadow_reg, shadow_offset)}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            ldrb {shadow_reg:32}, [{scratch_reg}]
            cbz {shadow_reg:32}, {check_ok_label}
        """
        if access_size < 8:
            asm += f"""
                and {scratch_reg:32}, {addr_reg:32}, #7
                add {scratch_reg:32}, {scratch_reg:32}, #{access_size - 1}
                cmp {scratch_reg:32}, {shadow_reg:32}
                b.lt {check_ok_label}
            """
        return asm

    def asan_stack_poison_snippet(self, addr_reg, value_reg, top_reg, *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool) -> str:
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

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int):
        @self.constraints()
        def patch(ctx):
            fixed_regs = self.fixed_spill_registers(abi, 3 if insert_memlog else 2)
            addr_reg, value_reg = fixed_regs[:2]
            top_reg = fixed_regs[2] if insert_memlog else None
            return f"""
                {self.save_regs_to_shadow_stack(
                    fixed_regs, save_flags=False,
                    frame_offset=AARCH64_SHADOW_STACK_ASAN_OFFSET,
                    preserve_sp=True)}
                {self.asan_stack_poison_snippet(
                    addr_reg, value_reg, top_reg, poison=poison,
                    shadow_offset=shadow_offset, insert_memlog=insert_memlog)}
                {self.restore_regs_from_shadow_stack(
                    fixed_regs, save_flags=False,
                    frame_offset=AARCH64_SHADOW_STACK_ASAN_OFFSET,
                    preserve_sp=True)}
            """

        return patch
