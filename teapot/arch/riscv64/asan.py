class RISCV64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg, scratch_reg) -> str:
        asm = f"""
            srli {scratch_reg}, {addr_reg}, 3
            li {shadow_reg}, {shadow_offset}
            add {scratch_reg}, {scratch_reg}, {shadow_reg}
            lbu {shadow_reg}, 0({scratch_reg})
            beqz {shadow_reg}, {check_ok_label}
        """
        if access_size < 8:
            asm += f"""
                andi {scratch_reg}, {addr_reg}, 7
                addi {scratch_reg}, {scratch_reg}, {access_size - 1}
                blt {scratch_reg}, {shadow_reg}, {check_ok_label}
            """
        return asm

    def asan_stack_poison_snippet(self, addr_reg, value_reg, top_reg, *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool) -> str:
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

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int):
        scratch_count = 3 if insert_memlog else 2

        @self.constraints(scratch_registers=scratch_count)
        def patch(ctx):
            addr_reg, value_reg = ctx.scratch_registers[:2]
            top_reg = ctx.scratch_registers[2] if insert_memlog else None
            return f"""
                {self.asan_stack_poison_snippet(
                    addr_reg, value_reg, top_reg, poison=poison,
                    shadow_offset=shadow_offset, insert_memlog=insert_memlog)}
            """

        return patch
