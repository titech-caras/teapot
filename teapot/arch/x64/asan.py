from typing import Optional

from gtirb_rewriting.assembly import Register


class X64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg: Register, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg: Register,
                           scratch_reg: Optional[Register] = None) -> str:
        shadow_subreg = shadow_reg.sizes["8l" if access_size <= 8 else str(access_size)]

        detailed_check_snippet = ""
        if access_size < 8:
            assert scratch_reg is not None
            detailed_check_snippet += f"""
                mov {scratch_reg:8l}, {addr_reg:8l}
                and {scratch_reg:8l}, 7
            """

            if access_size > 1:
                detailed_check_snippet += f"add {scratch_reg:8l}, {access_size - 1}\n"

            detailed_check_snippet += f"""
                cmp {scratch_reg:8l}, {shadow_subreg}
                jl {check_ok_label}
            """

        return f"""
            mov {shadow_reg}, {addr_reg}
            shr {shadow_reg}, 3
            mov {shadow_subreg}, [{shadow_reg}+{shadow_offset}]
            test {shadow_subreg}, {shadow_subreg}
            je {check_ok_label}
            {detailed_check_snippet}
        """

    def asan_stack_poison_snippet(self, addr_reg: Register, value_reg: Optional[Register],
                                  top_reg: Optional[Register], *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool) -> str:
        asan_val = "-1" if poison else "0"
        memlog = self.memlog_snippet(
            addr_reg, top_reg, value_reg, 1, no_clobber_addr=True) if insert_memlog else ""
        return f"""
            mov {addr_reg}, rsp
            shr {addr_reg}, 3
            lea {addr_reg}, [{addr_reg}+{shadow_offset}]
            {memlog}
            mov byte ptr [{addr_reg}], {asan_val}
        """

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int):
        scratch_registers = 3 if insert_memlog else 1

        @self.constraints(scratch_registers=scratch_registers, clobbers_flags=True)
        def patch(ctx):
            if insert_memlog:
                top_reg, addr_reg, value_reg = ctx.scratch_registers
            else:
                addr_reg = ctx.scratch_registers[0]
                top_reg = None
                value_reg = None

            return self.asan_stack_poison_snippet(
                addr_reg, value_reg, top_reg, poison=poison,
                shadow_offset=shadow_offset, insert_memlog=insert_memlog)

        return patch
