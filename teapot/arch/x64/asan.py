from typing import Optional

from gtirb_rewriting.assembly import Register

from teapot.configs.runtime import ASAN_TAG_STORAGE_SHADOW


class X64AsanPatchesMixin:
    def asan_check_snippet(self, addr_reg: Register, access_size: int, check_ok_label: str, *,
                           shadow_offset: int, shadow_reg: Register,
                           scratch_reg: Optional[Register] = None,
                           tag_storage: str = ASAN_TAG_STORAGE_SHADOW,
                           end_reg: Optional[Register] = None) -> str:
        if access_size <= 0:
            raise ValueError("x64 ASan check access size must be positive")
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("x64 only supports ASan shadow tag storage")
        if access_size > 1:
            return self._shadow_range_check_snippet(
                addr_reg, access_size, check_ok_label,
                shadow_offset=shadow_offset, shadow_reg=shadow_reg,
                scratch_reg=scratch_reg, end_reg=end_reg)

        assert scratch_reg is not None
        return f"""
            mov {shadow_reg}, {addr_reg}
            shr {shadow_reg}, 3
            mov {shadow_reg:8l}, [{shadow_reg}+{shadow_offset}]
            test {shadow_reg:8l}, {shadow_reg:8l}
            je {check_ok_label}
            mov {scratch_reg:8l}, {addr_reg:8l}
            and {scratch_reg:8l}, 7
            cmp {scratch_reg:8l}, {shadow_reg:8l}
            jl {check_ok_label}
        """

    @staticmethod
    def _shadow_range_check_snippet(addr_reg: Register, access_size: int, check_ok_label: str, *,
                                   shadow_offset: int, shadow_reg: Register,
                                   scratch_reg: Optional[Register],
                                   end_reg: Optional[Register]) -> str:
        if scratch_reg is None or end_reg is None:
            raise ValueError("multi-byte x64 ASan checks require scratch_reg and end_reg")

        label = check_ok_label + "_shadow"
        # At most two granules are touched by a small unaligned access.
        next_granule = (f"jmp {label}_loop" if access_size > 8
                        else f"mov {scratch_reg:8l}, byte ptr [{shadow_reg}]")

        return f"""
            mov {shadow_reg}, {addr_reg}
            shr {shadow_reg}, 3
            add {shadow_reg}, {shadow_offset}
            lea {end_reg}, [{addr_reg}+{access_size - 1}]
            shr {end_reg}, 3
            add {end_reg}, {shadow_offset}
        {label}_loop:
            mov {scratch_reg:8l}, byte ptr [{shadow_reg}]
            cmp {shadow_reg}, {end_reg}
            je {label}_last
            test {scratch_reg:8l}, {scratch_reg:8l}
            jne {label}_fail
            inc {shadow_reg}
            {next_granule}
        {label}_last:
            test {scratch_reg:8l}, {scratch_reg:8l}
            je {check_ok_label}
            cmp {scratch_reg:8l}, 8
            jae {label}_fail
            mov {end_reg}, {addr_reg}
            add {end_reg}, {access_size - 1}
            and {end_reg:8l}, 7
            cmp {end_reg:8l}, {scratch_reg:8l}
            jb {check_ok_label}
        {label}_fail:
        """

    def asan_stack_poison_snippet(self, addr_reg: Register, value_reg: Optional[Register],
                                  top_reg: Optional[Register], *, poison: bool,
                                  shadow_offset: int, insert_memlog: bool,
                                  tag_storage: str = ASAN_TAG_STORAGE_SHADOW) -> str:
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("x64 only supports ASan shadow tag storage")

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

    def asan_stack_patch(self, abi, *, poison: bool, insert_memlog: bool, shadow_offset: int,
                         tag_storage: str = ASAN_TAG_STORAGE_SHADOW):
        if tag_storage != ASAN_TAG_STORAGE_SHADOW:
            raise ValueError("x64 only supports ASan shadow tag storage")

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
                shadow_offset=shadow_offset, insert_memlog=insert_memlog,
                tag_storage=tag_storage)

        return patch
