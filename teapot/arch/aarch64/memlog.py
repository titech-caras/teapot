from teapot.configs.runtime import (
    MEMORY_HISTORY_DATA_OFFSET,
    MEMORY_HISTORY_DATA_WIDTH,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
)


class AArch64MemlogPatchesMixin:
    def memlog_snippet(self, addr_reg, top_reg, data_reg, access_size: int, *,
                       no_clobber_addr: bool = False) -> str:
        asm = f"""
            {self.load_address(top_reg, "memory_history_top")}
            ldr {top_reg}, [{top_reg}]
        """
        # Each entry holds the address at its start and at most
        # MEMORY_HISTORY_DATA_WIDTH data bytes.
        for idx in range(0, access_size, MEMORY_HISTORY_DATA_WIDTH):
            chunk_size = min(MEMORY_HISTORY_DATA_WIDTH, access_size - idx)
            if idx:
                assert not no_clobber_addr
                asm += f"add {addr_reg}, {addr_reg}, #{MEMORY_HISTORY_DATA_WIDTH}\n"
            asm += f"""
                str {addr_reg}, [{top_reg}]
            """
            byte_idx = 0
            for width, suffix, register_size in (
                    (8, "", "64"), (4, "", "32"), (2, "h", "32"), (1, "b", "32")):
                if not chunk_size & width:
                    continue
                asm += f"""
                    ldr{suffix} {data_reg:{register_size}}, [{addr_reg}, #{byte_idx}]
                    str{suffix} {data_reg:{register_size}}, [{top_reg}, #{MEMORY_HISTORY_DATA_OFFSET + byte_idx}]
                """
                byte_idx += width
            asm += f"""
                mov {data_reg:32}, #{chunk_size}
                strb {data_reg:32}, [{top_reg}, #{MEMORY_HISTORY_SIZE_OFFSET}]
            """
            asm += f"""
                add {top_reg}, {top_reg}, #{MEMORY_HISTORY_ENTRY_SIZE}
            """
        asm += f"""
            {self.load_address(data_reg, "memory_history_top")}
            str {top_reg}, [{data_reg}]
        """
        return asm
