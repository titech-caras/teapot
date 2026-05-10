from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET


class AArch64MemlogPatchesMixin:
    def memlog_snippet(self, addr_reg, top_reg, data_reg, access_size: int, *,
                       source_label=None, no_clobber_addr: bool = False) -> str:
        asm = f"""
            {self.load_address(top_reg, "memory_history_top")}
            ldr {top_reg}, [{top_reg}]
        """
        for idx in range(0, access_size, 8):
            chunk_size = min(8, access_size - idx)
            if idx:
                assert not no_clobber_addr
                asm += f"add {addr_reg}, {addr_reg}, #8\n"
            asm += f"""
                str {addr_reg}, [{top_reg}]
            """
            for byte_idx in range(chunk_size):
                asm += f"""
                    ldrb {data_reg:32}, [{addr_reg}, #{byte_idx}]
                    strb {data_reg:32}, [{top_reg}, #{8 + byte_idx}]
                """
            asm += f"""
                mov {data_reg:32}, #{chunk_size}
                strb {data_reg:32}, [{top_reg}, #{MEMORY_HISTORY_SIZE_OFFSET}]
            """
            if source_label is not None:
                asm += f"""
                    adr {data_reg}, {source_label}
                    str {data_reg:32}, [{top_reg}, #{MEMORY_HISTORY_SIZE_OFFSET + 1}]
                """
            asm += f"""
                add {top_reg}, {top_reg}, #{MEMORY_HISTORY_ENTRY_SIZE}
            """
        asm += f"""
            {self.load_address(data_reg, "memory_history_top")}
            str {top_reg}, [{data_reg}]
        """
        return asm
