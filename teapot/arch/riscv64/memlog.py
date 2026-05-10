from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET


class RISCV64MemlogPatchesMixin:
    def memlog_snippet(self, addr_reg, top_reg, data_reg, access_size: int, *,
                       source_label=None, no_clobber_addr: bool = False) -> str:
        asm = f"""
            {self.load_address(top_reg, "memory_history_top")}
            ld {top_reg}, 0({top_reg})
        """
        for idx in range(0, access_size, 8):
            chunk_size = min(8, access_size - idx)
            if idx:
                assert not no_clobber_addr
                asm += f"addi {addr_reg}, {addr_reg}, 8\n"
            asm += f"""
                sd {addr_reg}, 0({top_reg})
            """
            for byte_idx in range(chunk_size):
                asm += f"""
                    lbu {data_reg}, {byte_idx}({addr_reg})
                    sb {data_reg}, {8 + byte_idx}({top_reg})
                """
            asm += f"""
                li {data_reg}, {chunk_size}
                sb {data_reg}, {MEMORY_HISTORY_SIZE_OFFSET}({top_reg})
                addi {top_reg}, {top_reg}, {MEMORY_HISTORY_ENTRY_SIZE}
            """
        asm += f"""
            {self.load_address(data_reg, "memory_history_top")}
            sd {top_reg}, 0({data_reg})
        """
        return asm
