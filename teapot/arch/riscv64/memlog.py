from teapot.configs.runtime import (
    MEMORY_HISTORY_DATA_OFFSET,
    MEMORY_HISTORY_DATA_WIDTH,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
)
from teapot.fault_risc import MEMLOG, origin_marker


class RISCV64MemlogPatchesMixin:
    def memlog_snippet(self, addr_reg, top_reg, data_reg, access_size: int, *,
                       no_clobber_addr: bool = False) -> str:
        asm = f"""
            {self.load_address(top_reg, "memory_history_top")}
            ld {top_reg}, 0({top_reg})
        """
        # Each entry holds the address at its start and at most
        # MEMORY_HISTORY_DATA_WIDTH data bytes.
        for idx in range(0, access_size, MEMORY_HISTORY_DATA_WIDTH):
            chunk_size = min(MEMORY_HISTORY_DATA_WIDTH, access_size - idx)
            if idx:
                assert not no_clobber_addr
                asm += f"addi {addr_reg}, {addr_reg}, {MEMORY_HISTORY_DATA_WIDTH}\n"
            asm += f"""
                sd {addr_reg}, 0({top_reg})
            """
            # RV64GC does not guarantee misaligned wide loads. Use the fast
            # path only when every transfer is naturally aligned.
            alignment = 1 << (chunk_size.bit_length() - 1)
            if alignment > 1:
                asm += f"andi {data_reg}, {addr_reg}, {alignment - 1}\nbnez {data_reg}, 91f\n"
                byte_idx = 0
                for width, load, store in ((8, "ld", "sd"), (4, "lw", "sw"),
                                           (2, "lh", "sh"), (1, "lb", "sb")):
                    if not chunk_size & width:
                        continue
                    asm += origin_marker(self, MEMLOG)
                    asm += f"{load} {data_reg}, {byte_idx}({addr_reg})\n"
                    asm += f"{store} {data_reg}, {MEMORY_HISTORY_DATA_OFFSET + byte_idx}({top_reg})\n"
                    byte_idx += width
                asm += "j 92f\n91:\n"
            for byte_idx in range(chunk_size):
                asm += origin_marker(self, MEMLOG)
                asm += f"""
                    lbu {data_reg}, {byte_idx}({addr_reg})
                    sb {data_reg}, {MEMORY_HISTORY_DATA_OFFSET + byte_idx}({top_reg})
                """
            if alignment > 1:
                asm += "92:\n"
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
