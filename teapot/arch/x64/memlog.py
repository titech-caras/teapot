from gtirb_rewriting import Register

from teapot.configs.runtime import MEMORY_HISTORY_ENTRY_SIZE, MEMORY_HISTORY_SIZE_OFFSET


class X64MemlogPatchesMixin:
    @staticmethod
    def memlog_snippet(addr_reg: Register, top_reg: Register, data_reg: Register, access_size: int, *,
                       source_label=None, no_clobber_addr: bool = False):
        asm = f"mov {top_reg}, [memory_history_top]\n"

        if no_clobber_addr:
            assert access_size <= 8

        for offset in range(0, access_size, 8):
            chunk_size = min(8, access_size - offset)
            if offset:
                assert not no_clobber_addr
                asm += f"lea {addr_reg}, [{addr_reg} + 8]\n"
            asm += f"""
                mov [{top_reg}], {addr_reg}
            """
            for byte_idx in range(chunk_size):
                asm += f"""
                    mov {data_reg:8l}, byte ptr [{addr_reg} + {byte_idx}]
                    mov byte ptr [{top_reg} + {8 + byte_idx}], {data_reg:8l}
                """
            asm += f"""
                mov byte ptr [{top_reg} + {MEMORY_HISTORY_SIZE_OFFSET}], {chunk_size}
                lea {top_reg}, [{top_reg} + {MEMORY_HISTORY_ENTRY_SIZE}]
            """

        asm += f"""
            mov memory_history_top, {top_reg}
        """

        return asm
