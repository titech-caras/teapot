from gtirb_rewriting import Register

from teapot.configs.runtime import (
    MEMORY_HISTORY_DATA_OFFSET,
    MEMORY_HISTORY_DATA_WIDTH,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
)


class X64MemlogPatchesMixin:
    @staticmethod
    def memlog_snippet(addr_reg: Register, top_reg: Register, data_reg: Register, access_size: int, *,
                       no_clobber_addr: bool = False):
        asm = f"mov {top_reg}, [memory_history_top]\n"

        if no_clobber_addr:
            assert access_size <= MEMORY_HISTORY_DATA_WIDTH

        # Each entry holds the address at its start and at most
        # MEMORY_HISTORY_DATA_WIDTH data bytes.
        for offset in range(0, access_size, MEMORY_HISTORY_DATA_WIDTH):
            chunk_size = min(MEMORY_HISTORY_DATA_WIDTH, access_size - offset)
            if offset:
                assert not no_clobber_addr
                asm += f"lea {addr_reg}, [{addr_reg} + {MEMORY_HISTORY_DATA_WIDTH}]\n"
            asm += f"""
                mov [{top_reg}], {addr_reg}
            """
            byte_idx = 0
            for width, operand_size, register_size in (
                    (8, "qword", "64"), (4, "dword", "32"),
                    (2, "word", "16"), (1, "byte", "8l")):
                if not chunk_size & width:
                    continue
                asm += f"""
                    mov {data_reg:{register_size}}, {operand_size} ptr [{addr_reg} + {byte_idx}]
                    mov {operand_size} ptr [{top_reg} + {MEMORY_HISTORY_DATA_OFFSET + byte_idx}], {data_reg:{register_size}}
                """
                byte_idx += width
            asm += f"""
                mov byte ptr [{top_reg} + {MEMORY_HISTORY_SIZE_OFFSET}], {chunk_size}
                lea {top_reg}, [{top_reg} + {MEMORY_HISTORY_ENTRY_SIZE}]
            """

        asm += f"""
            mov memory_history_top, {top_reg}
        """

        return asm

    @staticmethod
    def address_reusing_memlog_snippet(addr_reg: Register, top_reg: Register, access_size: int):
        """memlog_snippet's entry for one 1-, 2-, 4- or 8-byte store, in two registers.

        The entry, its contents and their order are memlog_snippet's: the
        address at the entry's start, the old bytes (one load of the access's
        width), the size, then the new top. The old bytes are loaded into the
        address register only after the address is stored, so a faulting load
        leaves the entry unpublished, as before.
        """
        widths = {8: ("qword", "64"), 4: ("dword", "32"), 2: ("word", "16"), 1: ("byte", "8l")}
        if access_size not in widths:
            raise ValueError(f"a {access_size}-byte store is not one load of one entry")
        operand_size, register_size = widths[access_size]
        return f"""
            mov {top_reg}, [memory_history_top]
            mov [{top_reg}], {addr_reg}
            mov {addr_reg:{register_size}}, {operand_size} ptr [{addr_reg}]
            mov {operand_size} ptr [{top_reg} + {MEMORY_HISTORY_DATA_OFFSET}], {addr_reg:{register_size}}
            mov byte ptr [{top_reg} + {MEMORY_HISTORY_SIZE_OFFSET}], {access_size}
            lea {top_reg}, [{top_reg} + {MEMORY_HISTORY_ENTRY_SIZE}]
            mov memory_history_top, {top_reg}
        """
