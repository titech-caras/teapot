import gtirb
from typing import Tuple

from teapot.config import SYMBOL_SUFFIX


def create_guards(guard_section: gtirb.Section, count: int) -> Tuple[gtirb.Symbol, gtirb.Symbol]:
    guard_size = 4  # guards are uint32_t

    guard_byte_interval = next(iter(guard_section.byte_intervals))
    guard_byte_interval.contents = bytes([0x00] * guard_size * count)
    guard_byte_interval.size = guard_size * count

    guard_data_block = gtirb.DataBlock(
        size=guard_size*count, offset=0, uuid=None,
        byte_interval=guard_byte_interval
    )

    guard_start_symbol = gtirb.Symbol(
        name="__guard_start" + SYMBOL_SUFFIX,
        uuid=None,
        payload=guard_data_block,
        at_end=False,
        module=guard_section.module
    )

    guard_end_symbol = gtirb.Symbol(
        name="__guard_end" + SYMBOL_SUFFIX,
        uuid=None,
        payload=guard_data_block,
        at_end=True,
        module=guard_section.module
    )

    return guard_start_symbol, guard_end_symbol
