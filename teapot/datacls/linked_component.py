"""Explicit link contract for experimental, separately rewritten components.

This is not a CLI switch that permits arbitrary external calls. The binary-only
link driver must validate the complete selected dependency set, instrument every
named provider, and define the bounds/coverage offsets in the final link.
"""
from dataclasses import dataclass
import re
from typing import FrozenSet

import gtirb


@dataclass(frozen=True)
class LinkedComponent:
    component_id: str
    linked_function_symbols: FrozenSet[str]
    exported_function_symbols: FrozenSet[str]

    def __post_init__(self):
        if not re.fullmatch(r"[0-9a-f]{16,64}", self.component_id):
            raise ValueError("component identity must be a hexadecimal content key")
        if not self.exported_function_symbols <= self.linked_function_symbols:
            raise ValueError("component exports must belong to the validated link set")

    @property
    def guard_base_name(self):
        return "__teapot_component_guard_base_" + self.component_id

    @staticmethod
    def external_symbol(module, name):
        if next(module.symbols_named(name), None) is not None:
            raise ValueError("input collides with a reserved component symbol: " + name)
        symbol = gtirb.Symbol(name=name, payload=gtirb.ProxyBlock(module=module), module=module)
        module.aux_data["elfSymbolInfo"].data[symbol] = (0, "NOTYPE", "GLOBAL", "DEFAULT", 0)
        return symbol

    def bounds(self, module):
        return tuple(self.external_symbol(module, "__teapot_linked_" + name)
                     for name in ("normal_start", "normal_end", "transient_start", "transient_end"))

    @staticmethod
    def make_liveness_caller_independent(module):
        """Over-approximate validated metadata; never reuse caller-specific deadness.

        A separately lifted DSO does not contain every future caller. Until the
        cache carries a proved inter-component liveness summary, all tracked
        registers/flags must be preserved everywhere. Missing instruction masks
        already mean all-live in LiveRegisterManager. The untouched frontend
        tables remain in the driver's saved original lift.
        """
        names = module.aux_data["liveRegisterNames"].data
        masks = module.aux_data["liveRegisterSets"].data
        all_live = (1 << len(names)) - 1
        for offset in masks:
            masks[offset] = all_live
        return len(masks)
