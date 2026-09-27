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
        """Legacy all-live experiment, not the independent-library ABI policy.

        Retained for reproducing historical experiments. The current component
        pipeline preserves standalone DDisasm masks, including ABI boundary
        information; it does not call this over-approximation. Missing masks
        already mean all-live in LiveRegisterManager.
        """
        names = module.aux_data["liveRegisterNames"].data
        masks = module.aux_data["liveRegisterSets"].data
        all_live = (1 << min(64, len(names))) - 1
        for offset in masks:
            masks[offset] = all_live
        if len(names) > 64:
            module.aux_data['liveRegisterSetsHigh'] = gtirb.AuxData(
                {offset: (1 << (len(names) - 64)) - 1 for offset in masks},
                'mapping<Offset,uint64_t>')
        return len(masks)
