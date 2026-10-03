from dataclasses import dataclass
from typing import Tuple


AppRange = Tuple[int, int]


@dataclass(frozen=True)
class DiftLayout:
    """A DIFT address-space layout: the runtime's, from its contract (teapot/runtime_contract.py)."""
    name: str
    arch: str
    xor_mask: int
    asan_shadow_offset: int
    app_ranges: Tuple[AppRange, ...]

    def __post_init__(self):
        if self.xor_mask <= 0:
            raise ValueError(f"DIFT layout {self.name} has an invalid XOR mask")
        previous_end = 0
        for start, end in sorted(self.app_ranges):
            if start < 0 or start >= end:
                raise ValueError(f"Invalid app range in DIFT layout {self.name}")
            if start < previous_end:
                raise ValueError(f"DIFT layout {self.name} app ranges overlap")
            previous_end = end

        granularity = self.xor_mask & -self.xor_mask
        for start, end in self.app_ranges:
            while start < end:
                chunk_end = min(end, (start // granularity + 1) * granularity)
                shadow_start = start ^ self.xor_mask
                shadow_end = ((chunk_end - 1) ^ self.xor_mask) + 1
                for app_start, app_end in self.app_ranges:
                    if shadow_start < app_end and app_start < shadow_end:
                        raise ValueError(f"DIFT layout {self.name} tag and app ranges overlap")
                    asan_start = (app_start >> 3) + self.asan_shadow_offset
                    asan_end = ((app_end - 1) >> 3) + self.asan_shadow_offset + 1
                    if shadow_start < asan_end and asan_start < shadow_end:
                        raise ValueError(f"DIFT layout {self.name} tag and ASan ranges overlap")
                start = chunk_end
