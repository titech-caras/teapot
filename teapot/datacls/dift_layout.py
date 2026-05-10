import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple


AppRange = Tuple[int, int]


@dataclass(frozen=True)
class DiftLayout:
    name: str
    arch: str
    xor_mask: int
    asan_shadow_offset: int
    app_ranges: Tuple[AppRange, ...]

    def xor_bits(self) -> Tuple[int, ...]:
        return tuple(bit for bit in range(64) if self.xor_mask & (1 << bit))


_LAYOUT_KEYS = {"ARCH", "XOR_MASK", "ASAN_SHADOW_OFFSET", "APP_RANGES", "DEFAULT_FOR"}


def _layout_data_path() -> Path:
    override = os.environ.get("TEAPOT_DIFT_LAYOUT_FILE")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "libcheckpoint" / "cmake" / "DiftLayoutData.cmake"


def _int_literal(value: str) -> int:
    value = value.strip()
    for suffix in ("ULL", "LLU", "UL", "LU", "LL", "U", "L"):
        if value.upper().endswith(suffix):
            value = value[:-len(suffix)]
            break
    return int(value, 0)


def _parse_layout(tokens) -> Tuple[DiftLayout, Optional[str]]:
    if not tokens:
        raise ValueError("Empty DIFT layout declaration")

    name = tokens[0]
    values = {}
    ranges = []
    idx = 1
    while idx < len(tokens):
        key = tokens[idx]
        idx += 1
        if key in ("ARCH", "XOR_MASK", "ASAN_SHADOW_OFFSET", "DEFAULT_FOR"):
            if idx >= len(tokens):
                raise ValueError(f"DIFT layout {name} missing value for {key}")
            values[key] = tokens[idx]
            idx += 1
        elif key == "APP_RANGES":
            while idx < len(tokens) and tokens[idx] not in _LAYOUT_KEYS:
                range_parts = tokens[idx].split(":")
                if len(range_parts) != 2:
                    raise ValueError(f"Invalid DIFT app range {tokens[idx]} in layout {name}")
                ranges.append((_int_literal(range_parts[0]), _int_literal(range_parts[1])))
                idx += 1
        else:
            raise ValueError(f"Unknown DIFT layout key {key} in layout {name}")

    for required in ("ARCH", "XOR_MASK", "ASAN_SHADOW_OFFSET"):
        if required not in values:
            raise ValueError(f"DIFT layout {name} missing {required}")
    if not ranges:
        raise ValueError(f"DIFT layout {name} has no APP_RANGES")

    return (
        DiftLayout(
            name=name,
            arch=values["ARCH"],
            xor_mask=_int_literal(values["XOR_MASK"]),
            asan_shadow_offset=_int_literal(values["ASAN_SHADOW_OFFSET"]),
            app_ranges=tuple(ranges),
        ),
        values.get("DEFAULT_FOR"),
    )


def _load_layouts() -> Tuple[Dict[str, DiftLayout], Dict[str, str]]:
    path = _layout_data_path()
    if not path.exists():
        raise FileNotFoundError(f"Teapot DIFT layout data not found: {path}")

    layouts: Dict[str, DiftLayout] = {}
    defaults: Dict[str, str] = {}
    text = path.read_text()
    for match in re.finditer(r"teapot_dift_layout\((.*?)\)", text, re.DOTALL):
        tokens = shlex.split(match.group(1), comments=True, posix=True)
        layout, default_for = _parse_layout(tokens)
        layouts[layout.name] = layout
        if default_for:
            defaults[default_for] = layout.name

    if not layouts:
        raise ValueError(f"No Teapot DIFT layouts found in {path}")
    return layouts, defaults


LAYOUTS, DEFAULT_LAYOUTS = _load_layouts()


def get_dift_layout(arch_name: str, layout_name: Optional[str] = None) -> DiftLayout:
    if layout_name is None:
        layout_name = DEFAULT_LAYOUTS[arch_name]

    layout = LAYOUTS[layout_name]
    if layout.arch != arch_name:
        raise ValueError(f"DIFT layout {layout.name} is for {layout.arch}, not {arch_name}")
    return layout


def layout_names_for_arch(arch_name: str) -> Iterable[str]:
    return (name for name, layout in LAYOUTS.items() if layout.arch == arch_name)
