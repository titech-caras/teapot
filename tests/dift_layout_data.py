"""The DIFT layout profiles of libcheckpoint's cmake/DiftLayoutData.cmake, for tests.

Teapot itself takes the layout of the runtime it links with from that runtime's
contract (teapot/runtime_contract.py); these tests check the profiles the
runtime can be built with.
"""
import os
import re
import shlex
from pathlib import Path
from typing import Dict, Optional, Tuple

from teapot.datacls.dift_layout import DiftLayout


_LAYOUT_KEYS = {"ARCH", "XOR_MASK", "ASAN_SHADOW_OFFSET", "APP_RANGES", "DEFAULT_FOR"}


def layout_data_path() -> Path:
    override = os.environ.get("TEAPOT_DIFT_LAYOUT_FILE")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[1] / "libcheckpoint" / "cmake" / "DiftLayoutData.cmake"


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


def load_layouts() -> Tuple[Dict[str, DiftLayout], Dict[str, str]]:
    path = layout_data_path()
    if not path.exists():
        raise FileNotFoundError(
            f"Teapot DIFT layout data not found: {path}. Set TEAPOT_DIFT_LAYOUT_FILE "
            "to DiftLayoutData.cmake installed by the matching libcheckpoint build.")

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
