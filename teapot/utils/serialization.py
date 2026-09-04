"""Helpers for reducing post-rewrite GTIRB serialization overhead."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from typing import Iterable

import gtirb


@dataclass(frozen=True)
class CompactStats:
    cfg_edges_removed: int
    symbolic_sizes_before: int
    symbolic_sizes_after: int
    code_only_sizes_removed: int


def _merged_spans(
    blocks: Iterable[gtirb.ByteBlock],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    spans = sorted(
        (block.offset, block.offset + block.size)
        for block in blocks
        if block.size > 0
    )
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return tuple(span[0] for span in merged), tuple(span[1] for span in merged)


def _contains(
    starts: tuple[int, ...], ends: tuple[int, ...], offset: int
) -> bool:
    index = bisect_right(starts, offset) - 1
    return index >= 0 and offset < ends[index]


def compact_for_pprinter(ir: gtirb.IR) -> CompactStats:
    """Drop analysis-only metadata after rewriting is complete.

    The pretty-printer does not consume CFG edges.  It needs explicit symbolic
    expression widths for data, but code expressions are decoded from their
    instructions.  Entries outside every block are retained conservatively,
    and data wins when code and data overlap.
    """

    cfg_edges_removed = len(ir.cfg)
    ir.cfg.clear()

    symbolic_sizes_before = 0
    symbolic_sizes_after = 0
    code_only_sizes_removed = 0

    for module in ir.modules:
        spans: dict[
            int,
            tuple[
                tuple[int, ...],
                tuple[int, ...],
                tuple[int, ...],
                tuple[int, ...],
            ],
        ] = {}
        for section in module.sections:
            for interval in section.byte_intervals:
                data_starts, data_ends = _merged_spans(
                    block
                    for block in interval.blocks
                    if isinstance(block, gtirb.DataBlock)
                )
                code_starts, code_ends = _merged_spans(
                    block
                    for block in interval.blocks
                    if isinstance(block, gtirb.CodeBlock)
                )
                spans[id(interval)] = (
                    data_starts,
                    data_ends,
                    code_starts,
                    code_ends,
                )

        aux = module.aux_data.get("symbolicExpressionSizes")
        if aux is None:
            continue
        sizes = aux.data
        symbolic_sizes_before += len(sizes)
        retained = {}
        for key, size in sizes.items():
            interval_spans = spans.get(id(key.element_id))
            if interval_spans is None:
                retained[key] = size
                continue
            data_starts, data_ends, code_starts, code_ends = interval_spans
            displacement = key.displacement
            in_data = _contains(data_starts, data_ends, displacement)
            in_code = _contains(code_starts, code_ends, displacement)
            if in_code and not in_data:
                code_only_sizes_removed += 1
            else:
                retained[key] = size
        # Rewriting wraps offset tables in OffsetMapping. MutableMapping.clear
        # removes one Offset at a time, which is prohibitively slow for large
        # transformed modules. The rewrite pipeline is finished at this point,
        # so replace the completed aux-data value atomically instead.
        aux.data = retained
        symbolic_sizes_after += len(retained)

    return CompactStats(
        cfg_edges_removed=cfg_edges_removed,
        symbolic_sizes_before=symbolic_sizes_before,
        symbolic_sizes_after=symbolic_sizes_after,
        code_only_sizes_removed=code_only_sizes_removed,
    )
