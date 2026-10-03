"""Check a lift's live-register masks before rewriting it.

Teapot runs no liveness analysis of its own: it reads DDisasm's masks and
refuses a lift without them or whose masks predate the flag rule. A missing
mask on an instruction keeps every register live, which is safe but costs
spills. This tool builds the live-register manager as TeapotPipeline does and
reports, for each lift: whether Teapot would accept its tables, the flag rule,
how many original instructions lack a mask (and why), invalid entries, entries
at offsets that are no decoded instruction boundary, and on x64 masks without
the vector high word.

Usage: python3 tools/mask_audit.py [--json OUT.json] LIFT.gtirb...
Exits 1 when a lift would be refused or has any of these gaps.
"""
import argparse
import collections
import json
import sys

import gtirb
from gtirb_functions import Function
from gtirb_live_register_analysis.utils import CachedGtirbInstructionDecoder
from gtirb_rewriting.abi import _ABIS

from teapot.arch import get_arch
from teapot.liveness import (
    LIVE_REGISTER_FLAG_RULE_AUXDATA, LIVE_REGISTER_NAMES_AUXDATA, LIVE_REGISTER_SETS_AUXDATA,
    LivenessMetadataError, LiveRegisterManager,
)


def audit(path):
    ir = gtirb.IR.load_protobuf(path)
    module = ir.modules[0]
    abi = get_arch(module).register_abi(_ABIS)
    decoder = CachedGtirbInstructionDecoder(module.isa)
    decoder.cache.clear()
    aux = module.aux_data
    rule = aux.get(LIVE_REGISTER_FLAG_RULE_AUXDATA)
    row = {"path": str(path), "isa": module.isa.name,
           "flag_rule": rule.data if rule is not None else None,
           "has_tables": LIVE_REGISTER_NAMES_AUXDATA in aux and LIVE_REGISTER_SETS_AUXDATA in aux}
    try:
        manager = LiveRegisterManager(module, abi, decoder)
        row.update(accepted=True, reason=None)
        masks, high, discarded = manager.masks, manager.high_masks, manager.discarded
    except LivenessMetadataError as error:
        # Still report the coverage of whatever table there is.
        row.update(accepted=False, reason=str(error))
        sets = aux.get(LIVE_REGISTER_SETS_AUXDATA)
        masks = dict(sets.data) if sets is not None and isinstance(sets.data, dict) else {}
        high, discarded = {}, None
    names = list(aux[LIVE_REGISTER_NAMES_AUXDATA].data) if LIVE_REGISTER_NAMES_AUXDATA in aux else []
    instructions = 0
    missing = collections.Counter()
    boundaries, seen = set(), set()
    without_high = 0
    for function in Function.build_functions(module):
        for block in function.get_all_blocks():
            if block in seen:
                continue
            seen.add(block)
            decoded = list(decoder.get_instructions(block))
            offsets = [gtirb.Offset(block, instruction.address - block.address) for instruction in decoded]
            boundaries.update(offsets)
            present = [offset in masks for offset in offsets]
            for offset, has in zip(offsets, present):
                instructions += 1
                if block.address is None:
                    missing["block without an address"] += 1
                elif not has:
                    missing["whole block" if not any(present) else "part of a block"] += 1
                elif len(names) > 64 and offset not in high:
                    without_high += 1
    row.update({"instructions": instructions, "missing": dict(missing),
                "invalid_entries": discarded,
                "off_boundary_entries": sum(1 for offset in masks if offset not in boundaries),
                "x64_masks_without_high_word": without_high if len(names) > 64 else None})
    row["clean"] = (row["accepted"] and not missing and not row["invalid_entries"] and
                    not row["off_boundary_entries"] and not without_high)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json")
    parser.add_argument("lifts", nargs="+")
    args = parser.parse_args()
    rows = [audit(path) for path in args.lifts]
    for row in rows:
        print(f"{row['path']}: {'clean' if row['clean'] else 'GAPS' if row['accepted'] else 'REFUSED'}; "
              f"{row['instructions']} instructions, missing {sum(row['missing'].values())} {row['missing'] or ''}, "
              f"invalid {row['invalid_entries']}, off-boundary {row['off_boundary_entries']}, "
              f"flag rule {row['flag_rule']!r}")
        if row["reason"]:
            print(f"  {row['reason']}")
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(rows, handle, indent=1)
    return 0 if all(row["clean"] for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
