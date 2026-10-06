#!/usr/bin/env python3
"""Validate training-only fault metadata in a final whole-program or component ELF."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from elftools.elf.elffile import ELFFile
from experiments.reusable_libraries.validate_link import contract_records
from teapot.configs.runtime import RUNTIME_CONTRACT_VERSION
from teapot.fault_sites import require, validate_module_tables
from teapot.runtime_contract import CAPABILITIES


def validate(elf):
    runtime = contract_records(elf, "libcheckpoint_contract", 1)
    require(len(runtime) == 1, "expected one runtime record")
    runtime = runtime[0]
    require(runtime["version"] == RUNTIME_CONTRACT_VERSION and not runtime["fault_sites"],
            "unsupported runtime record")
    modules = contract_records(elf, "teapot_contract", 2)
    require(bool(modules), "no module records")
    for module in modules:
        require(module["version"] == runtime["version"] and module["fingerprint"] == runtime["fingerprint"]
                and module["contract"].get("abi") == runtime["contract"].get("abi"), "contract ABI mismatch")
        require(module["anchor"] == runtime["address"], "wrong runtime anchor")
        require(not module["capabilities"] >> len(CAPABILITIES) and
                not (module["capabilities"] & ~runtime["capabilities"]), "missing runtime capability")
    tables = validate_module_tables(elf, modules)
    return {"contract_version": runtime["version"], "tables": len(tables),
            "sites": sum(t["count"] for t in tables), "training_only": all(t["version"] == 2 for t in tables)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    with args.binary.open("rb") as stream:
        print(json.dumps(validate(ELFFile(stream)), sort_keys=True))


if __name__ == "__main__": main()
