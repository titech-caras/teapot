"""Archived pre-enforcement runtime contracts, retained for eager fallback.

test_runtime_contract.py validates the current runtime's exact ABI extension
of these legacy fixtures and separately tests enforcing/capability=0 modes.
"""
from pathlib import Path

from teapot.runtime_contract import load_runtime_contract

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "runtime_contracts"
# The DIFT layout each ISA's tests use: the runtime's default for that ISA.
_DEFAULT_RUNTIME = {"x64": "x64", "aarch64": "aarch64", "riscv64": "riscv64"}


def fixture_contract_path(name: str, *, nested: bool = False) -> Path:
    """A fixture runtime's contract file: x64, aarch64, aarch64-bti, aarch64-mte, riscv64 (with
    the FP state, which RISC-V rewrites with checkpoints need) or riscv64-nofp (without it); and
    x64-coverage, aarch64-coverage and riscv64-coverage, the default ones built for a fuzzer
    (-DTEAPOT_ENABLE_COVERAGE=ON)."""
    return FIXTURES / f"{name}{'-nested' if nested else ''}.contract.json"


def runtime_contract(name: str, *, nested: bool = False):
    return load_runtime_contract(fixture_contract_path(name, nested=nested))


def fixture_contract(arch_name: str, *, nested: bool = False, target_identification="software",
                     tag_storage="shadow", coverage: bool = False):
    """The fixture runtime a rewrite of ``arch_name`` with these options links with."""
    if coverage:
        if target_identification != "software" or tag_storage != "shadow":
            raise ValueError("the coverage fixtures are software-mode shadow-tag runtimes")
        return runtime_contract(_DEFAULT_RUNTIME[arch_name] + "-coverage", nested=nested)
    if arch_name == "aarch64" and target_identification == "aarch64-bti-pac":
        return runtime_contract("aarch64-bti", nested=nested)
    if arch_name == "aarch64" and tag_storage == "mte":
        return runtime_contract("aarch64-mte", nested=nested)
    return runtime_contract(_DEFAULT_RUNTIME[arch_name], nested=nested)


def fixture_layout(arch_name: str):
    """The DIFT layout of the ISA's default fixture runtime."""
    return runtime_contract(_DEFAULT_RUNTIME[arch_name]).dift_layout()
