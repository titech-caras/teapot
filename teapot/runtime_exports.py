"""Checked-in, archive-derived runtime names and fail-closed export coverage.

This stdlib-only file and its JSON manifest are mirrored in libcheckpoint/tools.
The manifest is a conservative union across supported ISAs and runtime modes,
not a list of the imports the current emitter happens to use. Hidden and weak
global definitions own their names too. Undefined archive references do not.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess


SCHEMA = "teapot-runtime-exports-v1"
CAPTURE_FORMAT = "gnu-nm-posix-defined-global-v1"
SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]*\Z")
ANCHOR = re.compile(r"__libcheckpoint_contract_v2_[0-9a-f]{16}\Z")
FAMILIES = ["contract-anchor-v2"]
NM_LINE = re.compile(r"(.+\[[^\[\]\r\n]+\]): (\S+) ([A-Za-z?]) ([0-9a-fA-F]+)(?: ([0-9a-fA-F]+))? *\Z")
# GNU nm: global definitions, including weak objects/functions, unique globals
# and IFUNCs. Undefined U/w/v, local symbols and unknown types are never accepted.
DEFINED_GLOBAL_TYPES = frozenset("ABCDGIRSTVWiu")


class RuntimeExportError(ValueError):
    """The runtime-owned namespace could not be established safely."""


def load_manifest(path=None):
    path = Path(path) if path is not None else Path(__file__).with_suffix(".json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeExportError(f"cannot load runtime export manifest {path}: {error}") from error
    expected = {"schema", "capture_format", "architectures", "configurations", "symbols", "symbol_families"}
    if not isinstance(data, dict) or set(data) != expected or data["schema"] != SCHEMA:
        raise RuntimeExportError(f"unsupported runtime export manifest schema in {path}")
    if (data["capture_format"] != CAPTURE_FORMAT or
            data["architectures"] != ["aarch64", "riscv64", "x64"] or
            data["symbol_families"] != FAMILIES):
        raise RuntimeExportError(f"unsupported runtime export capture or symbol family in {path}")
    for key in ("symbols", "configurations"):
        values = data[key]
        if (not isinstance(values, list) or not values or
                any(not isinstance(value, str) or not value for value in values) or
                values != sorted(set(values))):
            raise RuntimeExportError(f"invalid runtime export manifest {key} in {path}")
    if any(not SYMBOL.fullmatch(name) for name in data["symbols"]):
        raise RuntimeExportError(f"invalid runtime export symbol in {path}")
    return data


def runtime_owned_names(path=None):
    """Literal names; contract-anchor families are also covered by is_generated_name."""
    return tuple(load_manifest(path)["symbols"])


def parse_nm(output):
    """Parse *only* GNU nm -g --defined-only --format=posix -A archive output.

    Reject empty, malformed, undefined, local or unsupported captures rather
    than silently dropping lines and thereby weakening the reserved-name set.
    """
    symbols = set()
    for line in output.splitlines():
        match = NM_LINE.fullmatch(line)
        if match is None or match[3] not in DEFINED_GLOBAL_TYPES or not SYMBOL.fullmatch(match[2]):
            raise RuntimeExportError(f"unsupported defined-global nm record: {line!r}")
        symbols.add(match[2])
    if not symbols:
        raise RuntimeExportError("empty defined-global archive capture")
    return frozenset(symbols)


def archive_exports(archive, nm):
    archive = Path(archive)
    try:
        with archive.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise RuntimeExportError(f"unsupported archive format (thin archives excluded): {archive}")
        version = subprocess.run([str(nm), "--version"], check=True, capture_output=True, text=True)
        if not version.stdout.startswith("GNU nm ") or version.stderr:
            raise RuntimeExportError("unsupported export capture tool: GNU nm required")
        result = subprocess.run([str(nm), "-g", "--defined-only", "--format=posix", "-A", str(archive)],
                                check=True, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeExportError(f"cannot capture runtime exports: {error}") from error
    if result.stderr:
        raise RuntimeExportError(f"nm emitted diagnostics: {result.stderr.strip()}")
    return parse_nm(result.stdout)


def check_exports(symbols, manifest):
    # The fingerprint varies with user-selected ABI/layout configuration. The
    # only permitted family is this exact known anchor shape; Teapot reserves
    # the namespace independently with its existing generated-name rule.
    missing = sorted(name for name in symbols if name not in manifest["symbols"] and not ANCHOR.fullmatch(name))
    if missing:
        raise RuntimeExportError("runtime exports missing from reserved manifest: " + ", ".join(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--nm", required=True)
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        symbols = archive_exports(args.archive, args.nm)
        check_exports(symbols, manifest)
    except RuntimeExportError as error:
        parser.exit(1, f"runtime export coverage: FAIL: {error}\n")
    print(f"runtime export coverage: PASS: {args.archive.name}: {len(symbols)} defined global names")


if __name__ == "__main__":
    main()
