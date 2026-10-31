"""How a call to an uninstrumented library function affects tags: DFSan's ABI lists.

Teapot reads its own list (dfsan/teapot_abilist.txt) and then LLVM's
(dfsan/done_abilist.txt, vendored unmodified); a function named in Teapot's list
takes only that category. As in DFSan, a call to a function that is

- custom runs the runtime's wrapper, when the runtime has one
  (DiftExtCallPass redirects it);
- functional gives its result the union of its arguments' tags;
- discard, unlisted, or custom without a wrapper gives its result no tag.

Floating-point and vector registers carry no tags: only integer and pointer
arguments and results take part, and on lp64 RISC-V every scalar, since its
floating-point values travel in integer registers.
"""
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple

DFSAN_DIRECTORY = Path(__file__).with_name("dfsan")
# DFSan's precedence when a list gives a function several categories.
CATEGORIES = ("functional", "discard", "custom")

INTEGER_ARGUMENTS = {
    "x64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "aarch64": tuple(f"x{i}" for i in range(8)),
    "riscv64": tuple(f"a{i}" for i in range(8)),
}
INTEGER_RESULTS = {"x64": ("rax", "rdx"), "aarch64": ("x0", "x1"), "riscv64": ("a0", "a1")}


class AbiList:
    """One DFSan ABI list: fun:<name or glob>=<category> lines."""

    def __init__(self, text: str):
        self.exact: Dict[str, set] = {}
        self.patterns = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line.startswith("fun:"):
                continue
            pattern, _, category = line[len("fun:"):].partition("=")
            if category not in CATEGORIES:
                continue  # uninstrumented, other sanitizer keys
            if any(c in pattern for c in "*?["):
                self.patterns.append((pattern, category))
            else:
                self.exact.setdefault(pattern, set()).add(category)

    def categories(self, name: str) -> FrozenSet[str]:
        found = set(self.exact.get(name, ()))
        found.update(category for pattern, category in self.patterns if fnmatchcase(name, pattern))
        return frozenset(found)


@lru_cache(maxsize=None)
def _lists() -> Tuple[AbiList, AbiList]:
    return tuple(AbiList((DFSAN_DIRECTORY / name).read_text(encoding="utf-8"))
                 for name in ("teapot_abilist.txt", "done_abilist.txt"))


def category(name: str) -> Optional[str]:
    """The DFSan category of the library function ``name``, or None if unlisted."""
    for abi_list in _lists():
        found = abi_list.categories(name)
        if found:
            return next(category for category in CATEGORIES if category in found)
    return None


@lru_cache(maxsize=None)
def functional_prototypes() -> Dict[str, Tuple[str, Tuple[str, ...]]]:
    """{name: (return type, parameter types)} for the functional functions."""
    prototypes = {}
    for line in (DFSAN_DIRECTORY / "functional_prototypes.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].split()
        if line:
            prototypes[line[0]] = (line[1], tuple(line[2:]))
    return prototypes


def _integer_slots(arch: str, value_type: str, soft_float: bool) -> int:
    """How many integer registers a value of value_type occupies (0: untracked)."""
    if value_type in ("int", "pointer"):
        return 1
    if arch == "riscv64" and value_type == "longdouble":
        return 2  # 128-bit long double: an integer register pair
    if arch == "riscv64" and soft_float and value_type in ("float", "double"):
        return 1
    return 0  # FP/vector registers, or x87 long doubles in memory


def call_effect(arch: str, name: str, *, soft_float: bool = False) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """(argument registers, result registers) of a call to an uninstrumented ``name``.

    After the call each result register's tag is the union of the argument
    registers' tags; with no argument registers it is untagged. A call without
    a functional prototype untags both result registers, covering two-register
    results. The runtime's wrappers are not covered here: DiftExtCallPass
    redirects those calls.
    """
    if category(name) != "functional":
        return (), INTEGER_RESULTS[arch]
    return_type, parameter_types = functional_prototypes()[name]
    arguments = []
    for parameter_type in parameter_types:
        arguments.extend(range(len(arguments), len(arguments) + _integer_slots(arch, parameter_type, soft_float)))
    available = INTEGER_ARGUMENTS[arch]
    reads = tuple(available[i] for i in arguments if i < len(available))
    writes = INTEGER_RESULTS[arch][:_integer_slots(arch, return_type, soft_float)]
    return reads, writes
