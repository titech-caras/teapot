"""Teapot's instrumentation modes and the option combinations each one supports.

One table, checked once before a rewrite starts (``TeapotPipeline.run``).
BTI and PAC form one mode, aarch64-bti-pac: it enables both, and neither is
selectable alone. Whether the selected runtime can serve the options is the
runtime contract's check (teapot/runtime_contract.py), not this table's.
"""
from dataclasses import dataclass, fields
from typing import Callable, FrozenSet, Optional, Tuple

from teapot.configs.runtime import ASAN_TAG_STORAGE_MTE, ASAN_TAG_STORAGE_SHADOW


class ModeError(ValueError):
    """The options cannot be combined; the message names the conflict and the remedy."""


def _bti_pac_architecture():
    from teapot.arch.aarch64.bti_pac import AArch64BTIPACArchitecture
    return AArch64BTIPACArchitecture()


@dataclass(frozen=True)
class ModeSpec:
    name: str
    isas: FrozenSet[str]
    # (option field, what it enables, the flag that disabled it); each must be on.
    required: Tuple[Tuple[str, str, str], ...] = ()
    # Builds the mode's Architecture; None keeps the ISA's own.
    architecture: Optional[Callable[[], object]] = None


MODES = {
    "software": ModeSpec("software", frozenset({"x64", "aarch64", "riscv64"})),
    "aarch64-bti-pac": ModeSpec(
        "aarch64-bti-pac", frozenset({"aarch64"}),
        required=(("enable_indirect_transform", "target transformation", "--disable-indirect-transform"),
                  ("enable_indirect_check", "target checking", "--disable-indirect-check"),
                  ("enable_checkpoints", "checkpoints", "--disable-checkpoints")),
        architecture=_bti_pac_architecture),
}

ISA_NAMES = {"x64": "x64", "aarch64": "AArch64", "riscv64": "RV64"}

TAG_STORAGES = {
    "x64": frozenset({ASAN_TAG_STORAGE_SHADOW}),
    "aarch64": frozenset({ASAN_TAG_STORAGE_SHADOW, ASAN_TAG_STORAGE_MTE}),
    "riscv64": frozenset({ASAN_TAG_STORAGE_SHADOW}),
}

# Component rewriting (one module of a final link of separately rewritten
# components) keeps these options at their defaults, each with the remedy for
# the flag that changed it. Tag storage and the target identification may vary:
# they are link contracts, checked against the runtime and the other components.
# Every option field is in exactly one of the two tables (tests/test_modes.py),
# so a new option is a conscious choice, neither forbidden nor allowed by
# accident.
COMPONENT_FIXED = {
    "enable_dift": "drop --disable-dift",
    "eager_transient_dift": "drop --transient-dift eager",
    "enable_asan": "drop --disable-asan",
    "enable_gadgets": "drop --disable-gadgets",
    "enable_memlog": "drop --disable-memlog",
    "enable_checkpoints": "drop --disable-checkpoints",
    "enable_nested_speculation": "nested speculation is not supported; drop --enable-nested-speculation",
    "enable_indirect_transform": "drop --disable-indirect-transform",
    "enable_indirect_check": "drop --disable-indirect-check",
    "enable_conditional_branch_relax": "drop --disable-aarch64-relax",
    "enable_mem_operand_gadgets": "drop --disable-mem-operand-gadgets",
    "enable_port_gadgets": "drop --disable-port-gadgets",
    "enable_gadget_asan_check": "drop --disable-gadget-asan-check",
    "debug_source": "source lines are not preserved; drop --debug-source",
    "conservative_flags": "drop --conservative-flags",
    "force_checkpoint_df": "drop --force-checkpoint-df",
    "x64_vector_state": "the vector state is chosen per site; drop --x64-vector-state",
}
COMPONENT_FREE = frozenset({"aarch64_tag_storage", "target_identification"})


def validate_options(options, isa: str, *, component: bool = False) -> ModeSpec:
    """The mode the options select, or a ModeError naming every conflict."""
    mode = MODES.get(options.target_identification)
    if mode is None:
        raise ModeError(f"unknown target identification {options.target_identification!r}; "
                        f"choose one of {', '.join(sorted(MODES))}")
    if isa not in mode.isas:
        raise ModeError(f"{mode.name} requires {' or '.join(ISA_NAMES[name] for name in sorted(mode.isas))}; "
                        f"this module is {ISA_NAMES.get(isa, isa)}")
    missing = [(what, flag) for field, what, flag in mode.required if not getattr(options, field)]
    if missing:
        raise ModeError(f"{mode.name} requires " + ", ".join(what for what, _ in missing) +
                        "; drop " + " and ".join(flag for _, flag in missing))
    known = frozenset().union(*TAG_STORAGES.values())
    if options.aarch64_tag_storage not in known:
        raise ModeError(f"unknown tag storage {options.aarch64_tag_storage!r}; choose one of "
                        f"{', '.join(sorted(known))}")
    if options.aarch64_tag_storage not in TAG_STORAGES[isa]:
        raise ModeError(f"--aarch64-tag-storage={options.aarch64_tag_storage} is only valid for AArch64 modules")
    if component:
        defaults = type(options)()
        changed = [f"{field} ({remedy})" for field, remedy in COMPONENT_FIXED.items()
                   if getattr(options, field) != getattr(defaults, field)]
        if changed:
            raise ModeError("component rewriting requires the default instrumentation: " + "; ".join(changed))
    return mode


def option_fields(options_type):
    return {field.name for field in fields(options_type)}
