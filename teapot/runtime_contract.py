"""The rewrite/runtime contract: libcheckpoint's include/runtime_contract.h.

Each libcheckpoint archive comes with lib<archive>.contract.json, written when
the runtime is configured from its compiled headers. ``load_runtime_contract``
reads the one of the archive a rewrite will be linked with, and
``RuntimeContract.check`` compares every ABI fact in it with what Teapot emits
and the rewrite's options with what the archive provides. The ABI facts Teapot
expects come from the constants and functions its emitters use, so the check
covers the code Teapot actually writes.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Tuple, Union

from teapot.configs.runtime import (
    AARCH64_REPORT_ACCESS_ADDR,
    AARCH64_REPORT_CALL_STACK_OFFSET,
    AARCH64_REPORT_GADGET_ADDR,
    AARCH64_REPORT_RUNTIME_SAVE,
    AARCH64_REPORT_SIMD_STATE_OFFSET,
    AARCH64_REPORT_STATE_OFFSET,
    AARCH64_REPORT_TAG,
    ASAN_TAG_STORAGE_SHADOW,
    BRANCH_COUNTER_WIDTH,
    CHECKPOINT_TARGET_BRANCH_COUNTER_OFFSET,
    CHECKPOINT_TARGET_FIXED_REG_SOURCE_NONE,
    CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS,
    CHECKPOINT_TARGET_RETURN_OFFSET,
    CHECKPOINT_TARGET_SCRATCH_REG_OFFSET,
    CHECKPOINT_TARGET_TRAMPOLINE_OFFSET,
    COUNTER_WIDTH,
    DIFT_QUEUE_PENDING_SIZE,
    DIFT_REG_TAGS_ALIGNMENT,
    DIFT_REG_TAGS_SIZE,
    DIFT_TAG_SIZE,
    GUARD_ENTRY_WIDTH,
    MEMORY_HISTORY_ADDR_OFFSET,
    MEMORY_HISTORY_DATA_OFFSET,
    MEMORY_HISTORY_DATA_WIDTH,
    MEMORY_HISTORY_ENTRY_SIZE,
    MEMORY_HISTORY_SIZE_OFFSET,
    MEMORY_HISTORY_SIZE_WIDTH,
    RUNTIME_CONTRACT_VERSION,
    SCRATCHPAD_ALIGNMENT,
    SCRATCHPAD_SIZE,
    X64_REPORT_CALL_STACK_OFFSET,
    X64_REPORT_TAG_SPILL_OFFSET,
    X64_VECTOR_STATE_ARGUMENTS,
)
from teapot.configs.slots import (
    AARCH64_SHADOW_STACK_LAYOUT,
    RISCV64_ORIGINAL_TP_OFFSET,
    SCRATCHPAD_FIRST_SPILL_OFFSET,
)
from teapot.configs.tags import TAG_ATTACKER, TAG_ATTACKER_INDIRECT, TAG_SECRET, TAG_SECRET_INDIRECT
from teapot.datacls.dift_layout import DiftLayout

SCHEMA = "libcheckpoint-runtime-contract"

# Capability names in the bit order of runtime_contract.h.
CAPABILITIES = ("nested", "aarch64_bti_pac", "dift_runtime", "x64_vector_full", "coverage",
                "riscv64_float_state", "x64_vector_sse", "x64_vector_avx")
# The capability each x64 vector state needs: a runtime with a forced, smaller
# TEAPOT_X64_VECTOR_STATE ignores the state the rewrite asks for.
_X64_VECTOR_CAPABILITY = {"auto": "x64_vector_full", "full": "x64_vector_full", "avx": "x64_vector_avx",
                          "sse": "x64_vector_sse", "xmm0-7": None}

# Facts the runtime's build options choose; check() validates them against the
# rewrite's options instead of a fixed value. The application ranges are the
# runtime's (Teapot emits none of them) but belong to the fingerprint: the
# archive linked must cover exactly the ranges the rewrite was checked against.
# So does the coverage mode: a runtime built for a fuzzer (TEAPOT_ENABLE_COVERAGE)
# replays the speculative coverage guards, and Teapot emits their pushes for
# exactly such a runtime (RuntimeContract.emits_coverage).
_DIFT_RANGE_SLOTS = 5
_CONFIGURED = ("isa", "dift.layout", "dift.xor_mask", "dift.asan_shadow_offset", "tag_storage",
               "coverage", "dift.app_range_count",
               *(f"dift.app_range{index}.{end}" for index in range(_DIFT_RANGE_SLOTS)
                 for end in ("start", "end")))

_DIFT_REGISTERS = {
    "x64": ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
    "aarch64": tuple(f"x{index}" for index in range(31)) + ("sp",),
    "riscv64": ("zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
                "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
                "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
                "t3", "t4", "t5", "t6"),
}
_DIFT_RETURN_REGISTER = {"x64": "rax", "aarch64": "x0", "riscv64": "a0"}


class RuntimeContractError(ValueError):
    """The selected runtime cannot serve this rewrite, or its contract is unusable."""


def abi_fingerprint(abi: Mapping[str, Union[int, str]]) -> str:
    """The fingerprint libcheckpoint computes: SHA-256 over sorted KEY=VALUE lines."""
    text = "".join(f"{key}={abi[key]}\n" for key in sorted(abi))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def contract_anchor(version: int, fingerprint: str) -> str:
    """The symbol only an archive with this ABI defines."""
    return f"__libcheckpoint_contract_v{version}_{fingerprint}"


def capability_bits(names) -> int:
    return sum(1 << CAPABILITIES.index(name) for name in names)


@dataclass(frozen=True)
class RuntimeContract:
    path: str
    archive: str
    version: int
    fingerprint: str
    abi: Mapping[str, Union[int, str]]
    capabilities: frozenset
    runtime: Mapping[str, int]
    provenance: Mapping[str, str]

    @property
    def anchor(self) -> str:
        return contract_anchor(self.version, self.fingerprint)

    @property
    def isa(self) -> str:
        return self.abi["isa"]

    @property
    def tag_storage(self) -> str:
        return self.abi["tag_storage"]

    @property
    def coverage(self) -> bool:
        """Whether this runtime replays speculative coverage into a fuzzer.

        It is the archive's build option (TEAPOT_ENABLE_COVERAGE, the default
        with hfuzz-clang or hfuzz-gcc), fixed when the runtime is configured and
        part of its fingerprint; nothing at run time changes it.
        """
        return bool(self.abi["coverage"])

    def emits_coverage(self, options) -> bool:
        """Whether a rewrite with ``options`` for this runtime pushes coverage guards.

        Only a runtime built for a fuzzer replays them; an ordinary one resets
        the guard list at each rollback and would discard them, so a rewrite for
        it has neither the pushes nor the register spills around them.
        --disable-gadgets skips them in either case.
        """
        return options.enable_gadgets and self.coverage

    def dift_layout(self) -> DiftLayout:
        count = self.abi["dift.app_range_count"]
        ranges = tuple((self.abi[f"dift.app_range{index}.start"], self.abi[f"dift.app_range{index}.end"])
                       for index in range(count))
        return DiftLayout(name=self.abi["dift.layout"], arch=self.isa, xor_mask=self.abi["dift.xor_mask"],
                          asan_shadow_offset=self.abi["dift.asan_shadow_offset"], app_ranges=ranges)

    def check(self, arch, abi, options, dift_layout_name=None) -> Tuple[int, DiftLayout]:
        """Refuse a runtime Teapot does not emit for, or one the options need more of.

        Returns the module record's required capability bits and the runtime's
        DIFT layout. Every ABI field is compared, so a field either side does
        not know is a mismatch too.
        """
        if self.isa != arch.name:
            raise RuntimeContractError(
                f"{self.path} describes a {self.isa} runtime; this module is {arch.name}")
        expected = expected_abi(arch, abi)
        expected.update({key: self.abi[key] for key in _CONFIGURED if key in self.abi})
        problems = []
        for key in sorted(set(expected) | set(self.abi)):
            if key not in self.abi:
                problems.append(f"abi.{key}: Teapot emits {expected[key]!r}; the runtime has no such field")
            elif key not in expected:
                problems.append(f"abi.{key}: the runtime has {self.abi[key]!r}, which this Teapot does not know")
            elif self.abi[key] != expected[key]:
                problems.append(f"abi.{key}: runtime {self.abi[key]!r}, Teapot emits {expected[key]!r}")

        tag_storage = options.aarch64_tag_storage if arch.name == "aarch64" else ASAN_TAG_STORAGE_SHADOW
        if self.tag_storage != tag_storage:
            problems.append(f"tag storage: the runtime uses {self.tag_storage}; the rewrite asks for {tag_storage} "
                            f"(--aarch64-tag-storage or -DTEAPOT_AARCH64_TAG_STORAGE)")
        if dift_layout_name is not None and dift_layout_name != self.abi["dift.layout"]:
            problems.append(f"DIFT layout: the runtime was built for {self.abi['dift.layout']}; "
                            f"--dift-layout asks for {dift_layout_name}")

        required = set()
        if options.target_identification == "aarch64-bti-pac":
            required.add("aarch64_bti_pac")
        if options.enable_nested_speculation:
            required.add("nested")
        # DIFT propagation reads the DIFT shadow, and so do the x64 and AArch64
        # port-contention policies; the RISC-V one reads register tags only.
        if options.enable_dift or (options.enable_gadgets and options.enable_port_gadgets and
                                   arch.name in ("x64", "aarch64")):
            required.add("dift_runtime")
        if arch.name == "x64" and _X64_VECTOR_CAPABILITY[options.x64_vector_state]:
            required.add(_X64_VECTOR_CAPABILITY[options.x64_vector_state])
        # A RISC-V rollback restores the FP registers and FCSR only in a runtime
        # built to save them. Nothing proves a module free of FP state, so every
        # RISC-V rewrite with checkpoints needs it.
        if arch.name == "riscv64" and options.enable_checkpoints:
            required.add("riscv64_float_state")
        if self.emits_coverage(options):
            required.add("coverage")
        remedies = {
            "coverage": ("the module pushes speculative coverage guards, which only a runtime built "
                         "with -DTEAPOT_ENABLE_COVERAGE=ON replays"),
            "aarch64_bti_pac": "the BTI+PAC mode needs a runtime built with -DTEAPOT_EXPERIMENTAL_AARCH64_BTI=ON",
            "nested": ("nested speculation needs the nested runtime: libcheckpoint_nested.contract.json "
                       "(build it with -DTEAPOT_BUILD_NESTED_RUNTIME=ON)"),
            "dift_runtime": ("DIFT and the port-contention policies read the DIFT shadow, which a runtime "
                             "built with -DTEAPOT_ENABLE_DIFT_RUNTIME=OFF does not map"),
            "x64_vector_full": ("the runtime forces a smaller vector state than the checkpoint sites ask for; "
                                "build it with TEAPOT_X64_VECTOR_STATE=auto or full"),
            "x64_vector_avx": ("the runtime forces less than --x64-vector-state avx saves; build it with "
                               "TEAPOT_X64_VECTOR_STATE=auto, avx or full"),
            "x64_vector_sse": ("the runtime forces less than --x64-vector-state sse saves; build it with "
                               "TEAPOT_X64_VECTOR_STATE=auto, sse, avx or full"),
            "riscv64_float_state": ("a rollback would not restore the floating-point registers and FCSR; "
                                    "build the runtime with -DTEAPOT_ENABLE_RISCV_FLOAT_STATE=ON"),
        }
        for capability in sorted(required - self.capabilities):
            problems.append(f"capability {capability}: {remedies[capability]}")
        if problems:
            raise RuntimeContractError(
                f"the runtime in {self.path} does not match this rewrite:\n  " + "\n  ".join(problems))
        layout = self.dift_layout()
        if layout.arch != arch.name:
            raise RuntimeContractError(f"DIFT layout {layout.name} is for {layout.arch}, not {arch.name}")
        return capability_bits(required), layout


def expected_abi(arch, abi) -> dict:
    """The ABI Teapot's emitters assume for ``arch``, keyed like the contract."""
    calling_convention = abi.calling_convention().registers
    dift_id = lambda name: arch.dift_register_id(abi.get_register(name))
    expected = {
        "contract.version": RUNTIME_CONTRACT_VERSION,
        "word_size": 8,
        "little_endian": 1,
        "scratchpad.size": SCRATCHPAD_SIZE,
        "scratchpad.alignment": SCRATCHPAD_ALIGNMENT,
        "scratchpad.first_spill": SCRATCHPAD_FIRST_SPILL_OFFSET,
        "memlog.entry_size": MEMORY_HISTORY_ENTRY_SIZE,
        "memlog.addr_offset": MEMORY_HISTORY_ADDR_OFFSET,
        "memlog.data_offset": MEMORY_HISTORY_DATA_OFFSET,
        "memlog.data_width": MEMORY_HISTORY_DATA_WIDTH,
        "memlog.size_offset": MEMORY_HISTORY_SIZE_OFFSET,
        "memlog.size_width": MEMORY_HISTORY_SIZE_WIDTH,
        "target_metadata.trampoline": CHECKPOINT_TARGET_TRAMPOLINE_OFFSET,
        "target_metadata.return": CHECKPOINT_TARGET_RETURN_OFFSET,
        "target_metadata.branch_counter": CHECKPOINT_TARGET_BRANCH_COUNTER_OFFSET,
        "branch_counter.width": BRANCH_COUNTER_WIDTH,
        "counters.instruction_cnt_width": COUNTER_WIDTH,
        "counters.checkpoint_cnt_width": COUNTER_WIDTH,
        "guards.list_entry_width": GUARD_ENTRY_WIDTH,
        "dift.reg_tags_size": DIFT_REG_TAGS_SIZE,
        "dift.tag_size": DIFT_TAG_SIZE,
        "dift.reg_tags_bytes": DIFT_REG_TAGS_SIZE * DIFT_TAG_SIZE,
        "dift.reg_tags_alignment": DIFT_REG_TAGS_ALIGNMENT,
        "dift.queued_tags_alignment": DIFT_REG_TAGS_ALIGNMENT,
        "dift.queue_pending_size": DIFT_QUEUE_PENDING_SIZE,
        "dift.tag.attacker": TAG_ATTACKER,
        "dift.tag.attacker_indirect": TAG_ATTACKER_INDIRECT,
        "dift.tag.secret": TAG_SECRET,
        "dift.tag.secret_indirect": TAG_SECRET_INDIRECT,
        "dift.ret": dift_id(_DIFT_RETURN_REGISTER[arch.name]),
    }
    for index in range(6):
        expected[f"dift.arg{index}"] = dift_id(calling_convention[index])
    for name in _DIFT_REGISTERS[arch.name]:
        expected[f"dift.reg.{name}"] = dift_id(name)
    if arch.name == "x64":
        expected.update({
            "report.x64.tag_spill": X64_REPORT_TAG_SPILL_OFFSET,
            "report.x64.call_stack": X64_REPORT_CALL_STACK_OFFSET,
        })
        expected.update({f"x64.vector_state.{name}": value for name, value in X64_VECTOR_STATE_ARGUMENTS.items()})
        return expected

    expected.update({
        "target_metadata.scratch_reg": CHECKPOINT_TARGET_SCRATCH_REG_OFFSET,
        "target_metadata.fixed_reg0_source": CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS[0],
        "target_metadata.fixed_reg1_source": CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS[1],
        "target_metadata.fixed_reg_none": CHECKPOINT_TARGET_FIXED_REG_SOURCE_NONE,
    })
    if arch.name == "aarch64":
        for number in range(31):
            expected[f"checkpoint.reg.x{number}"] = arch.checkpoint_register_state_offset(number)
        expected.update({
            "report.aarch64.state": AARCH64_REPORT_STATE_OFFSET,
            "report.aarch64.gadget_addr": AARCH64_REPORT_GADGET_ADDR,
            "report.aarch64.access_addr": AARCH64_REPORT_ACCESS_ADDR,
            "report.aarch64.tag": AARCH64_REPORT_TAG,
            "report.aarch64.runtime_save": AARCH64_REPORT_RUNTIME_SAVE,
            "report.aarch64.simd_state": AARCH64_REPORT_SIMD_STATE_OFFSET,
            "report.aarch64.call_stack": AARCH64_REPORT_CALL_STACK_OFFSET,
        })
        expected.update({f"aarch64.shadow_stack.{name}": value
                         for name, value in AARCH64_SHADOW_STACK_LAYOUT.items()})
    else:
        for number in range(1, 32):
            expected[f"checkpoint.reg.x{number}"] = arch.checkpoint_register_state_offset(number)
        expected["scratchpad.riscv64_original_tp"] = RISCV64_ORIGINAL_TP_OFFSET
    return expected


def _require(condition, path, message):
    if not condition:
        raise RuntimeContractError(f"{path}: {message}")


def load_runtime_contract(path) -> RuntimeContract:
    """Read and validate one archive's lib<archive>.contract.json.

    This checks only the file itself: its schema and version, and that its
    fingerprint is the hash of its ABI section. ``RuntimeContract.check``
    compares it with the rewrite.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise RuntimeContractError(f"cannot read the runtime contract {path}: {error}") from None
    _require(isinstance(data, dict) and data.get("schema") == SCHEMA, path,
             f"not a libcheckpoint runtime contract (schema {SCHEMA})")
    version = data.get("version")
    _require(version == RUNTIME_CONTRACT_VERSION, path,
             f"contract version {version}; this Teapot supports version {RUNTIME_CONTRACT_VERSION}. "
             "Use the Teapot and libcheckpoint versions pinned together")
    for field, kind in (("abi", dict), ("capabilities", dict), ("runtime", dict), ("provenance", dict),
                        ("fingerprint", str), ("archive", str), ("capability_bits", int)):
        _require(isinstance(data.get(field), kind), path, f"missing or malformed field {field}")
    abi = data["abi"]
    _require(all(isinstance(value, (int, str)) and not isinstance(value, bool) for value in abi.values()),
             path, "ABI values must be integers or strings")
    for key, kind in (("isa", str), ("dift.layout", str), ("tag_storage", str), ("dift.xor_mask", int),
                      ("dift.asan_shadow_offset", int)):
        _require(isinstance(abi.get(key), kind) and not isinstance(abi.get(key), bool), path,
                 f"missing or malformed ABI field {key}")
    _require(abi.get("coverage") in (0, 1) and type(abi.get("coverage")) is int, path,
             "missing or malformed ABI field coverage (0 or 1)")
    _require(all(isinstance(value, int) and not isinstance(value, bool) for value in data["runtime"].values()),
             path, "runtime values must be integers")
    # The application ranges: a count of 1 to the number of slots, every slot
    # present as integers, and the slots past the count zero, as the runtime's
    # probe writes them (they are fingerprinted, so a stray value would bind the
    # anchor to ranges that dift_layout() ignores).
    count = abi.get("dift.app_range_count")
    _require(isinstance(count, int) and not isinstance(count, bool) and 1 <= count <= _DIFT_RANGE_SLOTS, path,
             f"dift.app_range_count must be an integer from 1 to {_DIFT_RANGE_SLOTS}")
    for index in range(_DIFT_RANGE_SLOTS):
        for end in ("start", "end"):
            key = f"dift.app_range{index}.{end}"
            value = abi.get(key)
            _require(isinstance(value, int) and not isinstance(value, bool), path, f"missing or malformed ABI field {key}")
            _require(index < count or value == 0, path, f"{key} is past dift.app_range_count but not zero")
    fingerprint = abi_fingerprint(abi)
    _require(data["fingerprint"] == fingerprint, path,
             f"the fingerprint {data['fingerprint']} is not the hash of its ABI section ({fingerprint}); "
             "regenerate the file by configuring libcheckpoint, do not edit it")
    _require(data.get("anchor", contract_anchor(version, fingerprint)) == contract_anchor(version, fingerprint),
             path, "the anchor symbol does not match the fingerprint")
    _require(set(data["capabilities"]) == set(CAPABILITIES), path,
             "unknown or missing capabilities: " + ", ".join(sorted(set(data["capabilities"]) ^ set(CAPABILITIES))))
    capabilities = frozenset(name for name, present in data["capabilities"].items() if present is True)
    _require(capability_bits(capabilities) == data["capability_bits"], path,
             "capability_bits disagrees with the named capabilities")
    # Both come from the archive's COVERAGE switch.
    _require(("coverage" in capabilities) == bool(abi["coverage"]), path,
             "the coverage capability disagrees with ABI field coverage")
    return RuntimeContract(
        path=str(path), archive=data["archive"], version=version, fingerprint=fingerprint,
        abi=MappingProxyType(dict(abi)), capabilities=capabilities,
        runtime=MappingProxyType(dict(data["runtime"])), provenance=MappingProxyType(dict(data["provenance"])))
