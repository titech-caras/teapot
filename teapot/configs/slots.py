import os
from pathlib import Path
import re

from teapot.configs.runtime import SCRATCHPAD_SIZE


def _aarch64_shadow_stack_config_path():
    default_path = Path(__file__).resolve().parents[2] / "libcheckpoint/include/aarch64_shadow_stack.h"
    return Path(os.environ.get("TEAPOT_AARCH64_SHADOW_STACK_CONFIG", default_path))


def _aarch64_shadow_stack_constants():
    path = _aarch64_shadow_stack_config_path()
    if not path.is_file():
        raise FileNotFoundError(
            f"AArch64 shadow-stack configuration not found: {path}. Set "
            "TEAPOT_AARCH64_SHADOW_STACK_CONFIG to the header installed by the matching libcheckpoint build.")
    # The shared header deliberately uses literal definitions, not arbitrary C
    # expressions; reject missing or nonliteral values rather than guessing.
    definitions = re.findall(r"^#define AARCH64_SHADOW_STACK_([A-Z_]+) (0|[1-9][0-9]*)$",
                             path.read_text(), re.MULTILINE)
    values = {name: int(value) for name, value in definitions}
    if len(definitions) != len(values):
        raise ValueError(f"Duplicate AArch64 shadow stack definitions in {path}")
    size = values.get("SIZE", 0)
    if size < 4096 or size % 4096 or size // 4096 > 4095:
        raise ValueError("AArch64 shadow stack size must be 1-4095 pages for one add/sub immediate")
    for name in ("CONTROL_OFFSET", "REPORT_OFFSET"):
        offset = values.get(name, -1)
        if offset < 0 or offset > 504 or offset % 8:
            raise ValueError(f"AArch64 shadow stack {name} must fit a register-pair immediate")
    return values


class ScratchpadSlots:
    FIRST_SPILL = SCRATCHPAD_SIZE // 2
    RISCV64_LANDING_RESTORE_FLAG = FIRST_SPILL + 4096
    RISCV64_LANDING_TEMP = RISCV64_LANDING_RESTORE_FLAG + 8
    RISCV64_ORIGINAL_TP = SCRATCHPAD_SIZE - 32768
    X64_REP_STATE = FIRST_SPILL + 8192
    X64_MEM_POLICY_CONDITION = FIRST_SPILL + 12288
    # Report callbacks use the first eight words. Deferred transient captures
    # can now span a policy which does not read their pending tags.
    TRANSIENT_DIFT_CAPTURE = 64

    TEXT_DIFT_CAPTURE_SCRATCH_SAVE = SCRATCHPAD_SIZE - 65536
    TEXT_DIFT_LLVM_SCRATCH_SAVE = TEXT_DIFT_CAPTURE_SCRATCH_SAVE + 4096
    TEXT_DIFT_LLVM_ORIGINAL_SP_SLOT = 4096 - 8
    TEXT_DIFT_LLVM_STACK = TEXT_DIFT_LLVM_SCRATCH_SAVE + 8192
    TEXT_DIFT_LLVM_STACK_SIZE = 16384
    TEXT_DIFT_LLVM_STACK_SP = TEXT_DIFT_LLVM_STACK + TEXT_DIFT_LLVM_STACK_SIZE // 2


class AArch64ShadowStackSlots:
    _values = _aarch64_shadow_stack_constants()
    SIZE = _values["SIZE"]
    DIFT = _values["DIFT_OFFSET"]
    MEMLOG = _values["MEMLOG_OFFSET"]
    ASAN = _values["ASAN_OFFSET"]
    GADGET_MEM = _values["GADGET_MEM_OFFSET"]
    GADGET_PORT = _values["GADGET_PORT_OFFSET"]
    GADGET = GADGET_MEM
    COVERAGE = _values["COVERAGE_OFFSET"]
    CONTROL = _values["CONTROL_OFFSET"]
    RESTORE = _values["RESTORE_OFFSET"]
    INDIRECT_TARGET = _values["INDIRECT_TARGET_OFFSET"]
    REPORT = _values["REPORT_OFFSET"]
    ABI = _values["ABI_OFFSET"]
    TEXT_DIFT_CAPTURE = _values["TEXT_DIFT_CAPTURE_OFFSET"]
    TEXT_DIFT_LLVM = _values["TEXT_DIFT_LLVM_OFFSET"]
    del _values


SCRATCHPAD_FIRST_SPILL_OFFSET = ScratchpadSlots.FIRST_SPILL
RISCV64_LANDING_RESTORE_FLAG_OFFSET = ScratchpadSlots.RISCV64_LANDING_RESTORE_FLAG
RISCV64_LANDING_TEMP_OFFSET = ScratchpadSlots.RISCV64_LANDING_TEMP
RISCV64_ORIGINAL_TP_OFFSET = ScratchpadSlots.RISCV64_ORIGINAL_TP

AARCH64_SHADOW_STACK_SIZE = AArch64ShadowStackSlots.SIZE
AARCH64_SHADOW_STACK_DIFT_OFFSET = AArch64ShadowStackSlots.DIFT
AARCH64_SHADOW_STACK_MEMLOG_OFFSET = AArch64ShadowStackSlots.MEMLOG
AARCH64_SHADOW_STACK_ASAN_OFFSET = AArch64ShadowStackSlots.ASAN
AARCH64_SHADOW_STACK_GADGET_MEM_OFFSET = AArch64ShadowStackSlots.GADGET_MEM
AARCH64_SHADOW_STACK_GADGET_PORT_OFFSET = AArch64ShadowStackSlots.GADGET_PORT
AARCH64_SHADOW_STACK_GADGET_OFFSET = AArch64ShadowStackSlots.GADGET
AARCH64_SHADOW_STACK_COVERAGE_OFFSET = AArch64ShadowStackSlots.COVERAGE
AARCH64_SHADOW_STACK_CONTROL_OFFSET = AArch64ShadowStackSlots.CONTROL
AARCH64_SHADOW_STACK_RESTORE_OFFSET = AArch64ShadowStackSlots.RESTORE
AARCH64_SHADOW_STACK_INDIRECT_TARGET_OFFSET = AArch64ShadowStackSlots.INDIRECT_TARGET
AARCH64_SHADOW_STACK_ABI_OFFSET = AArch64ShadowStackSlots.ABI
AARCH64_SHADOW_STACK_TEXT_DIFT_CAPTURE_OFFSET = AArch64ShadowStackSlots.TEXT_DIFT_CAPTURE
AARCH64_SHADOW_STACK_TEXT_DIFT_LLVM_OFFSET = AArch64ShadowStackSlots.TEXT_DIFT_LLVM
AARCH64_SHADOW_STACK_REPORT_OFFSET = AArch64ShadowStackSlots.REPORT
