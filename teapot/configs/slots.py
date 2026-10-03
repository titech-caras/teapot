from teapot.configs.runtime import SCRATCHPAD_SIZE

# The AArch64 shadow-stack layout of libcheckpoint's include/aarch64_shadow_stack.h,
# keyed like its runtime contract (aarch64.shadow_stack.*), which the contract
# check compares. Change both together.
AARCH64_SHADOW_STACK_LAYOUT = {
    "size": 8388608,
    "dift_offset": 0,
    "memlog_offset": 64,
    "asan_offset": 128,
    "gadget_mem_offset": 192,
    "gadget_port_offset": 240,
    "coverage_offset": 288,
    "control_offset": 320,
    "restore_offset": 352,
    "indirect_target_offset": 384,
    "report_offset": 416,
    "abi_offset": 448,
    "text_dift_capture_offset": 480,
    "text_dift_llvm_offset": 512,
}


def _check_aarch64_shadow_stack_layout(values):
    size = values["size"]
    if size < 4096 or size % 4096 or size // 4096 > 4095:
        raise ValueError("AArch64 shadow stack size must be 1-4095 pages for one add/sub immediate")
    for name in ("control_offset", "report_offset"):
        offset = values[name]
        if offset < 0 or offset > 504 or offset % 8:
            raise ValueError(f"AArch64 shadow stack {name} must fit a register-pair immediate")


_check_aarch64_shadow_stack_layout(AARCH64_SHADOW_STACK_LAYOUT)


class ScratchpadSlots:
    FIRST_SPILL = SCRATCHPAD_SIZE // 2
    RISCV64_LANDING_RESTORE_FLAG = FIRST_SPILL + 4096
    RISCV64_LANDING_TEMP = RISCV64_LANDING_RESTORE_FLAG + 8
    RISCV64_ORIGINAL_TP = SCRATCHPAD_SIZE - 32768
    X64_REP_STATE = FIRST_SPILL + 8192
    X64_MEM_POLICY_CONDITION = FIRST_SPILL + 12288
    # The cold path of the x64 load policy's fast path saves its four extra
    # registers here: apart from the wrappers, reports (0-63) and captures (64+).
    X64_MEM_POLICY_COLD_SPILL = FIRST_SPILL + 16384
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
    SIZE = AARCH64_SHADOW_STACK_LAYOUT["size"]
    DIFT = AARCH64_SHADOW_STACK_LAYOUT["dift_offset"]
    MEMLOG = AARCH64_SHADOW_STACK_LAYOUT["memlog_offset"]
    ASAN = AARCH64_SHADOW_STACK_LAYOUT["asan_offset"]
    GADGET_MEM = AARCH64_SHADOW_STACK_LAYOUT["gadget_mem_offset"]
    GADGET_PORT = AARCH64_SHADOW_STACK_LAYOUT["gadget_port_offset"]
    GADGET = GADGET_MEM
    COVERAGE = AARCH64_SHADOW_STACK_LAYOUT["coverage_offset"]
    CONTROL = AARCH64_SHADOW_STACK_LAYOUT["control_offset"]
    RESTORE = AARCH64_SHADOW_STACK_LAYOUT["restore_offset"]
    INDIRECT_TARGET = AARCH64_SHADOW_STACK_LAYOUT["indirect_target_offset"]
    REPORT = AARCH64_SHADOW_STACK_LAYOUT["report_offset"]
    ABI = AARCH64_SHADOW_STACK_LAYOUT["abi_offset"]
    TEXT_DIFT_CAPTURE = AARCH64_SHADOW_STACK_LAYOUT["text_dift_capture_offset"]
    TEXT_DIFT_LLVM = AARCH64_SHADOW_STACK_LAYOUT["text_dift_llvm_offset"]


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
