SYMBOL_SUFFIX = "__teapot__"

# The names of the symbols Teapot generates, which the input must not use: it
# finds its symbols and refers to them by these names. Whole programs are
# refused in TeapotPipeline (teapot/preprocess/runtime_names.py), components in
# their driver (experiments/reusable_libraries/rewrite_components.py), by the
# same rule (is_generated_name).
GENERATED_NAME_INFIXES = (
    SYMBOL_SUFFIX,                # labels, copies, section and guard bounds, reference aliases
)
GENERATED_NAME_PREFIXES = (
    ".L__teapot_",                # the contract record, source-line labels, direct entries, reference aliases
    "__teapot_bti_",              # AArch64 BTI section bounds
    "__teapot_linked_",           # the bounds of a separately rewritten component
    "__teapot_component_",        # its guard base
    "__libcheckpoint_contract_",  # contract anchors, of any fingerprint
)
GENERATED_NAME_SUFFIXES = (
    "__teapot_wrapper__",         # the runtime's wrappers that external calls are redirected to
    "__dift_wrapper__",
)
GENERATED_NAMES = (
    "teapot_aarch64_bti_pac_rewrite_marker",
)


def is_generated_name(name: str) -> bool:
    """Whether Teapot generates symbols called ``name`` (GENERATED_NAME_*)."""
    return (any(infix in name for infix in GENERATED_NAME_INFIXES) or name.startswith(GENERATED_NAME_PREFIXES) or
            name.endswith(GENERATED_NAME_SUFFIXES) or name in GENERATED_NAMES)


# The speculation budget: Teapot's alone, recorded in each module's contract
# record but never compared with the runtime, which does not read it.
ROB_LEN = 250

# The layout Teapot's emitted code assumes. teapot/runtime_contract.py compares
# each value with the selected runtime's contract (libcheckpoint's
# lib<archive>.contract.json), so change one only together with the runtime.
RUNTIME_CONTRACT_VERSION = 1
SCRATCHPAD_SIZE = 1048576
SCRATCHPAD_ALIGNMENT = 16
# A memory-history entry: the address at offset 0 (the emitters store it at the
# entry's start), then up to MEMORY_HISTORY_DATA_WIDTH bytes and their count.
MEMORY_HISTORY_ENTRY_SIZE = 24
MEMORY_HISTORY_ADDR_OFFSET = 0
MEMORY_HISTORY_DATA_OFFSET = 8
MEMORY_HISTORY_DATA_WIDTH = 8
MEMORY_HISTORY_SIZE_OFFSET = 16
MEMORY_HISTORY_SIZE_WIDTH = 1
# checkpoint_target_metadata: the trampoline at offset 0 (the emitters store it
# at the symbol itself), the return address, the branch counter's address, the
# runtime's save slot for the final transfer register (AArch64, RISC-V) and the
# two fixed-register sources.
CHECKPOINT_TARGET_TRAMPOLINE_OFFSET = 0
CHECKPOINT_TARGET_RETURN_OFFSET = 8
CHECKPOINT_TARGET_BRANCH_COUNTER_OFFSET = 16
CHECKPOINT_TARGET_SCRATCH_REG_OFFSET = 24
CHECKPOINT_TARGET_FIXED_REG_SOURCE_OFFSETS = (32, 40)
CHECKPOINT_TARGET_FIXED_REG_SOURCE_NONE = -1
# Each trampoline's branch counter is a uint32_t; instruction_cnt and
# checkpoint_cnt are uint64_t; guard_list entries are uint32_t.
BRANCH_COUNTER_WIDTH = 4
COUNTER_WIDTH = 8
GUARD_ENTRY_WIDTH = 4
# One tag byte per register, copied in 16-byte pieces, and the pending byte of
# dift_reg_queued_tags (one granule, of which only byte 0 is used). Tags are
# bytes: the emitters load and store them as bytes.
DIFT_TAG_SIZE = 1
DIFT_REG_TAGS_SIZE = 48
DIFT_REG_TAGS_ALIGNMENT = 16
DIFT_QUEUE_PENDING_SIZE = 8

# Report calls. x64: Teapot saves eight registers in the scratchpad's first 64
# bytes and calls with rsp at X64_REPORT_STACK_OFFSET; the runtime's wrapper
# pushes two words below the return address, spills rdx at
# X64_REPORT_TAG_SPILL_OFFSET and runs C on a stack from
# X64_REPORT_CALL_STACK_OFFSET. AArch64: Teapot fills the report block's call
# site, access address and tag and keeps its x30 at AARCH64_REPORT_LINK_SAVE,
# below the runtime's save area.
X64_REPORT_STACK_OFFSET = SCRATCHPAD_SIZE - 32
X64_REPORT_TAG_SPILL_OFFSET = SCRATCHPAD_SIZE - 64
X64_REPORT_CALL_STACK_OFFSET = SCRATCHPAD_SIZE - 32768
AARCH64_REPORT_STATE_OFFSET = SCRATCHPAD_SIZE - 512
AARCH64_REPORT_GADGET_ADDR = 0
AARCH64_REPORT_ACCESS_ADDR = 8
AARCH64_REPORT_TAG = 16
AARCH64_REPORT_LINK_SAVE = 24
AARCH64_REPORT_RUNTIME_SAVE = 32
AARCH64_REPORT_SIMD_STATE_OFFSET = SCRATCHPAD_SIZE - 1040
AARCH64_REPORT_CALL_STACK_OFFSET = SCRATCHPAD_SIZE - 4096

# The argument of libcheckpoint_set_vector_state for each fixed x64 vector state.
X64_VECTOR_STATE_ARGUMENTS = {"xmm0-7": 1, "sse": 2, "avx": 3, "full": 4}

ASAN_TAG_STORAGE_SHADOW = "shadow"
ASAN_TAG_STORAGE_MTE = "mte"
ASAN_TAG_STORAGES = (ASAN_TAG_STORAGE_SHADOW, ASAN_TAG_STORAGE_MTE)

# The Sanitizer Coverage hooks. A coverage runtime calls them and the fuzzer's
# runtime defines them; a program compiled with -fsanitize-coverage calls them
# too, so a program may refer to them (teapot/preprocess/runtime_names.py).
COVERAGE_HOOK_SYMBOLS = [
    "__sanitizer_cov_trace_pc",
    "__sanitizer_cov_trace_pc_guard",
]

# The runtime names Teapot's code refers to, with each architecture's additions
# (Architecture.checkpoint_lib_symbols). The rewrite imports them, and a program
# that uses one of them is refused (teapot/preprocess/runtime_names.py).
COMMON_CHECKPOINT_LIB_SYMBOLS = [
    "scratchpad",

    "checkpoint_cnt",
    "libcheckpoint_enable",
    "libcheckpoint_disable",
    "restore_checkpoint_ROB_LEN",
    "restore_checkpoint_EXT_LIB",
    "restore_checkpoint_MALFORMED_INDIRECT_BR",

    "report_gadget_KASPER_CACHE",
    "report_gadget_KASPER_MDS",
    "report_gadget_KASPER_PORT",

    "checkpoint_target_metadata",
    "memory_history_top",
    "guard_list_top",
    "instruction_cnt",

    "dift_reg_tags",
    "dift_reg_queued_tags",
    "dift_reg_queue_pending",

    *COVERAGE_HOOK_SYMBOLS,
]
