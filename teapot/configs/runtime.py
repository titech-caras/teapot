SYMBOL_SUFFIX = "__teapot__"

ROB_LEN = 250
SCRATCHPAD_SIZE = 1048576
MEMORY_HISTORY_ENTRY_SIZE = 24
MEMORY_HISTORY_SIZE_OFFSET = 16
MEMORY_HISTORY_MTE_TAG_SIZE = 0xff

ASAN_TAG_STORAGE_SHADOW = "shadow"
ASAN_TAG_STORAGE_MTE = "mte"
ASAN_TAG_STORAGES = (ASAN_TAG_STORAGE_SHADOW, ASAN_TAG_STORAGE_MTE)

COMMON_CHECKPOINT_LIB_SYMBOLS = [
    "scratchpad",
    "old_rsp",
    "scratchpad_rsp",

    "checkpoint_cnt",
    "libcheckpoint_enable",
    "libcheckpoint_disable",
    "restore_checkpoint_ROB_LEN",
    "restore_checkpoint_EXT_LIB",
    "restore_checkpoint_MALFORMED_INDIRECT_BR",

    "report_gadget_SPECFUZZ_ASAN_READ",
    "report_gadget_SPECFUZZ_ASAN_WRITE",
    "report_gadget_SPECTAINT_BCB",
    "report_gadget_SPECTAINT_BCBS",
    "report_gadget_KASPER_CACHE",
    "report_gadget_KASPER_MDS",
    "report_gadget_KASPER_PORT",

    "checkpoint_target_metadata",
    "memory_history_top",
    "guard_list_top",
    "indirect_branch_flags_scratch",
    "instruction_cnt",

    "dift_reg_tags",
    "dift_reg_queued_tags",

    "__sanitizer_cov_trace_pc",
    "__sanitizer_cov_trace_pc_guard",
]
