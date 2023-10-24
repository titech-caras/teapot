SYMBOL_SUFFIX = "__NaHCO3__"

ROB_LEN = 250
SCRATCHPAD_SIZE = 1048576

ASAN_SHADOW_OFFSET = "0x7fff8000"

BLACKLIST_FUNCTION_NAMES = [
    "_start",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "dummy",
    "frame_dummy"
]

CHECKPOINT_LIB_SYMBOLS = [
    "scratchpad",
    "old_rsp",

    "libcheckpoint_enable",
    "libcheckpoint_disable",
    "make_checkpoint",
    "restore_checkpoint_ROB_LEN",
    "restore_checkpoint_EXT_LIB",
    "restore_checkpoint_MALFORMED_INDIRECT_BR",

    "report_gadget_specfuzz_asan",

    "checkpoint_target_metadata",
    "memory_history_top",
    "checkpoint_cnt",
    "instruction_cnt",
]
