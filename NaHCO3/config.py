SYMBOL_SUFFIX = "__NaHCO3__"

ROB_LEN = 250
SCRATCHPAD_SIZE = 1024

BLACKLIST_FUNCTION_NAMES = [
    "_start",
    "main",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "dummy",
    "frame_dummy"
]

CHECKPOINT_LIB_SYMBOLS = [
    "scratchpad",
    "old_rsp",

    "make_checkpoint",
    "restore_checkpoint",

    "checkpoint_target_metadata",
    "memory_history_top",
    "instruction_cnt",
]
