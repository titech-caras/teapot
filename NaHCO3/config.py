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
    "frame_dummy",
    "__libc_csu_init",
    "NaHCO3_setup",
]

CHECKPOINT_LIB_SYMBOLS = [
    "scratchpad",
    "old_rsp",
    "scratchpad_rsp",

    "libcheckpoint_enable",
    "libcheckpoint_disable",
    "make_checkpoint",
    "restore_checkpoint_ROB_LEN",
    "restore_checkpoint_EXT_LIB",
    "restore_checkpoint_MALFORMED_INDIRECT_BR",

    "report_gadget_SPECFUZZ_ASAN",
    "report_gadget_KASPER",

    "checkpoint_target_metadata",
    "memory_history_top",
    "checkpoint_cnt",
    "instruction_cnt",

    "dift_reg_tags",

    "__sanitizer_cov_trace_pc_guard",
]

# TODO: eventually take an abilist file instead
DIFT_IGNORE_LIST = [
    "printf", "puts", "putchar", "fprintf", "putc", "fputc",
    "isatty", "clock", "utimensat",
    "chown", "chmod", "unlink",
    "open", "fdopen", "fwrite", "fopen", "fclose", "fflush", "ferror", "fseek", "ftell", "feof",
    "malloc", "free", "realloc", "calloc",
    "strcmp", "strncmp",
    "abort", "__assert_fail", "exit", "__errno_location", "__xstat"
]

TAG_ATTACKER = 1
TAG_SECRET = 2

#MODE = "SpecFuzz"
MODE = "Kasper"

assert MODE in ("SpecFuzz", "Kasper")