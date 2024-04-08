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

    "checkpoint_cnt",
    "libcheckpoint_enable",
    "libcheckpoint_disable",
    "make_checkpoint",
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
    "checkpoint_cnt",
    "instruction_cnt",

    "dift_reg_tags",

    "__sanitizer_cov_trace_pc",
    "__sanitizer_cov_trace_pc_guard",
]

# TODO: eventually take an abilist file instead
DIFT_IGNORE_LIST = [
    "printf", "puts", "putchar", "fprintf", "putc", "fputc", "__fprintf_chk", "__snprintf_chk", "__vsnprintf_chk",
    "fputs", "vfprintf",
    "isatty", "clock", "utimensat", "__fxstat", "gettimeofday", "getpid", "secure_getenv", "gmtime", "clock_gettime",
    "sendmsg", "uname", "getnameinfo", "getaddrinfo", "gethostbyname", "freeaddrinfo", "getsockname", "connect",
    "chown", "chmod", "unlink", "umask", "mkstemp", "shmdt", "shutdown", "shmget", "sysconf", "syscall", "tcgetattr",
    "shmat", "bind", "accept", "setsockopt", "tcsetattr", "sigaction", "listen", "getsockopt", "usleep", "socket",
    "signal", "time",
    "open", "fdopen", "fwrite", "fopen", "fclose", "fflush", "ferror", "fseek", "ftell", "feof", "close", "write",
    "fopen64", "dlopen", "dladdr", "dlsym", "dlclose", "dlerror", "perror", "fcntl", "ioctl", "select", "fileno",
    "readdir", "closedir", "opendir",
    "malloc", "free", "realloc",
    "strcmp", "strncmp", "strchr", "strrchr", "strerror", "memchr", "memcmp", "qsort", "strspn", "strcspn",
    "__ctype_b_loc", "__ctype_tolower_loc", "__ctype_toupper_loc",
    "abort", "__assert_fail", "exit", "__errno_location", "__xstat", "__stack_chk_fail", "__cxa_atexit", "gai_strerror",
    "__xpg_strerror_r", "mmap", "mprotect", "mlock", "madvise", "munmap",
    "inflateInit2_", "inflateEnd",
    "crc32",

    "sprintf", "__isoc99_sscanf"  # FIXME: these should actually be tainted
]

TAG_ATTACKER = 1
TAG_SECRET = 2
TAG_SECRET_NON_CONTROLLED = 4
