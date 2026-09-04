import re

from teapot.configs.runtime import SYMBOL_SUFFIX


BLACKLIST_FUNCTION_NAMES = [
    "_start",
    "_init",
    "_fini",
    "call_weak_fn",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
    "dummy",
    "frame_dummy",
    "__libc_csu_init",
    "__libc_csu_fini",
    "load_gp",
    "teapot_setup",
    "__teapot_specvariant_setup",
    "__wrap_main",
]

GENERATED_CTOR_DTOR_RE = re.compile(r"^(_sub_[ID]_[0-9]+_[0-9]+|_GLOBAL__sub_[ID]_.+)$")


def unsuffixed_symbol_name(name: str) -> str:
    if name.endswith(SYMBOL_SUFFIX):
        return name[:-len(SYMBOL_SUFFIX)]
    return name


def is_blacklisted_function_name(name: str) -> bool:
    name = unsuffixed_symbol_name(name)
    return name in BLACKLIST_FUNCTION_NAMES or GENERATED_CTOR_DTOR_RE.match(name) is not None


def function_symbol_names(function):
    names = getattr(function, "names", None)
    if names is None:
        return [function.get_name()]
    return names


def is_gnu_ifunc_resolver(function) -> bool:
    """Return whether an ELF GNU_IFUNC symbol resolves through this function.

    IFUNC resolvers run while the dynamic loader is still applying
    relocations, before Teapot's runtime and ASan shadow state are ready.  A
    resolver's Function name is often a local implementation name rather than
    the public GNU_IFUNC symbol name, so identify it through the entry block
    referenced by ``elfSymbolInfo`` instead of a name list.
    """
    entry_blocks = set(function.get_entry_blocks())
    if not entry_blocks:
        return False

    entry_block = next(iter(entry_blocks))
    section = entry_block.section
    module = section.module if section is not None else None
    if module is None:
        return False

    elf_symbol_info = module.aux_data.get("elfSymbolInfo")
    if elf_symbol_info is None:
        return False

    for symbol, info in elf_symbol_info.data.items():
        if (getattr(symbol, "referent", None) in entry_blocks and
                len(info) > 1 and info[1] == "GNU_IFUNC"):
            return True
    return False


def is_blacklisted_function(function) -> bool:
    return (any(is_blacklisted_function_name(name) for name in function_symbol_names(function)) or
            is_gnu_ifunc_resolver(function))


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
    "fstat",
    "fopen64", "dlopen", "dladdr", "dlsym", "dlclose", "dlerror", "perror", "fcntl", "ioctl", "select", "fileno",
    "readdir", "closedir", "opendir",
    "malloc", "free", "realloc",
    "strcmp", "strncmp", "strchr", "strrchr", "strerror", "memchr", "memcmp", "qsort", "strspn", "strcspn",
    "strlcat", "strlcpy",
    "strcasecmp", "strncasecmp",
    "__ctype_b_loc", "__ctype_tolower_loc", "__ctype_toupper_loc",
    "abort", "__assert_fail", "exit", "__errno_location", "__xstat", "__stack_chk_fail", "__cxa_atexit",
    "gai_strerror", "__xpg_strerror_r", "mmap", "mprotect", "mlock", "madvise", "munmap",
    "inflateInit2_", "inflateEnd",
    "crc32",

    "getenv",  # FIXME: whitelist only for now, needed for some experiments

    "sprintf", "__isoc99_sscanf", "__isoc23_strtol",  # FIXME: these should actually be tainted
]

DIFT_WRAPPER_FUNCTIONS = {
    "read",
    "fread",
    "fread_unlocked",
    "fgets",
    "getc",
    "fgetc",
    "getchar",
    "calloc",
    "atoi",
    "strtol",
    "strtoul",
    "strlen",
    "strdup",
    "memcpy",
    "__memcpy_chk",
    "memmove",
    "strcpy",
    "strcat",
    "strncat",
    "__strncat_chk",
    "strncpy",
    "memset",
    "__memset_chk",
    "strtok_r",
    "strtok",
    "strstr",
    "inet_pton",
    "log2",
    "inflate",
}
