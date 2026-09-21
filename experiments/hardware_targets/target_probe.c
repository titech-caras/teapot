/* Standalone experiment, NOT a Teapot instrumentation/runtime backend.
 * The software predicate below is intentionally identical to Teapot's current
 * range + two-word predicate. Generated pages have no application side effects.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#if defined(__x86_64__)
#include <cpuid.h>
#endif

#if defined(__aarch64__)
#define ARCH_NAME "aarch64"
#define MAGIC0 UINT32_C(0xd280229f)
#define MAGIC1 UINT32_C(0xd280a29f)
#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif
#ifndef HWCAP2_BTI
#define HWCAP2_BTI (1UL << 17)
#endif
#elif defined(__x86_64__)
#define ARCH_NAME "x64"
#define MAGIC0 UINT32_C(0x90db8748)
#define MAGIC1 UINT32_C(0x90d28748)
#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS 0x5005
#endif
#else
#error Unsupported probe architecture; RV64 remains software.
#endif

extern int probe_call(void *);
extern int probe_jump(void *);
extern int probe_return(void *);
extern int probe_elf_landing(void);
extern int probe_elf_plain(void);
typedef int (*transfer_fn)(void *);

struct outcome {
    int signal_number, signal_code, value;
    uintptr_t pc, address, branch_state;
};

static int result_fd = -1;
static size_t page_size;
static unsigned char *normal_page, *transient_page, *outside_page;

static void fail(const char *message) {
    perror(message);
    exit(2);
}

static void fault_handler(int number, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    struct outcome result = {.signal_number = number, .signal_code = info->si_code,
                             .address = (uintptr_t)info->si_addr};
#if defined(__aarch64__)
    result.pc = uc->uc_mcontext.pc;
    result.branch_state = (uc->uc_mcontext.pstate >> 10) & 3;
#else
    result.pc = uc->uc_mcontext.gregs[REG_RIP];
#endif
    if (write(result_fd, &result, sizeof(result)) != sizeof(result)) _exit(3);
    _exit(0);
}

static struct outcome invoke(transfer_fn transfer, void *target) {
    int fds[2];
    if (pipe(fds)) fail("pipe");
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (!child) {
        close(fds[0]);
        result_fd = fds[1];
        struct sigaction action = {.sa_sigaction = fault_handler, .sa_flags = SA_SIGINFO};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, NULL) || sigaction(SIGSEGV, &action, NULL) ||
                sigaction(SIGBUS, &action, NULL)) _exit(4);
        alarm(5);
        struct outcome result = {.value = transfer(target)};
        if (write(fds[1], &result, sizeof(result)) != sizeof(result)) _exit(5);
        _exit(0);
    }
    close(fds[1]);
    struct outcome result;
    size_t done = 0;
    while (done != sizeof(result)) {
        ssize_t size = read(fds[0], (char *)&result + done, sizeof(result) - done);
        if (size < 0 && errno == EINTR) continue;
        if (size <= 0) fail("missing child outcome");
        done += (size_t)size;
    }
    close(fds[0]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
        fail("child failed");
    return result;
}

/* Do not replace these two comparisons with an alignment/known-entry check.
 * Even an unaligned address inside transient text is permitted by this policy
 * (the subsequent CPU instruction fetch can independently fault).
 */
static bool software_accepts(const void *pointer) {
    uintptr_t target = (uintptr_t)pointer;
    if (target >= (uintptr_t)transient_page && target < (uintptr_t)transient_page + page_size)
        return true;
    if (target < (uintptr_t)normal_page || target >= (uintptr_t)normal_page + page_size)
        return false;
    uint32_t first, second;
    memcpy(&first, pointer, sizeof(first));
    memcpy(&second, (const char *)pointer + 4, sizeof(second));
    return first == MAGIC0 && second == MAGIC1;
}

static unsigned char *allocate_page(void) {
    /* Include one readable padding page: the exact old marker predicate can
     * read beyond the half-open normal interval. No executable permission here.
     */
    void *page = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) fail("mmap");
    return page;
}

static void emit_word(unsigned char **cursor, uint32_t word) {
    memcpy(*cursor, &word, sizeof(word));
    *cursor += sizeof(word);
}

static void emit_target(unsigned char *cursor, bool hardware_landing, bool software_marker,
                        bool wrong_second) {
#if defined(__aarch64__)
    if (hardware_landing) emit_word(&cursor, UINT32_C(0xd50324df)); /* BTI jc */
#else
    if (hardware_landing) emit_word(&cursor, UINT32_C(0xfa1e0ff3)); /* ENDBR64 */
#endif
    if (software_marker) {
        emit_word(&cursor, MAGIC0);
        emit_word(&cursor, wrong_second ? UINT32_C(0x90909090) : MAGIC1);
    }
#if defined(__aarch64__)
    emit_word(&cursor, UINT32_C(0x52800540)); /* mov w0, #42 */
    emit_word(&cursor, UINT32_C(0xd65f03c0)); /* ret */
#else
    static const unsigned char body[] = {0xb8, 42, 0, 0, 0, 0xc3};
    memcpy(cursor, body, sizeof(body));
#endif
}

static int make_executable(unsigned char *page, bool guarded) {
    __builtin___clear_cache((char *)page, (char *)page + page_size);
    int protections = PROT_READ | PROT_EXEC;
#if defined(__aarch64__)
    if (guarded) protections |= PROT_BTI;
#else
    (void)guarded; /* There is no Linux user-IBT PROT_* API. */
#endif
    return mprotect(page, page_size, protections);
}

static void report_case(const char *name, const char *transfer_name,
                        transfer_fn transfer, void *target, int *mismatches) {
    bool policy = software_accepts(target);
    struct outcome result = invoke(transfer, target);
    bool executed = !result.signal_number && result.value == 42;
    /* Cases below use valid executable instruction starts, so a difference is
     * a meaningful counterexample, not merely an invalid instruction fault.
     */
    if (policy != executed) (*mismatches)++;
    printf("{\"kind\":\"case\",\"name\":\"%s\",\"transfer\":\"%s\","
           "\"software_accepts\":%s,\"raw_transfer_executed\":%s,\"signal\":%d,"
           "\"si_code\":%d,\"value\":%d,\"fault_pc\":\"0x%" PRIxPTR "\","
           "\"fault_address\":\"0x%" PRIxPTR "\",\"pstate_btype\":%" PRIuPTR "}\n",
           name, transfer_name, policy ? "true" : "false", executed ? "true" : "false",
           result.signal_number, result.signal_code, result.value, result.pc, result.address,
           result.branch_state);
}

int main(int argc, char **argv) {
    bool require_backend = argc == 2 && strcmp(argv[1], "--require-backend") == 0;
    if (argc > 1 && !require_backend) {
        fprintf(stderr, "usage: %s [--require-backend]\n", argv[0]);
        return 2;
    }
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) fail("setrlimit");
    long size = sysconf(_SC_PAGESIZE);
    if (size <= 0) fail("sysconf");
    page_size = (size_t)size;
    bool cpu_capability = false;
#if defined(__aarch64__)
    unsigned long hwcaps = getauxval(AT_HWCAP2);
    cpu_capability = !!(hwcaps & HWCAP2_BTI);
    printf("{\"kind\":\"capability\",\"arch\":\"%s\",\"page_size\":%zu,"
           "\"hwcap2\":\"0x%lx\",\"bti\":%s}\n", ARCH_NAME, page_size, hwcaps,
           cpu_capability ? "true" : "false");
#else
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    cpu_capability = !!(edx & (1u << 20));
    unsigned long shadow_status = 0;
    errno = 0;
    long shadow_result = syscall(SYS_arch_prctl, ARCH_SHSTK_STATUS, &shadow_status);
    int shadow_errno = errno;
    printf("{\"kind\":\"capability\",\"arch\":\"%s\",\"page_size\":%zu,"
           "\"cpuid_ibt\":%s,\"cpuid_shstk\":%s,\"shstk_status_rc\":%ld,"
           "\"shstk_status_errno\":%d,\"shstk_status\":%lu}\n", ARCH_NAME, page_size,
           cpu_capability ? "true" : "false", ecx & (1u << 7) ? "true" : "false",
           shadow_result, shadow_errno, shadow_status);
#endif
    normal_page = allocate_page();
    transient_page = allocate_page();
    outside_page = allocate_page();
    unsigned char *pages[] = {normal_page, transient_page, outside_page};
    for (unsigned i = 0; i < 3; i++) {
        emit_target(pages[i], false, true, false);
        emit_target(pages[i] + 64, true, false, false);
        emit_target(pages[i] + 128, false, false, false);
        emit_target(pages[i] + 192, true, true, false);
    }
    errno = 0;
    int guarded_result = make_executable(normal_page, true);
    int guarded_errno = errno;
    bool guarded_mapping = guarded_result == 0;
    if (guarded_result && make_executable(normal_page, false)) fail("mprotect fallback");
    if (make_executable(transient_page, false) || make_executable(outside_page, guarded_mapping))
        fail("mprotect");
    struct outcome valid = invoke(probe_call, normal_page + 64);
    struct outcome invalid = invoke(probe_call, normal_page + 128);
    if (make_executable(normal_page, false)) fail("mprotect guard control");
    struct outcome unguarded = invoke(probe_call, normal_page + 128);
    if (make_executable(normal_page, guarded_mapping)) fail("mprotect restore guard");
#if defined(__aarch64__)
    /* Native Linux reports ILL_ILLOPC; QEMU 10.0.11 reports ILL_ILLOPN.
     * Keep the exact signal code in evidence. The same instruction must also
     * execute without PROT_BTI: a generic illegal-instruction fault is not
     * sufficient to demonstrate guarded-page enforcement.
     */
    bool expected_fault = invalid.signal_number == SIGILL &&
                          (invalid.signal_code == ILL_ILLOPC || invalid.signal_code == ILL_ILLOPN) &&
                          invalid.pc == (uintptr_t)normal_page + 128 &&
                          !unguarded.signal_number && unguarded.value == 42;
#else
    /* Linux's #CP delivery is SIGSEGV/SEGV_CPERR (10), not a generic SIGSEGV. */
    bool expected_fault = invalid.signal_number == SIGSEGV && invalid.signal_code == 10 &&
                          invalid.pc == (uintptr_t)normal_page + 128;
#endif
    bool enforced = cpu_capability && guarded_mapping && !valid.signal_number &&
                    valid.value == 42 && expected_fault;
    printf("{\"kind\":\"enforcement\",\"mprotect_rc\":%d,\"mprotect_errno\":%d,"
           "\"valid_landing_executes\":%s,\"invalid_landing_faults\":%s,"
           "\"unguarded_invalid_executes\":%s,\"invalid_signal\":%d,\"invalid_si_code\":%d,"
           "\"enforced\":%s}\n", guarded_result, guarded_errno,
           !valid.signal_number && valid.value == 42 ? "true" : "false",
           expected_fault ? "true" : "false",
           !unguarded.signal_number && unguarded.value == 42 ? "true" : "false",
           invalid.signal_number, invalid.signal_code, enforced ? "true" : "false");
    struct outcome elf_valid = invoke(probe_call, probe_elf_landing);
    struct outcome elf_invalid = invoke(probe_call, probe_elf_plain);
    printf("{\"kind\":\"elf_loader\",\"valid_landing_executes\":%s,"
           "\"invalid_landing_signal\":%d,\"invalid_landing_si_code\":%d,"
           "\"invalid_landing_fault_pc_matches\":%s}\n",
           !elf_valid.signal_number && elf_valid.value == 42 ? "true" : "false",
           elf_invalid.signal_number, elf_invalid.signal_code,
           elf_invalid.pc == (uintptr_t)probe_elf_plain ? "true" : "false");
    int mismatches = 0;
    report_case("normal_software_marker", "call", probe_call, normal_page, &mismatches);
    report_case("normal_hardware_only", "call", probe_call, normal_page + 64, &mismatches);
    report_case("normal_plain", "call", probe_call, normal_page + 128, &mismatches);
    report_case("normal_prefixed_marker", "call", probe_call, normal_page + 192, &mismatches);
    report_case("normal_prefixed_marker_interior", "jump", probe_jump, normal_page + 196, &mismatches);
    report_case("normal_plain", "jump", probe_jump, normal_page + 128, &mismatches);
    report_case("normal_plain", "return", probe_return, normal_page + 128, &mismatches);
    report_case("normal_software_marker", "return", probe_return, normal_page, &mismatches);
    report_case("transient_plain_unguarded", "call", probe_call, transient_page + 128, &mismatches);
    report_case("transient_software_marker", "jump", probe_jump, transient_page, &mismatches);
    report_case("external_hardware_landing", "call", probe_call, outside_page + 64, &mismatches);
    report_case("trusted_runtime_landing", "jump", probe_jump, outside_page + 192, &mismatches);
    if (make_executable(transient_page, true) == 0)
        report_case("transient_plain_guarded", "call", probe_call, transient_page + 128, &mismatches);
    printf("{\"kind\":\"policy_boundaries\",\"transient_unaligned_accepted\":%s,"
           "\"transient_last_byte_accepted\":%s,\"transient_end_rejected\":%s}\n",
           software_accepts(transient_page + 1) ? "true" : "false",
           software_accepts(transient_page + page_size - 1) ? "true" : "false",
           !software_accepts(transient_page + page_size) ? "true" : "false");
    printf("{\"kind\":\"summary\",\"raw_hardware_policy_mismatches\":%d,"
           "\"enforcement_demonstrated\":%s,\"teapot_backend_supported\":false,"
           "\"selected_backend\":\"software\"}\n", mismatches, enforced ? "true" : "false");
    for (unsigned i = 0; i < 3; i++) if (munmap(pages[i], page_size * 2)) fail("munmap");
    /* An explicit request must not silently select an unenforced backend. */
    return require_backend ? 77 : 0;
}
