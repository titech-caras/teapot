/* Exercise real activation, including its child enforcing PROT_BTI. Only the
 * unrelated libcheckpoint initialization entry is stubbed in this gate test. */
#define _GNU_SOURCE
#include "checkpoint.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

uint64_t checkpoint_cnt;
void teapot_aarch64_bti_activate(void);
void restore_checkpoint_MALFORMED_INDIRECT_BR(void) { _exit(99); }
LIBCHECKPOINT_PRESERVE_MOST void libcheckpoint_enable(int argc, char **argv) {
    (void)argc; (void)argv;
}

unsigned long __real_getauxval(unsigned long);
unsigned long __wrap_getauxval(unsigned long type) {
    const char *mode = getenv("BTI_GATE_TEST");
    if (mode && !strcmp(mode, "no-hwcap") && type == AT_HWCAP2) return 0;
    return __real_getauxval(type);
}

int __real_mprotect(void *, size_t, int);
int __wrap_mprotect(void *addr, size_t size, int prot) {
    const char *mode = getenv("BTI_GATE_TEST");
    if (mode && !strcmp(mode, "reject-protection")) { errno = EINVAL; return -1; }
    if (mode && !strcmp(mode, "ignore-protection")) prot &= ~0x10;
    return __real_mprotect(addr, size, prot);
}

int main(void) {
    teapot_aarch64_bti_activate();
    return 0;
}
