#define _GNU_SOURCE
#include <assert.h>
#include <asm/prctl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

unsigned char scratchpad[SCRATCHPAD_SIZE] __attribute__((aligned(16)));
unsigned char dift_reg_tags[48], dift_reg_queued_tags[48];
unsigned char dift_reg_queue_pending[8];
struct history_entry { unsigned char *addr; uint64_t data; unsigned char size, pad[7]; };
struct history_entry history[4096], *memory_history_top = history;
struct state { uint64_t ax, si, di, cx, flags, other[10], unused, redzone[16]; };
struct test_case {
    void (*original)(struct state *), (*common)(struct state *);
    void (*history)(struct state *);
    unsigned width, address_size, segment;
    char kind;
};
#include "cases.h"

static unsigned char *data, *tags;
static unsigned char original[4096], expected_data[4096], initial_tags[4096], expected_tags[4096];
static const unsigned char initial_regs[48] = {[0]=1, [2]=2, [4]=4, [5]=8};
static volatile sig_atomic_t faults, skip_fault;

static void handle_fault(int sig, siginfo_t *info, void *context) {
    (void)sig;
    if ((uintptr_t)info->si_addr != (uintptr_t)data + 4096) _exit(20);
    ++faults;
    if (skip_fault) {
        ucontext_t *uc = context;
        uc->uc_mcontext.gregs[REG_RIP] += 3; /* REP MOVSQ, no other prefixes. */
    } else if (mprotect(data+4096, 4096, PROT_READ|PROT_WRITE)) _exit(21);
}

static void model(const struct test_case *test, const struct state *in, const struct state *out,
                  unsigned char *regs) {
    uint64_t count = in->cx - out->cx;
    if (test->address_size == 4) count = (uint32_t)count;
    if (!count) return;
    int step = (in->flags & 0x400) ? -(int)test->width : (int)test->width;
    intptr_t si = test->segment ? in->si : (intptr_t)(uint32_t)in->si - (intptr_t)data;
    intptr_t di = (intptr_t)(uint32_t)in->di - (intptr_t)data;
    if (test->address_size == 4 && test->segment) si = (uint32_t)si;
    unsigned char base = regs[2], tag = 0;
    if (test->kind == 'm' || test->kind == 'l' || test->kind == 'c') base |= regs[4];
    if (test->kind != 'l') base |= regs[5];
    if (test->kind == 's' || test->kind == 't') base |= regs[0];
    for (uint64_t n = 0; n < count; ++n, si += step, di += step) {
        tag = base;
        if (test->kind == 'm' || test->kind == 'l' || test->kind == 'c')
            for (unsigned j = 0; j < test->width; ++j) tag |= expected_tags[si+j];
        if (test->kind == 'c' || test->kind == 't')
            for (unsigned j = 0; j < test->width; ++j) tag |= expected_tags[di+j];
        if (test->kind == 'm' || test->kind == 's')
            memset(expected_tags+di, tag, test->width);
        if (test->kind == 'c' || test->kind == 't') base = tag;
    }
    if (test->kind == 'l') regs[0] = tag | (test->width < 4 ? regs[0] : 0);
    if (test->kind == 'c' || test->kind == 't') {
        regs[2] = regs[5] = tag;
        if (test->kind == 'c') regs[4] = tag;
    } else {
        if (test->kind == 'm' || test->kind == 'l') regs[4] |= regs[2];
        if (test->kind != 'l') regs[5] |= regs[2];
    }
}

int main(void) {
    data = mmap((void *)0x31000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    tags = mmap((void *)0x131000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(data == (void *)0x31000000 && tags == (void *)0x131000000);
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, data) == 0);
    for (unsigned i = 0; i < 4096; ++i) {
        original[i] = i % 7;
        initial_tags[i] = (i % 5) ? 1u << (i % 8) : 0;
    }
    for (unsigned t = 0; t < sizeof(cases)/sizeof(*cases); ++t) {
        const struct test_case *test = &cases[t];
        for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned count = 0; count <= 4; ++count)
        for (int overlap = -1; overlap <= 2; ++overlap) {
            struct state in = {.ax=0x0102030405060000ULL, .cx=count,
                               .flags=0xad7 | (direction ? 0x400 : 0)};
            in.si = test->segment ? 128 : (uintptr_t)(data+128);
            in.di = (uintptr_t)(data+128+(overlap == 2 ? 96 : overlap*(int)test->width));
            if (test->address_size == 4) {
                in.si |= 0x123400000000ULL;
                in.di |= 0x234500000000ULL;
                in.cx |= 0x345600000000ULL;
            }
            struct state expected = in;
            unsigned char expected_regs[48];
            memcpy(data, original, 4096);
            test->original(&expected);
            memcpy(expected_data, data, 4096);
            memcpy(expected_tags, initial_tags, 4096);
            memcpy(expected_regs, initial_regs, 48);
            model(test, &in, &expected, expected_regs);
            void (*runners[])(struct state *) = {test->common, test->history};
            for (unsigned mode = 0; mode < 2; ++mode) {
                struct state actual = in;
                memcpy(data, original, 4096);
                memcpy(tags, initial_tags, 4096);
                memcpy(dift_reg_tags, initial_regs, 48);
                memory_history_top = history;
                runners[mode](&actual);
                if (memcmp(&actual, &expected, sizeof(actual)) || memcmp(data, expected_data, 4096) ||
                    memcmp(tags, expected_tags, 4096) || memcmp(dift_reg_tags, expected_regs, 48)) {
                    fprintf(stderr, "case=%u width=%u addr=%u kind=%c seg=%u DF=%u count=%u overlap=%d mode=%u state=%d data=%d tags=%d regs=%d\n",
                            t, test->width, test->address_size, test->kind, test->segment,
                            direction, count, overlap, mode,
                            memcmp(&actual, &expected, sizeof(actual)), memcmp(data, expected_data, 4096),
                            memcmp(tags, expected_tags, 4096), memcmp(dift_reg_tags, expected_regs, 48));
                    return 1;
                }
                if (mode == 1) {
                    while (memory_history_top != history) {
                        struct history_entry *entry = --memory_history_top;
                        assert(entry->size == 1 && entry->addr >= tags && entry->addr < tags+4096);
                        memcpy(entry->addr, &entry->data, entry->size);
                    }
                    assert(memcmp(tags, initial_tags, 4096) == 0);
                } else assert(memory_history_top == history);
            }
        }
    }
    /* A fault either resumes the same hardware REP or skips its unfinished
       suffix. The post patch must tag exactly the completed prefix in both. */
    struct sigaction action = {.sa_sigaction=handle_fault, .sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    for (unsigned t = 0; t < sizeof(cases)/sizeof(*cases); ++t) {
        const struct test_case *test = &cases[t];
        if (test->kind != 'm' || test->width != 8 || test->address_size != 8 || test->segment) continue;
        void (*runners[])(struct state *) = {test->original, test->common, test->history};
        for (skip_fault = 0; skip_fault < 2; ++skip_fault) {
            struct state expected = {0};
            for (unsigned mode = 0; mode < 3; ++mode) {
                assert(mprotect(data+4096, 4096, PROT_READ|PROT_WRITE) == 0);
                memset(data, 0x31, 8192);
                memset(tags, 0, 8192);
                memset(tags+4080, 0x10, 8);
                memset(tags+4088, 0x20, 8);
                memset(tags+4096, 0x40, 8);
                memset(tags+4104, 0x80, 8);
                memcpy(dift_reg_tags, initial_regs, 48);
                memory_history_top = history;
                struct state actual = {.si=(uintptr_t)(data+4080), .di=(uintptr_t)(data+128),
                                       .cx=4, .flags=0x202};
                faults = 0;
                assert(mprotect(data+4096, 4096, PROT_NONE) == 0);
                runners[mode](&actual);
                assert(faults == 1 && actual.cx == (skip_fault ? 2 : 0));
                if (!mode) expected = actual;
                else {
                    assert(memcmp(&actual, &expected, sizeof(actual)) == 0);
                    unsigned completed = skip_fault ? 2 : 4;
                    for (unsigned i = 0; i < 32; ++i)
                        assert(tags[128+i] == (i < completed*8 ? (14 | (0x10 << (i/8))) : 0));
                }
            }
        }
    }
    assert(mprotect(data+4096, 4096, PROT_READ|PROT_WRITE) == 0);
    /* Address-size overrides wrap the index, not the FS/GS-adjusted address.
       Place both sides of that wrap, including their distinct XOR partners. */
    unsigned char *high = mmap((void *)0x130fff000, 4096, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *high_tags = mmap((void *)0x30fff000, 4096, PROT_READ|PROT_WRITE,
                                   MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(high == (void *)0x130fff000 && high_tags == (void *)0x30fff000);
    for (unsigned t = 0; t < sizeof(cases)/sizeof(*cases); ++t) {
        const struct test_case *test = &cases[t];
        if ((test->kind != 'm' && test->kind != 'l') || test->width != 8 ||
            test->address_size != 4 || !test->segment) continue;
        void (*runners[])(struct state *) = {test->original, test->common, test->history};
        for (unsigned direction = 0; direction < 2; ++direction) {
            struct state expected = {0};
            for (unsigned mode = 0; mode < 3; ++mode) {
                memset(high+4088, 0x55, 8);
                memset(high_tags+4088, 0x10, 8);
                memset(data, 0x66, 8);
                memset(tags, 0x20, 8);
                memset(tags+112, 0, 32);
                memcpy(dift_reg_tags, initial_regs, 48);
                memory_history_top = history;
                struct state actual = {.si=0x123400000000ULL | (direction ? 0 : 0xfffffff8),
                                       .di=(uintptr_t)(data+128), .cx=0x345600000002ULL,
                                       .flags=0x202 | (direction ? 0x400 : 0)};
                runners[mode](&actual);
                if (!mode) expected = actual;
                else {
                    assert(memcmp(&actual, &expected, sizeof(actual)) == 0);
                    if (test->kind == 'l') assert(dift_reg_tags[0] == (direction ? 0x16 : 0x26));
                    else {
                        for (unsigned i = 0; i < 8; ++i) {
                            assert(tags[128+i] == (direction ? 0x2e : 0x1e));
                            assert(tags[(direction ? 120 : 136)+i] == (direction ? 0x1e : 0x2e));
                        }
                    }
                }
            }
        }
    }
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, 0) == 0);
    puts("REP values, tags, flags, all-live spills, red zone and history passed");
    return 0;
}
