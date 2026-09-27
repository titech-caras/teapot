#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include "checkpoint.h"

extern uint64_t max_checkpoints;
extern memory_history_t *memory_history_top;
extern uint32_t *guard_list_top;
uint32_t __guard_start__teapot__[1], __guard_end__teapot__[1];
static uint64_t value, visits, expected_direction;

/* This probe checks checkpoint machinery without adding ASan startup to it. */
void __asan_poison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }
void __asan_unpoison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }

static void check_direction(uint64_t direction, uint64_t flags) {
    assert(direction == expected_direction);
#if defined(__aarch64__)
    assert(((flags >> 30) & 1) == expected_direction);
#else
    (void)flags;
#endif
}

static void logged_write(uint64_t next) {
    *memory_history_top++ = (memory_history_t){.addr = &value, .data = value, .size = 8};
    value = next;
}

void probe_outer(uint64_t depth, uint64_t direction, uint64_t flags) {
    assert(depth == 1 && checkpoint_cnt == 1 && instruction_cnt == 17);
    assert(value == 7 && memory_history_top == memory_history);
    check_direction(direction, flags);
    visits |= 1;
    logged_write(11);
    instruction_cnt = 29;
}

void probe_inner(uint64_t depth, uint64_t direction, uint64_t flags) {
    assert(depth == 2 && checkpoint_cnt == 2 && instruction_cnt == 29);
    assert(value == 11 && memory_history_top == memory_history + 1);
    check_direction(direction, flags);
    visits |= 2;
    logged_write(99);
    instruction_cnt = 41;
}

void probe_inner_restored(void) {
    assert(checkpoint_cnt == 1 && instruction_cnt == 29 && value == 11);
    assert(memory_history_top == memory_history + 1);
    visits |= 4;
}

void probe_finished(void) {
    assert(checkpoint_cnt == 0 && instruction_cnt == 17 && value == 7);
    assert(memory_history_top == memory_history && visits == 7);
    visits |= 8;
}

#define PROBE(n, t) extern void probe_##n##_##t(void *);
PROBE(0, 0) PROBE(0, 1) PROBE(1, 0) PROBE(1, 1) PROBE(2, 0) PROBE(2, 1)

int main(void) {
    void (*probes[])(void *) = {
        probe_0_0, probe_0_1, probe_1_0, probe_1_1, probe_2_0, probe_2_1};
    size_t size = 2 * AARCH64_SHADOW_STACK_SIZE;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    for (unsigned i = 0; i < 6; ++i) {
        value = 7;
        visits = 0;
        expected_direction = i % 2;
        checkpoint_cnt = 0;
        max_checkpoints = MAX_CHECKPOINTS;
        instruction_cnt = 17;
        memory_history_top = memory_history;
        guard_list_top = guard_list;
        libcheckpoint_enabled = true;
        probes[i]((char *)stack + size - 4096);
        assert(visits == 15);
    }
    assert(munmap(stack, size) == 0);
    puts("6 nested checkpoint chains passed (0/1/2 spare registers, both directions)");
    return 0;
}
