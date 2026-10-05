/*
 * Speculative coverage through real nested windows (tests/test_coverage_execution.py).
 *
 * Each probe runs one chain built from Teapot's checkpoint, trampoline and
 * coverage-push emitters: the outer window pushes guard 0, the inner window
 * guard 1, and the outer window guard 2 after the inner rollback. The fuzzer is
 * this file's recording callbacks, which a COVERAGE runtime requires (it has no
 * fallback; a fuzzing build links libhfuzz). With a COVERAGE runtime each
 * rollback must hand it exactly the guards of the window it undoes, newest
 * first, after undoing the memory log; without COVERAGE (EXPECT_NO_COVERAGE)
 * the pushes reach nothing.
 */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>
#include "checkpoint.h"

extern uint64_t max_checkpoints;
extern memory_history_t *memory_history_top;
extern uint32_t *guard_list_top;
/* The guard section of the probes' module, three guards (the generated assembly). */
extern uint32_t __guard_start__teapot__[], __guard_end__teapot__[];
static uint64_t value, visits, expected_direction;
static unsigned events[8], event_count, normal_events;

/* This probe checks checkpoint machinery without adding ASan startup to it. */
void __asan_poison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }
void __asan_unpoison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }

/* The fuzzer numbers the guards once (honggfuzz: from 1). */
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    for (uint32_t *guard = start; guard < stop; ++guard)
        *guard = (uint32_t)(guard - start) + 1;
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    assert(guard >= __guard_start__teapot__ && guard < __guard_end__teapot__);
    assert(*guard == (uint32_t)(guard - __guard_start__teapot__) + 1);
    /* The memory log is undone before the fuzzer sees the window. */
    assert(value == (event_count == 0 ? 11 : 7));
    assert(event_count < sizeof(events) / sizeof(events[0]));
    events[event_count++] = (unsigned)(guard - __guard_start__teapot__);
}

/* The runtime's normal-path coverage, at the outermost checkpoint. */
void hfuzz_trace_pc(uint64_t pc) {
    (void)pc;
    normal_events++;
}

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
    assert(depth == 1 && checkpoint_cnt == 1 && value == 7);
    check_direction(direction, flags);
    /* The outer window pushed guard 0. */
    assert(guard_list_top == guard_list + 1 && guard_list[0] == 0 && event_count == 0);
    visits |= 1;
    logged_write(11);
}

void probe_inner(uint64_t depth, uint64_t direction, uint64_t flags) {
    assert(depth == 2 && checkpoint_cnt == 2 && value == 11);
    check_direction(direction, flags);
    /* The inner window pushed guard 1 above the outer window's guard. */
    assert(guard_list_top == guard_list + 2 && guard_list[0] == 0 && guard_list[1] == 1);
    visits |= 2;
    logged_write(99);
}

void probe_inner_restored(void) {
    assert(checkpoint_cnt == 1 && value == 11);
#ifdef EXPECT_NO_COVERAGE
    assert(event_count == 0);
#else
    /* The inner rollback replayed guard 1 alone and kept guard 0; the outer
     * window then pushed guard 2. */
    assert(event_count == 1 && events[0] == 1);
#endif
    assert(guard_list_top == guard_list + 2 && guard_list[0] == 0 && guard_list[1] == 2);
    visits |= 4;
}

void probe_finished(void) {
    assert(checkpoint_cnt == 0 && value == 7);
    assert(memory_history_top == memory_history && guard_list_top == guard_list);
#ifdef EXPECT_NO_COVERAGE
    assert(event_count == 0 && normal_events == 0);
#else
    /* The outer rollback replayed guards 2 and 0, newest first. */
    assert(event_count == 3 && events[1] == 2 && events[2] == 0);
    assert(normal_events == 1);
#endif
    assert(visits == 7);
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
    assert(__guard_end__teapot__ - __guard_start__teapot__ == 3);
    __sanitizer_cov_trace_pc_guard_init(__guard_start__teapot__, __guard_end__teapot__);
    for (unsigned i = 0; i < 6; ++i) {
        value = 7;
        visits = 0;
        event_count = normal_events = 0;
        expected_direction = i % 2;
        checkpoint_cnt = 0;
        max_checkpoints = MAX_CHECKPOINTS;
        instruction_cnt = 0;
        memory_history_top = memory_history;
        guard_list_top = guard_list;
        libcheckpoint_enabled = true;
        probes[i]((char *)stack + size - 4096);
        assert(visits == 15);
    }
    assert(munmap(stack, size) == 0);
    puts("6 coverage chains passed");
    return 0;
}
