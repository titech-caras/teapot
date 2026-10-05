/* Restore points inside two nested checkpoints of the real x64 runtime.
 *
 * Each case runs the register form (old) and the compare-first form (new) of
 * the same chain: an outer checkpoint, restore points, an inner checkpoint,
 * restore points until one rolls back, then restore points after the inner
 * rollback until the outer one rolls back too. The probes record, after every
 * restore point that falls through, the counter and the flags read right after
 * it, and the counter and depth after each rollback. cases.h holds the cases
 * and the expected records. */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "checkpoint.h"

extern uint64_t max_checkpoints;
extern memory_history_t *memory_history_top;
extern uint32_t *guard_list_top;
uint32_t __guard_start__teapot__[1], __guard_end__teapot__[1];
uint32_t branch_counter;

/* This probe checks checkpoint machinery without adding ASan startup to it. */
void __asan_poison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }
void __asan_unpoison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }

#define SLOTS 64
#define INNER_COUNTER 60
#define INNER_DEPTH 61
#define OUTER_COUNTER 62
#define OUTER_DEPTH 63
#define UNSET UINT64_MAX
uint64_t trace[SLOTS], ftrace[SLOTS];

typedef void (*probe_fn)(void);
struct chain {
    const char *name;
    probe_fn old_probe, new_probe;
    uint64_t start;
    uint64_t expected[SLOTS];   /* UNSET where nothing is recorded */
    uint64_t flags[SLOTS];      /* the flags set before each restore point */
};
#include "cases.h"

static void run(probe_fn probe, uint64_t start, uint64_t *counters, uint64_t *flags) {
    for (unsigned i = 0; i < SLOTS; ++i) trace[i] = ftrace[i] = UNSET;
    /* Depth 1 as if nested already: the runtime's depth heuristic applies only at depth 0. */
    checkpoint_cnt = 1;
    max_checkpoints = MAX_CHECKPOINTS;
    instruction_cnt = start;
    memory_history_top = memory_history;
    guard_list_top = guard_list;
    branch_counter = 0;
    libcheckpoint_enabled = true;
    probe();
    assert(checkpoint_cnt == 1 && instruction_cnt == start);
    checkpoint_cnt = 0;
    memcpy(counters, trace, sizeof trace);
    memcpy(flags, ftrace, sizeof ftrace);
}

int main(void) {
    unsigned points = 0;
    for (unsigned c = 0; c < sizeof chains / sizeof *chains; ++c) {
        const struct chain *chain = &chains[c];
        uint64_t a[SLOTS], b[SLOTS], fa[SLOTS], fb[SLOTS];
        run(chain->old_probe, chain->start, a, fa);
        run(chain->new_probe, chain->start, b, fb);
        for (unsigned i = 0; i < SLOTS; ++i) {
            if (a[i] != chain->expected[i] || b[i] != chain->expected[i]) {
                fprintf(stderr, "%s slot %u: old %#lx new %#lx expected %#lx\n", chain->name, i,
                        (unsigned long)a[i], (unsigned long)b[i], (unsigned long)chain->expected[i]);
                return 1;
            }
            if (i < INNER_COUNTER && chain->expected[i] != UNSET) {
                /* Flags live across the point: the wrapper hands them back. */
                assert((fa[i] & 0x8d5) == (chain->flags[i] & 0x8d5));
                assert((fb[i] & 0x8d5) == (chain->flags[i] & 0x8d5));
                points++;
            }
        }
    }
    printf("%u nested restore point chains passed (%u points fell through)\n",
           (unsigned)(sizeof chains / sizeof *chains), points);
    return 0;
}
