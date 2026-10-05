/* Memory-log entries of the three- and two-register x64 forms, replayed by the real runtime.
 *
 * Each chain stores once in an outer checkpoint, then in an inner one, where
 * the window rolls back or the next entry's old-value load faults (the
 * runtime's SIGSEGV path). After the inner rollback it stores once more and
 * rolls the outer checkpoint back. The probes snapshot the data and the log's
 * length after each step; both forms must leave the same records, and every
 * rollback must restore the bytes the expected model gives. */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "checkpoint.h"
#include "signal_handler.h"

extern uint64_t max_checkpoints;
extern memory_history_t *memory_history_top;
extern uint32_t *guard_list_top;
uint32_t __guard_start__teapot__[1], __guard_end__teapot__[1];
uint32_t branch_counter;

void __asan_poison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }
void __asan_unpoison_memory_region(void const volatile *p, size_t n) { (void)p; (void)n; }

#define DATA 64
unsigned char data[DATA] __attribute__((aligned(16)));
/* Snapshots: after the outer store, after the inner rollback, after the outer rollback. */
unsigned char snapshots[3][DATA];
uint64_t entries[3];     /* the log's length at the same three points */
uint64_t data_address;   /* &data, for the probes' address registers */

typedef void (*probe_fn)(void);
struct chain {
    const char *name;
    probe_fn old_probe, new_probe;
    unsigned char expected[3][DATA];
    uint64_t expected_entries[3];
    int faults;              /* the inner rollback comes from an old-value load fault */
};
#include "cases.h"

static void initial(unsigned char *bytes) {
    for (unsigned i = 0; i < DATA; ++i) bytes[i] = (unsigned char)(i * 7 + 1);
}

static void run(probe_fn probe) {
    initial(data);
    memset(snapshots, 0xee, sizeof snapshots);
    memset(entries, 0xee, sizeof entries);
    checkpoint_cnt = 1;
    max_checkpoints = MAX_CHECKPOINTS;
    instruction_cnt = 0;
    memory_history_top = memory_history;
    guard_list_top = guard_list;
    branch_counter = 0;
    libcheckpoint_enabled = true;
    probe();
    assert(checkpoint_cnt == 1 && memory_history_top == memory_history);
    checkpoint_cnt = 0;
}

int main(void) {
    setup_signal_handler();
    data_address = (uint64_t)(uintptr_t)data;
    for (unsigned c = 0; c < sizeof chains / sizeof *chains; ++c) {
        const struct chain *chain = &chains[c];
        unsigned char a[3][DATA];
        uint64_t a_entries[3];
        uint64_t faults = simulation_statistics.rollback_reason[ROLLBACK_SIGSEGV];
        run(chain->old_probe);
        memcpy(a, snapshots, sizeof a);
        memcpy(a_entries, entries, sizeof a_entries);
        run(chain->new_probe);
        for (unsigned s = 0; s < 3; ++s) {
            if (memcmp(a[s], chain->expected[s], DATA) || memcmp(snapshots[s], chain->expected[s], DATA) ||
                    a_entries[s] != chain->expected_entries[s] || entries[s] != chain->expected_entries[s]) {
                fprintf(stderr, "%s snapshot %u: old %d new %d, entries %lu/%lu expected %lu\n", chain->name, s,
                        memcmp(a[s], chain->expected[s], DATA), memcmp(snapshots[s], chain->expected[s], DATA),
                        (unsigned long)a_entries[s], (unsigned long)entries[s],
                        (unsigned long)chain->expected_entries[s]);
                return 1;
            }
        }
        assert(simulation_statistics.rollback_reason[ROLLBACK_SIGSEGV] - faults == 2u * chain->faults);
    }
    printf("%u nested memory-log chains passed\n", (unsigned)(sizeof chains / sizeof *chains));
    return 0;
}
