/* The nested_checkpoint.c chains, repeated inside each root to exercise hash
 * octaves. The code under test is emitted by the real checkpoint/trampoline
 * patches and runs the real runtime; the C hooks only check and log it. */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>
#include "checkpoint.h"
#include "nested_policy.h"
#include "nested_model.h"

extern memory_history_t *memory_history_top;
extern uint32_t *guard_list_top;
extern uintptr_t checkpoint_target_metadata[];
uint32_t __guard_start__teapot__[1], __guard_end__teapot__[1];
static uint64_t value, visits, expected_direction, index;
static unsigned attempts, entered;
static uint32_t generation;
static struct teapot_nested_site reference;
static struct teapot_nested_site *site;
static uint64_t trace = UINT64_C(0xcbf29ce484222325);

void __asan_init(void) {}
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
    site = (void *)checkpoint_target_metadata[CHECKPOINT_TARGET_BRANCH_COUNTER_ADDR / 8];
    assert(checkpoint_target_metadata[CHECKPOINT_TARGET_OUTCOME / 8] == expected_direction);
    assert(checkpoint_target_metadata[CHECKPOINT_TARGET_SITE_INDEX / 8] == index);
    assert(model_decision(&reference, index, expected_direction, 0, &generation, teapot_nested_seed_word));
    assert(teapot_nested_root_gen == generation);
    visits |= 1;
    logged_write(11);
    instruction_cnt = 29;
}

void probe_inner(uint64_t depth, uint64_t direction, uint64_t flags) {
    assert(depth == 2 && checkpoint_cnt == 2 && instruction_cnt == 29);
    assert(value == 11 && memory_history_top == memory_history + 1);
    check_direction(direction, flags);
    visits |= 2;
    ++entered;
    logged_write(99);
    instruction_cnt = 41;
}

int probe_inner_restored(void) {
    assert(checkpoint_cnt == 1 && instruction_cnt == 29 && value == 11);
    assert(memory_history_top == memory_history + 1 && memory_history[0].addr == &value);
    assert(checkpoint_target_metadata[CHECKPOINT_TARGET_OUTCOME / 8] == expected_direction);
    int expected = model_decision(&reference, index, expected_direction, 1, &generation, teapot_nested_seed_word);
    assert(entered == (unsigned)expected);
    assert(site->gen == reference.gen && site->tree[0] == reference.tree[0] && site->tree[1] == reference.tree[1]);
    printf("decision %" PRIu64 " %u %" PRIu64 " %d\n", index, attempts, expected_direction, expected);
    trace = (trace ^ (index * 4 + expected_direction * 2 + entered)) * UINT64_C(0x100000001b3);
    entered = 0;
    visits |= 4;
    return ++attempts < 32;
}

void probe_finished(void) {
    assert(checkpoint_cnt == 0 && instruction_cnt == 17 && value == 7);
    assert(memory_history_top == memory_history && visits == 7 && attempts == 32);
    visits |= 8;
}

#include "cases.h"

int main(int argc, char **argv) {
    libcheckpoint_enable(argc, argv);
    size_t size = 2 * AARCH64_SHADOW_STACK_SIZE;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    for (index = 0; index < sizeof(probes) / sizeof(*probes); ++index) {
        value = 7;
        visits = attempts = entered = 0;
        reference = (struct teapot_nested_site){0};
        expected_direction = index % 2;
        instruction_cnt = 17;
        memory_history_top = memory_history;
        guard_list_top = guard_list;
        probes[index]((char *)stack + size - 4096);
        assert(visits == 15);
    }
    assert(simulation_statistics.ckpt_depth[1] > 0);
    printf("seed=%016" PRIx64 " trace=%016" PRIx64 " depth2=%" PRIu64 "\n",
           teapot_nested_seed_word, trace, simulation_statistics.ckpt_depth[1]);
    assert(munmap(stack, size) == 0);
    return 0;
}
