#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ranges.h"

struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
static struct entry history[64];
struct entry *memory_history_top = history;
unsigned char scratchpad[1 << 20] __attribute__((aligned(64)));
uintptr_t old_rsp;
extern void run_original(unsigned char *);
extern void test_function(unsigned char *);

int main(void) {
    unsigned char original[128], actual[128], expected_log[128] = {0}, actual_log[128] = {0};
    memset(original, 0xa5, sizeof(original));
    memset(actual, 0xa5, sizeof(actual));
    for (unsigned i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i)
        memset(expected_log + ranges[i][0], 1, ranges[i][1]);
    run_original(original);
    test_function(actual);
    if (memcmp(actual, original, sizeof(actual))) return 1;
    for (struct entry *p = history; p < memory_history_top; ++p) {
        uintptr_t offset = (uintptr_t)p->addr - (uintptr_t)actual;
        if (!p->size || p->size > 8 || offset + p->size > sizeof(actual)) return 2;
        memset(actual_log + offset, 1, p->size);
    }
    if (memcmp(expected_log, actual_log, sizeof(actual_log))) return 3;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    for (unsigned i = 0; i < sizeof(actual); ++i)
        if (actual[i] != 0xa5) return 4;
    puts("x87 stores and rollback passed");
    return 0;
}
