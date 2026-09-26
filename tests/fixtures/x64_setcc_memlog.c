#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
static struct entry history[32];
struct entry *memory_history_top = history;
unsigned char scratchpad[1 << 20] __attribute__((aligned(64)));
uintptr_t old_rsp;
extern uint64_t run_original(unsigned char *, uint64_t);
extern uint64_t run_rewritten(unsigned char *, uint64_t);

int main(void) {
    const unsigned flag_bits[] = {0, 2, 4, 6, 7, 11};
    unsigned seen[16] = {0};
    for (unsigned combination = 0; combination < 64; ++combination) {
        uint64_t flags = 0x202;
        unsigned char expected[16], actual[16];
        for (unsigned i = 0; i < 6; ++i)
            if (combination & (1u << i)) flags |= 1u << flag_bits[i];
        memset(expected, 0xa5, sizeof(expected));
        memset(actual, 0xa5, sizeof(actual));
        uint64_t ordinary_flags = run_original(expected, flags);
        memory_history_top = history;
        uint64_t rewritten_flags = run_rewritten(actual, flags);
        if (memcmp(actual, expected, sizeof(actual)) ||
            ((ordinary_flags ^ rewritten_flags) & 0x8d5) ||
            memory_history_top - history != 16) {
            fprintf(stderr, "SETcc values/flags/history failed: flags=%lx entries=%ld\n",
                    flags, (long)(memory_history_top - history));
            return 1;
        }
        for (unsigned i = 0; i < 16; ++i) {
            if (actual[i] > 1 || history[i].addr != actual + i ||
                history[i].size != 1 || (history[i].data & 255) != 0xa5)
                return 2;
            seen[i] |= 1u << actual[i];
        }
        while (memory_history_top != history) {
            struct entry *e = --memory_history_top;
            memcpy(e->addr, &e->data, e->size);
        }
        for (unsigned i = 0; i < 16; ++i)
            if (actual[i] != 0xa5) return 3;
    }
    for (unsigned i = 0; i < 16; ++i)
        if (seen[i] != 3) return 4;
    puts("all SETcc stores and rollback passed");
    return 0;
}

