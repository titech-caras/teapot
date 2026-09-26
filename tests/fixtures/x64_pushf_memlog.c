#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
static struct entry history[16];
struct entry *memory_history_top = history;
unsigned char scratchpad[1 << 20] __attribute__((aligned(64)));
uintptr_t old_rsp, runner_rsp, after_rsp;
extern uint64_t run_original(unsigned char *, uint64_t);
extern uint64_t run_rewritten(unsigned char *, uint64_t);

int main(void) {
    unsigned char original[512] __attribute__((aligned(16)));
    unsigned char actual[512] __attribute__((aligned(16)));
    const uint64_t flags[] = {0x202, 0x203, 0xad7, 0xed7};
    for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
        memset(original, 0xa5, sizeof(original));
        memset(actual, 0xa5, sizeof(actual));
        memory_history_top = history;
        uint64_t expected = run_original(original, flags[i]);
        if (after_rsp != (uintptr_t)original + 256) return 1;
        uint64_t got = run_rewritten(actual, flags[i]);
        if (after_rsp != (uintptr_t)actual + 256 || expected != got) return 2;
        if ((got & 0xcd5) != (flags[i] & 0xcd5)) return 3;
        const unsigned offset = 256 - 8 - WIDTH; /* CALL slot, then PUSHF. */
        if (memcmp(original + offset, actual + offset, WIDTH)) return 4;
        if (memory_history_top != history + 1) return 5;
        if (history[0].addr != actual + offset || history[0].size != WIDTH) return 6;
        if (memcmp(&history[0].data, "\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5", WIDTH)) return 7;
        --memory_history_top;
        memcpy(history[0].addr, &history[0].data, history[0].size);
        for (unsigned j = 0; j < sizeof(actual); ++j) {
            if (j >= 248 && j < 256) continue; /* The runner's CALL return address. */
            if (actual[j] != 0xa5) return 8;
        }
    }
    puts("PUSHF flags, stack and rollback passed");
    return 0;
}
