/* Memory-log entries of real calls: each call's return-address slot, logged
 * before the call writes it, replays back to its original bytes. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
static struct entry history[8];
struct entry *memory_history_top = history;
unsigned char scratchpad[1 << 20] __attribute__((aligned(64)));
uintptr_t old_rsp, runner_rsp, after_rsp;
uint64_t calls, return_addresses[8];
extern void run_rewritten(unsigned char *stack_top);
static unsigned char stack[4096] __attribute__((aligned(16)));

int main(void) {
    memset(stack, 0xa5, sizeof stack);
    unsigned char *top = stack + sizeof stack;
    run_rewritten(top);
    unsigned char *slot = top - 16;   /* below the runner's return address */
    if (calls != 3) return 1;
    if (after_rsp != (uintptr_t)top) return 2;
    if (memory_history_top != history + 3) return 3;
    for (unsigned i = 0; i < 3; ++i)
        if (history[i].addr != slot || history[i].size != 8) return 4;
    /* The first call's slot held the stack's own bytes; each later one the return address before it. */
    if (history[0].data != 0xa5a5a5a5a5a5a5a5ull) return 5;
    if (history[1].data != return_addresses[0] || history[2].data != return_addresses[1]) return 6;
    uint64_t now;
    memcpy(&now, slot, 8);
    if (now != return_addresses[2]) return 7;
    while (memory_history_top != history) {
        struct entry *p = --memory_history_top;
        memcpy(p->addr, &p->data, p->size);
    }
    for (unsigned i = 0; i < sizeof stack - 8; ++i)
        if (stack[i] != 0xa5) return 8;
    puts("CALL return slots logged and replayed");
    return 0;
}
