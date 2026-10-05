/* The memory log of a store to one of two statics that share a name
 * (tests/test_symbol_references.py): it must name the stored static, so that
 * replaying it, as a rollback does, restores that static. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct entry { void *addr; uint64_t data; uint8_t size; uint8_t padding[7]; };
static struct entry history[8];
struct entry *memory_history_top = history;
unsigned char scratchpad[1 << 20] __attribute__((aligned(64)));
uintptr_t old_rsp;
/* Global names of the two statics, which the module defines. */
extern uint32_t store_target, other_static;
extern void test_function(uint32_t value);

int main(void) {
    store_target = 0x1111;
    other_static = 0x2222;
    test_function(0x5555);
    if (store_target != 0x5555 || other_static != 0x2222) {
        fprintf(stderr, "the store itself changed store_target %#x, other_static %#x\n",
                store_target, other_static);
        return 1;
    }
    if (memory_history_top - history != 1) {
        fprintf(stderr, "%ld log entries\n", (long)(memory_history_top - history));
        return 2;
    }
    printf("logged %p (%u bytes, old %#lx); store_target is %p, other_static %p\n",
           history[0].addr, history[0].size, (unsigned long)history[0].data,
           (void *)&store_target, (void *)&other_static);
    while (memory_history_top != history) {
        struct entry *entry = --memory_history_top;
        memcpy(entry->addr, &entry->data, entry->size);
    }
    printf("after the rollback: store_target %#x, other_static %#x\n", store_target, other_static);
    if (history[0].addr != (void *)&store_target) {
        fprintf(stderr, "the log names %p, not the stored static %p\n",
                history[0].addr, (void *)&store_target);
        return 3;
    }
    if (store_target != 0x1111 || other_static != 0x2222) {
        fprintf(stderr, "the rollback left store_target %#x, other_static %#x\n", store_target, other_static);
        return 4;
    }
    puts("the log names the stored static and the rollback restores it");
    return 0;
}
