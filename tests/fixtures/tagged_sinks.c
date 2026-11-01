#include <stddef.h>
#include <stdio.h>

extern void tag_inputs(volatile size_t *, void (*volatile *)(void), int);
volatile int gate;
volatile size_t secret_index = 7;
volatile unsigned char destination[64];
void (*volatile indirect_target)(void);
__attribute__((noinline)) void target(void) { __asm__ volatile(""); }

int main(int argc, char **argv) {
    indirect_target = target;
    tag_inputs(&secret_index, &indirect_target, argc > 1 ? argv[1][0] - '0' : 0);
    if (gate)
        destination[secret_index] = 23;
    if (gate)
        indirect_target();
    printf("restored=%u\n", destination[7]);
    return destination[7] != 0;
}
