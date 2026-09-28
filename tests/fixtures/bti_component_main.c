#include <stdio.h>
#include <stdlib.h>

#ifndef BIAS
#define BIAS 0
#endif
extern int component_apply(int, int (*)(int));
__attribute__((noinline)) int component_callback(int value) {
    return value * 3 + BIAS;
}
int main(int argc, char **argv) {
    int value = argc > 1 ? atoi(argv[1]) : 4;
    printf("result=%d\n", component_apply(value, component_callback));
    return 0;
}
