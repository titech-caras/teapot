#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void start(void) {
    (void)write(2, "library constructor\n", 20);
}

__attribute__((destructor)) static void finish(void) {
    (void)write(2, "library destructor\n", 19);
}

__attribute__((noinline)) int component_apply(int value, int (*callback)(int)) {
    /* Exercise the normal/transient boundary in both directions. */
    if (value & 1)
        return callback(value + 3) + 5;
    return callback(value - 2) - 7;
}
