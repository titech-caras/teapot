#include <stdio.h>
#include <stdlib.h>
#ifndef CALLER_ID
#define CALLER_ID 1
#endif
extern int library_use(int);
static void main_exit(void) { puts("executable main exit"); }
__attribute__((constructor)) static void main_init(void) { puts("executable constructor"); }
__attribute__((destructor)) static void main_fini(void) { puts("executable destructor"); }
int main(void) {
    int value = library_use(CALLER_ID);
    if (atexit(main_exit)) abort();
    printf("caller=%d value=%d\n", CALLER_ID, value);
    return value != CALLER_ID + 40;
}
