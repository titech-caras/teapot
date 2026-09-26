#include <stdio.h>
#ifndef CALLER_ID
#define CALLER_ID 1
#endif
extern int api(int);
extern int old_api(int);
__asm__(".symver old_api,api@LIBTEST_1");
int main(void) {
    int old = old_api(CALLER_ID), current = api(CALLER_ID);
    printf("caller=%d old=%d default=%d\n", CALLER_ID, old, current);
    return old != CALLER_ID + 10 || current != CALLER_ID + 20;
}
