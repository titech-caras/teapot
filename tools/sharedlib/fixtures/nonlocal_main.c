#include <stdio.h>
#ifndef CALLER_ID
#define CALLER_ID 1
#endif
extern int library_probe(int);
int main(void) {
    int result = library_probe(CALLER_ID);
    printf("caller=%d probe=%d\n", CALLER_ID, result);
    return result != CALLER_ID + 42;
}
