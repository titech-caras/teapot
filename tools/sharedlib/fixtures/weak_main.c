#include <stdio.h>

extern int weak_probe(int);

int main(void)
{
    int value = weak_probe(CALLER_ID);
    printf("weak=%d caller=%d\n", value, CALLER_ID);
    return value != EXPECTED_WEAK + CALLER_ID;
}
