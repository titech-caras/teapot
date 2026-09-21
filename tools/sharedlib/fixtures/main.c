#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int alpha_counter;
extern int beta_bias;
extern int beta_unwind_depth;
extern int alpha_table[];
extern int alpha_step(int);
extern int alpha_verify_pointer(void);
extern int *beta_counter_address(void);

int main(int argc, char **argv) {
    int value = argc > 1 ? atoi(argv[1]) : 2;
    int result = alpha_step(value);
    int identity = beta_counter_address() == &alpha_counter;
    int alignment = ((uintptr_t)alpha_table & 63) == 0;
    printf("result=%d alpha=%d beta=%d identity=%d pointer=%d aligned=%d unwind=%d\n",
           result, alpha_counter, beta_bias, identity, alpha_verify_pointer(),
           alignment, beta_unwind_depth);
    return !(identity && alpha_verify_pointer() && alignment && beta_unwind_depth >= 6);
}
