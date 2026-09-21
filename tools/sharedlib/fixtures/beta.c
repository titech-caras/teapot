#include <execinfo.h>

extern int alpha_counter;
int beta_bias = 11;
int beta_unwind_depth;

int beta_transform(int value) {
    void *frames[16];
    beta_unwind_depth = backtrace(frames, 16);
    beta_bias += 2;
    return value * 3 + beta_bias + alpha_counter;
}

int *beta_counter_address(void) {
    return &alpha_counter;
}
