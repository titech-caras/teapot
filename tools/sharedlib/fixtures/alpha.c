#include <stddef.h>

extern int beta_bias;
extern int beta_transform(int);
int alpha_counter = 7;
__attribute__((aligned(64))) int alpha_table[] = {3, 5, 8, 13};
int *alpha_shared_pointer = &beta_bias;
int (*alpha_dispatch)(int) = beta_transform;

int alpha_step(int value) {
    alpha_counter += value;
    return beta_transform(alpha_counter) + alpha_dispatch(2) + alpha_table[value & 3];
}

int alpha_verify_pointer(void) {
    return alpha_shared_pointer == &beta_bias && alpha_dispatch == beta_transform;
}
