/* Two statics called target, in first.c and second.c, which a relaxed link
 * accesses gp-relative (tests/test_symbol_reference_execution.py). Each
 * access must reach its own file's static. Exit status: 0 if they all do;
 * 1 if a load reads the other static, 2 if an address computation yields it,
 * 3 or 4 if a store writes it. */
long first_get(void), second_get(void);
void first_set(long), second_set(long);
long *first_address(void), *second_address(void);

/* Linked before the statics: moves them away from the edge of the linker's
 * gp window, so that it relaxes their accesses to gp-relative ones. */
__attribute__((section(".sdata"), used)) static char window[256];

int main(void) {
    if (first_get() != 0x1111 || second_get() != 0x2222)
        return 1;
    if (first_address() == second_address() || *first_address() != 0x1111 || *second_address() != 0x2222)
        return 2;
    first_set(0x5555);
    if (first_get() != 0x5555 || second_get() != 0x2222 || *first_address() != 0x5555)
        return 3;
    second_set(0x6666);
    if (first_get() != 0x5555 || second_get() != 0x6666 || *second_address() != 0x6666)
        return 4;
    return 0;
}
