/* One of two statics called target (tests/test_symbol_reference_execution.py). */
static long target = 0x1111;
long first_get(void) { return target; }
void first_set(long value) { target = value; }
long *first_address(void) { return &target; }
