/* The other static called target (tests/test_symbol_reference_execution.py). */
static long target = 0x2222;
long second_get(void) { return target; }
void second_set(long value) { target = value; }
long *second_address(void) { return &target; }
