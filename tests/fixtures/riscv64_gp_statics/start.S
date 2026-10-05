/* The entry of tests/fixtures/riscv64_gp_statics: gp for the program's
 * gp-relative accesses, then exit with main's result. */
    .section .text._start, "ax"
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    call main
    li a7, 93
    ecall
