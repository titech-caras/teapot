#include "checkpoint.h"
#include <string.h>

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
memory_history_t memory_history[ROB_LEN];
uint64_t checkpoint_cnt = MAX_CHECKPOINTS; // Library initially disabled

void libcheckpoint_enable() {
    checkpoint_cnt = 0;
}

void libcheckpoint_disable() {
    checkpoint_cnt = MAX_CHECKPOINTS;
}

/*
 * Takes two stack arguments: trampoline address and checkpoint return address.
 * The function will pop the checkpoint return address from stack and return to trampoline address.
 * Should be called like:
 *
 * push 0x114514 // trampoline address
 * call make_checkpoint
 */
__attribute__((naked)) void make_checkpoint() {
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

    // Store %rax and FLAGS
    __asm__ __volatile__ (
        "pushfq\n"
        "push %rax\n"
        "push %rbx\n"
        "mov checkpoint_cnt@GOTPCREL(%rip), %rbx\n"
        "mov (%rbx), %rax\n"
        "cmp $" STR(MAX_CHECKPOINTS) ", %rax\n"
        "jge .Lskip_checkpoint\n"
    );

    // Dancing in stack to checkpoint %rax, %rbx, %rsp, return address, and FLAGS
    __asm__ __volatile__ (
        "incl (%rbx)\n" // Increment count in memory
        "mov checkpoint_metadata@GOTPCREL(%rip), %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
        "mov (%rsp), %rbx\n" // Original %rbx
        "mov %rbx, 8(%rax)\n" // checkpoint->rbx
        "mov 8(%rsp), %rbx\n" // Original %rax
        "mov %rbx, (%rax)\n" // checkpoint->rax
        "mov 16(%rsp), %rbx\n" // Original FLAGS
        "mov %rbx, 128(%rax)\n" // checkpoint->flags
        "mov 24(%rsp), %rbx\n" // return address
        "mov %rbx, 152(%rax)\n" // checkpoint->return_address
        "lea 40(%rsp), %rbx\n" // Original %rsp, as we pushed five things onto the stack
        "mov %rbx, 48(%rax)\n" // checkpoint->rsp
    );

    // Store other general purpose registers
    __asm__ __volatile__ (
        // rax stored above
        // rbx stored above
        "mov %rcx, 16(%rax)\n"
        "mov %rdx, 24(%rax)\n"
        "mov %rsi, 32(%rax)\n"
        "mov %rdi, 40(%rax)\n"
        // rsp stored above
        "mov %rbp, 56(%rax)\n"
        "mov %r8, 64(%rax)\n"
        "mov %r9, 72(%rax)\n"
        "mov %r10, 80(%rax)\n"
        "mov %r11, 88(%rax)\n"
        "mov %r12, 96(%rax)\n"
        "mov %r13, 104(%rax)\n"
        "mov %r14, 112(%rax)\n"
        "mov %r15, 120(%rax)\n"
        // flags stored above
    );

    // Check if is first checkpoint
    __asm__ __volatile__ (
        "cmp checkpoint_metadata@GOTPCREL(%rip), %rax\n"
        "jne .Lnot_first_checkpoint\n"
        // if is first checkpoint
        "movq $0, 136(%rax)\n" // checkpoint->instruction_cnt
        "movq $0, 144(%rax)\n" // checkpoint->memory_history_cnt
        "jmp .Lcleanup_after_checkpoint\n"
    );

    // If is not first checkpoint, copy counters from previous checkpoint
    __asm__ __volatile__ (
        ".Lnot_first_checkpoint:\n"
        "mov -120(%rax), %rbx\n" // prev_checkpoint->instruction_cnt
        "mov %rbx, 136(%rax)\n" // checkpoint->instruction_cnt
        "mov -112(%rax), %rbx\n" // prevcheckpoint->memory_history_cnt
        "mov %rbx, 144(%rax)\n" // checkpoint->memory_history_cnt
    );

    // Exit cleanup, return to trampoline
    __asm__ __volatile__ (
        ".Lcleanup_after_checkpoint:"
        "pop %rbx\n"
        "pop %rax\n"
        "popfq\n"
        "lea 8(%rsp), %rsp\n" // get rid of the return address because we want to go to the trampoline
        "ret\n"
    );

    // If we don't do checkpointing at all
    __asm__ __volatile__ (
        ".Lskip_checkpoint:\n"
        "pop %rbx\n"
        "mov 16(%rsp), %rax\n" // return address
        "mov %rax, 24(%rsp)\n" // overwrite trampoline address
        "pop %rax\n"
        "popfq\n"
        "lea 8(%rsp), %rsp\n" // get rid of extra return address
        "ret\n"
    );

#undef STR_HELPER
#undef STR
}

void restore_checkpoint() {
    // TODO: restore memory log

    checkpoint_cnt--;

    restore_checkpoint_registers();
}

__attribute__((naked)) void restore_checkpoint_registers() {
    // Load address of current metadata into %rax
    __asm__ __volatile__(
        "mov checkpoint_cnt@GOTPCREL(%rip), %rax\n"
        "mov (%rax), %rax\n"
        "mov checkpoint_metadata@GOTPCREL(%rip), %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
    );

    // Restore registers
    __asm__ __volatile__(
        // Restore %rax later
        // Restore %rbx later
        "mov 16(%rax), %rcx\n"
        "mov 24(%rax), %rdx\n"
        "mov 32(%rax), %rsi\n"
        "mov 40(%rax), %rdi\n"
        "mov 48(%rax), %rsp\n"
        "mov 56(%rax), %rbp\n"
        "mov 64(%rax), %r8\n"
        "mov 72(%rax), %r9\n"
        "mov 80(%rax), %r10\n"
        "mov 88(%rax), %r11\n"
        "mov 96(%rax), %r12\n"
        "mov 104(%rax), %r13\n"
        "mov 112(%rax), %r14\n"
        "mov 120(%rax), %r15\n"
    );

    __asm__ __volatile__(
        "mov 128(%rax), %rbx\n" // checkpoint->flags
        "push %rbx\n"
        "popfq\n"
        "mov 152(%rax), %rbx\n" // checkpoint->return_address
        "push %rbx\n"
        "mov 8(%rax), %rbx\n" // restore %rbx
        "mov (%rax), %rax\n" // restore %rax
        "ret"
    );
}