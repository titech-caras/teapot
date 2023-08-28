#include "checkpoint.h"
#include <string.h>

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
uint64_t checkpoint_cnt = MAX_CHECKPOINTS; // Library initially disabled
uint64_t instruction_cnt = 0, memory_history_cnt = 0;

void libcheckpoint_enable() {
    checkpoint_cnt = 0;
}

void libcheckpoint_disable() {
    checkpoint_cnt = MAX_CHECKPOINTS;
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

/*
 * Takes two stack arguments: trampoline address and checkpoint return address.
 * The function will pop the checkpoint return address from stack and return to trampoline address.
 * Should be called like:
 *
 * push 0x114514 // trampoline address
 * call make_checkpoint
 */
__attribute__((naked)) void make_checkpoint() {

    // Store %rax and FLAGS
    __asm__ __volatile__ (
        "pushfq\n"
        "push %rax\n"
        "push %rbx\n"
        "mov checkpoint_cnt@GOTPCREL(%rip), %rbx\n"
        "mov (%rbx), %rax\n"
        "cmp $" STR(MAX_CHECKPOINTS) ", %rax\n" // TODO: use a better strategy to determine checkpoint skipping
        "jge .Lskip_checkpoint\n"
        "incl (%rbx)\n" // Increment count in memory
    );

    // Store processor extended states
    __asm __volatile__ (
        "push %rax\n" // Save the original counter for now
        "mov processor_extended_states@GOTPCREL(%rip), %rbx\n"
        "shl $11, %rax\n" // XSAVE area is aligned to 2048 bytes
        "add %rax, %rbx\n"
        "push %rdx\n"
        "mov $0xFFFFFFFF, %eax\n"
        "mov $0xFFFFFFFF, %edx\n" // TODO: maybe save only the necessary components?
        "xsave (%rbx)\n"
        "pop %rdx\n"
        "pop %rax\n"
    );

    // Dancing in stack to checkpoint %rax, %rbx, %rsp, return address, and FLAGS
    __asm__ __volatile__ (
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

    // Store current counters
    __asm__ __volatile__ (
        "mov instruction_cnt@GOTPCREL(%rip), %rbx\n"
        "mov (%rbx), %rbx\n"
        "mov %rbx, 136(%rax)\n" // checkpoint->instruction_cnt
        "mov memory_history_cnt@GOTPCREL(%rip), %rbx\n"
        "mov (%rbx), %rbx\n"
        "mov %rbx, 144(%rax)\n" // checkpoint->memory_history_cnt
    );

    // Exit cleanup, go to the trampoline
    __asm__ __volatile__ (
        "pop %rbx\n"
        "pop %rax\n"
        "popfq\n"
        "lea 8(%rsp), %rsp\n" // get rid of the return address because we want to go to the trampoline
        "ret\n"
    );

    // If we don't do checkpointing at all, we don't want to go to the trampoline
    __asm__ __volatile__ (
        ".Lskip_checkpoint:\n"
        "pop %rbx\n"
        "mov 16(%rsp), %rax\n" // return address
        "mov %rax, 24(%rsp)\n" // overwrite trampoline address
        "pop %rax\n"
        "popfq\n"
        "ret\n"
    );
}

__attribute__((naked)) void add_instruction_counter_check_restore() {
    __asm__ __volatile__ (
        "pushfq\n"
        "push %rax\n"
        "push %rbx\n"
        "mov instruction_cnt@GOTPCREL(%rip), %rbx\n"
        "mov (%rbx), %rax\n"
        "add 32(%rsp), %rax\n" // instruction count parameter
        "cmp $" STR(ROB_LEN) ", %rax\n"
        "jge .Lgo_restore_checkpoint\n"
        "mov %rax, (%rbx)\n"
        "pop %rbx\n"
        "pop %rax\n"
        "popfq\n"
        "ret\n"
    );

    __asm__ __volatile__ (
        ".Lgo_restore_checkpoint:\n"
        "call *restore_checkpoint@GOTPCREL(%rip)\n"
    );
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
        "mov %rax, %r8\n" // Make a copy of the counter to use for XRSTOR stuff
        "mov checkpoint_metadata@GOTPCREL(%rip), %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
    );

    // Restore processor extended states
    __asm __volatile__ (
        "mov %rax, %r11\n"
        "mov processor_extended_states@GOTPCREL(%rip), %r9\n"
        "shl $11, %r8\n" // XSAVE area is aligned to 2048 bytes
        "add %r9, %r8\n"
        "mov $0xFFFFFFFF, %eax\n"
        "mov $0xFFFFFFFF, %edx\n" // TODO: maybe restore only the necessary components?
        "xrstor (%r8)\n"
        "mov %r11, %rax\n"
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
        "sub $8, %rsp\n" // balance stack
        "push %rbx\n"
        "popfq\n"
        "mov 152(%rax), %rbx\n" // checkpoint->return_address
        "push %rbx\n"
        "mov 8(%rax), %rbx\n" // restore %rbx
        "mov (%rax), %rax\n" // restore %rax
        "ret"
    );
}