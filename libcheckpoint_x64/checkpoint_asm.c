#include "checkpoint.h"

#define SCRATCHPAD_SIZE 1024
__attribute__((aligned(8))) uint8_t scratchpad[SCRATCHPAD_SIZE];
void *old_rsp;

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define SCRATCHPAD_TOP "scratchpad+" STR(SCRATCHPAD_SIZE)

#define SWITCH_TO_SCRATCHPAD_STACK "mov %rsp, old_rsp\n" "lea " SCRATCHPAD_TOP ", %rsp\n"
#define SWITCH_TO_ORIGINAL_STACK "mov old_rsp, %rsp\n"

struct {
    void *trampoline_addr, *return_addr;
} checkpoint_target_metadata;
__attribute__((naked)) void make_checkpoint() {
    // Store %rax and FLAGS
    asm volatile (
        SWITCH_TO_SCRATCHPAD_STACK
        "pushfq\n"
        "push %rax\n"
        "push %rbx\n"
        "mov checkpoint_cnt, %rax\n"
        "cmp $" STR(MAX_CHECKPOINTS) ", %rax\n" // TODO: use a better strategy to determine checkpoint skipping
        "jge .Lskip_checkpoint\n"
        "incl checkpoint_cnt\n" // Increment count in memory
        );

    // Store processor extended states
    asm volatile (
        "push %rax\n" // Save the original counter for now
        "lea processor_extended_states, %rbx\n"
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
    asm volatile (
        "lea checkpoint_metadata, %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
        "mov (%rsp), %rbx\n" // Original %rbx
        "mov %rbx, 8(%rax)\n" // checkpoint->rbx
        "mov 8(%rsp), %rbx\n" // Original %rax
        "mov %rbx, (%rax)\n" // checkpoint->rax
        "mov 16(%rsp), %rbx\n" // Original FLAGS
        "mov %rbx, 128(%rax)\n" // checkpoint->flags
        "mov checkpoint_target_metadata+8, %rbx\n" // return address
        "mov %rbx, 152(%rax)\n" // checkpoint->return_address
        "mov old_rsp, %rbx\n"
        "mov %rbx, 48(%rax)\n" // checkpoint->rsp
        );

    // Store other general purpose registers
    asm volatile (
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
    asm volatile (
        "mov instruction_cnt, %rbx\n"
        "mov %rbx, 136(%rax)\n" // checkpoint->instruction_cnt
        "mov memory_history_top, %rbx\n"
        "mov %rbx, 144(%rax)\n" // checkpoint->memory_history_top
        );

    // Exit cleanup, go to the trampoline
    asm volatile (
        "pop %rbx\n"
        "pop %rax\n"
        "popfq\n"
        SWITCH_TO_ORIGINAL_STACK
        "jmp *(checkpoint_target_metadata)\n" // Trampoline address
        );

    // If we don't do checkpointing at all, we don't want to go to the trampoline
    asm volatile (
        ".Lskip_checkpoint:"
        "pop %rbx\n"
        "pop %rax\n"
        "popfq\n"
        SWITCH_TO_ORIGINAL_STACK
        "jmp *(checkpoint_target_metadata+8)\n" // Return address
        );
}

__attribute__((naked)) void restore_checkpoint_registers() {
    // Load address of current metadata into %rax
    asm volatile(
        "mov checkpoint_cnt, %rax\n"
        "mov %rax, %r8\n" // Make a copy of the counter to use for XRSTOR stuff
        "lea checkpoint_metadata, %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
        );

    // Restore processor extended states
    asm volatile (
        "mov %rax, %r11\n"
        "lea processor_extended_states, %r9\n"
        "shl $11, %r8\n" // XSAVE area is aligned to 2048 bytes
        "add %r9, %r8\n"
        "mov $0xFFFFFFFF, %eax\n"
        "mov $0xFFFFFFFF, %edx\n" // TODO: maybe restore only the necessary components?
        "xrstor (%r8)\n"
        "mov %r11, %rax\n"
        );

    // Restore registers
    asm volatile(
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

    asm volatile(
        SWITCH_TO_SCRATCHPAD_STACK
        "mov 128(%rax), %rbx\n" // checkpoint->flags
        "push %rbx\n"
        "popfq\n"
        SWITCH_TO_ORIGINAL_STACK
        "mov 152(%rax), %rbx\n" // checkpoint->return_address
        "mov %rbx, checkpoint_target_metadata+8\n"
        "mov 8(%rax), %rbx\n" // restore %rbx
        "mov (%rax), %rax\n" // restore %rax
        "jmp *(checkpoint_target_metadata+8)"
        );
}