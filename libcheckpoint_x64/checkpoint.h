#pragma once

#include <stdint.h>
#include <stdbool.h>

//#define ROB_LEN 224
#define ROB_LEN 5

#define MAX_CHECKPOINTS 3

typedef struct memory_history {
    void *addr;
    uint64_t data;
    uint8_t size;
} memory_history_t;

typedef struct general_register_state {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t flags;
} general_register_state_t;

typedef __attribute__((aligned(256))) struct checkpoint_metadata {
    // Size must be kept at 32 * 8 bytes
    general_register_state_t registers;
    uint64_t instruction_cnt, memory_history_cnt;
    uint64_t return_address;

    uint64_t alignment[12];
} checkpoint_metadata_t;

void libcheckpoint_enable();
void libcheckpoint_disable();
void make_checkpoint();
void restore_checkpoint();
void restore_checkpoint_registers();
/*void log_write(void *addr, uint64_t data, uint8_t size);
void increase_instruction_cnt();
void after_one_instruction();*/
