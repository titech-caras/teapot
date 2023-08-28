#pragma once

#include <stdint.h>
#include <stdbool.h>

//#define ROB_LEN 250
#define ROB_LEN 50

#define MEM_HISTORY_LEN 1000

#define MAX_CHECKPOINTS 3

typedef struct memory_history {
    void *aligned_addr;
    uint64_t data;
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

typedef __attribute__((aligned(64))) struct xsave_area {
    // Let's just give XSAVE more than enough room...
    char data[2048];
} xsave_area_t;

void libcheckpoint_enable();
void libcheckpoint_disable();
void make_checkpoint();
void add_instruction_counter_check_restore();
void restore_checkpoint();
void restore_checkpoint_registers();
/*void log_write(void *addr, uint64_t data, uint8_t size);
void increase_instruction_cnt();
void after_one_instruction();*/
