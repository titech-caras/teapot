#include "checkpoint.h"

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
uint64_t checkpoint_cnt = MAX_CHECKPOINTS; // Library initially disabled
uint64_t instruction_cnt = 0;

memory_history_t *memory_history_top = &memory_history[0];

void libcheckpoint_enable() {
    checkpoint_cnt = 0;
}

void libcheckpoint_disable() {
    checkpoint_cnt = MAX_CHECKPOINTS;
}

void restore_checkpoint() {
    while (memory_history_top > checkpoint_metadata[checkpoint_cnt].memory_history_top) {
        memory_history_top--;
        *(uint64_t*)(memory_history_top->addr) = memory_history_top->data;
    }

    checkpoint_cnt--;

    restore_checkpoint_registers();
}
