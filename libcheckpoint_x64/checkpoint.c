#include "checkpoint.h"

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

void restore_checkpoint() {
    // TODO: restore memory log

    checkpoint_cnt--;

    restore_checkpoint_registers();
}
