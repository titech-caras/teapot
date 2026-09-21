#define main normal_rep_main
#include "x64_rep_dift.c"
#undef main
#include <setjmp.h>

uint64_t instruction_cnt;
static jmp_buf rollback;
void budget_stop(void) { longjmp(rollback, 1); }

static void undo_history(void) {
    while (memory_history_top != history) {
        struct history_entry *entry = --memory_history_top;
        assert(entry->size >= 1 && entry->size <= 8);
        memcpy(entry->addr, &entry->data, entry->size);
    }
}

int main(void) {
    data = mmap((void *)0x31000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    tags = mmap((void *)0x131000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(data == (void *)0x31000000 && tags == (void *)0x131000000);
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, data) == 0);
    for (unsigned i = 0; i < 4096; ++i) {
        original[i] = i % 7;
        initial_tags[i] = (i % 5) ? 1u << (i % 8) : 0;
    }
    for (unsigned t = 0; t < sizeof(cases)/sizeof(*cases); ++t) {
        const struct test_case *test = &cases[t];
        for (unsigned direction = 0; direction < 2; ++direction)
        for (unsigned count = 0; count <= 4; ++count)
        for (int overlap = -1; overlap <= 2; ++overlap) {
            struct state in = {.ax=0x0102030405060000ULL, .cx=count,
                               .flags=0xad7 | (direction ? 0x400 : 0)};
            in.si = test->segment ? 128 : (uintptr_t)(data+128);
            in.di = (uintptr_t)(data+128+(overlap == 2 ? 96 : overlap*(int)test->width));
            if (test->address_size == 4) {
                in.si |= 0x123400000000ULL;
                in.di |= 0x234500000000ULL;
                in.cx |= 0x345600000000ULL;
            }
            struct state expected = in;
            unsigned char expected_regs[48];
            memcpy(data, original, 4096);
            test->original(&expected);
            memcpy(expected_data, data, 4096);
            memcpy(expected_tags, initial_tags, 4096);
            memcpy(expected_regs, initial_regs, 48);
#if TEST_DIFT_ENABLED
            model(test, &in, &expected, expected_regs);
#endif
            for (unsigned mode = 0; mode < 2; ++mode) {
                struct state actual = in;
                memcpy(data, original, 4096);
                memcpy(tags, initial_tags, 4096);
                memcpy(dift_reg_tags, initial_regs, 48);
                memory_history_top = history;
                instruction_cnt = 17;
                (mode ? test->history : test->common)(&actual);
                uint64_t completed = in.cx - expected.cx;
                if (test->address_size == 4) completed = (uint32_t)completed;
                if (memcmp(&actual, &expected, sizeof(actual)) || memcmp(data, expected_data, 4096) ||
                    memcmp(tags, expected_tags, 4096) || memcmp(dift_reg_tags, expected_regs, 48) ||
                    instruction_cnt != 17 + completed) {
                    fprintf(stderr, "case=%u kind=%c width=%u DF=%u count=%u overlap=%d mode=%u state=%d data=%d tags=%d regs=%d budget=%lu\n",
                            t, test->kind, test->width, direction, count, overlap, mode,
                            memcmp(&actual, &expected, sizeof(actual)), memcmp(data, expected_data, 4096),
                            memcmp(tags, expected_tags, 4096), memcmp(dift_reg_tags, expected_regs, 48), instruction_cnt);
                    fprintf(stderr, "SI %lx/%lx DI %lx/%lx CX %lx/%lx FLAGS %lx/%lx\n",
                            actual.si, expected.si, actual.di, expected.di, actual.cx, expected.cx,
                            actual.flags, expected.flags);
                    return 1;
                }
                if (mode) {
                    undo_history();
                    assert(!memcmp(data, original, 4096) && !memcmp(tags, initial_tags, 4096));
                } else assert(memory_history_top == history);
            }
        }
        if (test->kind != 'm' && test->kind != 's') continue;
        const unsigned rooms[] = {0, 1, 2, 3, 4, ROB_LEN - 1};
        for (unsigned r = 0; r < sizeof(rooms)/sizeof(*rooms); ++r) {
            unsigned room = rooms[r];
            struct state in = {.si=test->segment ? 128 : (uintptr_t)(data+128),
                               .di=(uintptr_t)(data+512), .cx=UINT64_MAX, .flags=0x202};
            memcpy(data, original, 4096);
            memcpy(tags, initial_tags, 4096);
            memcpy(dift_reg_tags, initial_regs, 48);
            memory_history_top = history;
            instruction_cnt = ROB_LEN - 1 - room;
            if (!setjmp(rollback)) {
                test->history(&in);
                assert(!"unbounded REP returned instead of rolling back");
            }
            assert(instruction_cnt == ROB_LEN - 1);
            assert(memory_history_top - history == (long)(room * (1 + TEST_DIFT_ENABLED * test->width)));
            undo_history();
            assert(!memcmp(data, original, 4096) && !memcmp(tags, initial_tags, 4096));
        }
    }
    puts("transient REP values, flags, tags, history and iteration budgets passed");
    return 0;
}
