#define main normal_rep_main
#include "x64_rep_dift.c"
#undef main

uint64_t instruction_cnt, old_rsp, reports_CACHE, reports_MDS, reports_PORT;
uint64_t ordering_seen;

int main(void) {
    data = mmap((void *)0x31000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    tags = mmap((void *)0x131000000, 8192, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *shadow = mmap((void *)0x16200000, 4096, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(data == (void *)0x31000000 && tags == (void *)0x131000000 && shadow == (void *)0x16200000);
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, data) == 0);
    const struct test_case *test = &cases[0];
    for (unsigned direction = 0; direction < 2; ++direction)
    for (unsigned count = 0; count <= 3; ++count)
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        struct state in = {.cx=count, .flags=0xad7 | (direction ? 0x400 : 0)};
        in.si = test->segment ? 128 : (uintptr_t)(data+128);
        in.di = (uintptr_t)(data+512);
        if (test->address_size == 4) {
            in.si |= 0x123400000000ULL;
            in.di |= 0x234500000000ULL;
            in.cx |= 0x345600000000ULL;
        }
        struct state expected = in, actual = in;
        memset(data, 0, 8192);
        test->original(&expected);
        memcpy(expected_data, data, 4096);
        memset(data, 0, 8192);
        memset(tags, scenario == 0 ? 0x10 : 0, 8192);
        memset(shadow, scenario == 1 || scenario == 3 ? 0xff : 0, 4096);
        memset(dift_reg_tags, 0, 48);
        dift_reg_tags[4] = dift_reg_tags[5] = scenario == 1 ? 1 : scenario == 2 ? 0x10 : 0;
        dift_reg_tags[2] = scenario == 4 ? 0x10 : 0;
        memory_history_top = history;
        instruction_cnt = reports_CACHE = reports_MDS = reports_PORT = 0;
        ordering_seen = 0;
        test->common(&actual);
        assert(ordering_seen == 1);
        assert(!memcmp(&actual, &expected, sizeof(actual)));
        assert(!memcmp(data, expected_data, 4096));
        uint64_t completed = in.cx - expected.cx;
        if (test->address_size == 4) completed = (uint32_t)completed;
        assert(instruction_cnt == completed);
        if (scenario == 4) assert(reports_PORT);
        if (!count) {
            assert(!reports_CACHE && !reports_MDS && memory_history_top == history);
            if (scenario != 4) assert(!reports_PORT);
            continue;
        }
        if (test->kind != 's') {
            if (scenario == 1) assert(reports_MDS);
            if (scenario == 2) assert(reports_CACHE);
            unsigned char tag = test->kind == 'm' ? tags[512] :
                test->kind == 'l' ? dift_reg_tags[0] : dift_reg_tags[2];
            assert(tag & (scenario == 3 ? 2 : 0x10));
            if ((test->kind == 'c' || test->kind == 't') && scenario != 3) assert(reports_PORT);
        }
        while (memory_history_top != history) {
            struct history_entry *entry = --memory_history_top;
            memcpy(entry->addr, &entry->data, entry->size);
        }
        for (unsigned i = 0; i < 4096; ++i) {
            assert(data[i] == 0);
            assert(tags[i] == (scenario == 0 ? 0x10 : 0));
        }
    }
    puts("rewritten REP access policies and tag flow passed");
    return 0;
}
