#define _GNU_SOURCE
#include <assert.h>
#include <asm/prctl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

unsigned char scratchpad[SCRATCHPAD_SIZE] __attribute__((aligned(16)));
unsigned char dift_reg_tags[48], dift_reg_queued_tags[48];
unsigned char dift_reg_queue_pending[8];
uintptr_t old_rsp;
extern unsigned char test_function(unsigned char *dst, unsigned char *src, unsigned count);
extern unsigned char tail_entry(unsigned char *dst, unsigned char *src, unsigned count, unsigned spare);

int main(void) {
    unsigned char *data = mmap((void *)0x31000000, 4096, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char *tags = mmap((void *)0x131000000, 4096, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(data == (void *)0x31000000 && tags == (void *)0x131000000);
    dift_reg_tags[3] = 1; /* RDX supplies RCX's count. */
    dift_reg_tags[4] = 2;
    dift_reg_tags[5] = 4;
    for (unsigned i = 0; i < 4; ++i) {
        memset(data+128+WIDTH*i, i+1, WIDTH);
        tags[128+WIDTH*i+WIDTH-1] = 0x10 << i;
    }
#if SOURCE_SEGMENT
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, data) == 0);
#endif
    assert(test_function(data, SOURCE_SEGMENT ? (void *)128 : data+128, 4) == 4);
    for (unsigned i = 0; i < 4*WIDTH; ++i) {
        assert(data[i] == i/WIDTH + 1);
        assert(tags[i] == (7 | (0x10 << (i/WIDTH))));
    }
    for (unsigned i = 4*WIDTH; i < 4*WIDTH+4; ++i) {
        assert(data[i] == (ADJACENT ? 0 : 4));
        assert(tags[i] == (ADJACENT ? 0 : 0x87));
    }
    assert(dift_reg_tags[0] == 0x87);
#if SPLIT && !ADJACENT
    /* Only the REP predecessor may enter its post patch. An independent entry
       to the next block must not consume that predecessor's stale capture. */
    memset(tags, 0, 4096);
    memset(dift_reg_tags, 0, 48);
    dift_reg_tags[3] = 1;
    dift_reg_tags[5] = 4;
    tags[63] = 0x80;
    data[63] = 4;
    assert(tail_entry(data+64, data+128, 4, 0) == 4);
    assert(dift_reg_tags[0] == 0x85);
    for (unsigned i = 0; i < 63; ++i) assert(tags[i] == 0);
    for (unsigned i = 64; i < 68; ++i) assert(data[i] == 4 && tags[i] == 0x85);
#endif
#if SOURCE_SEGMENT
    assert(syscall(SYS_arch_prctl, ARCH_SET_GS, 0) == 0);
#endif
    return 0;
}
