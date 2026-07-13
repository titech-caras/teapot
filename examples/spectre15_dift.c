#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef TAG_SECRET
#define TAG_SECRET 16
#endif

__attribute__((weak))
void dift_set_mem_tags(void *addr, unsigned char tag, size_t len) {
    (void)addr;
    (void)tag;
    (void)len;
}

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
};
uint8_t unused2[64];
uint8_t array2[256 * 512];
const char *secret = "The Magic Words are Squeamish Ossifrage.";
volatile uint8_t temp = 0;

static void teapot_poison_byte(const void *addr) {
#if defined(__x86_64__)
    uintptr_t shadow = ((uintptr_t)addr >> 3) + 0x7fff8000ULL;
    uintptr_t page = shadow & ~0xfffULL;
    mmap((void *)page, 4096, PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    *(volatile uint8_t *)shadow = 0xff;
#else
    (void)addr;
#endif
}

__attribute__((noinline))
void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}

int main(void) {
    int attacker_offset = 0;
    size_t malicious_x = (size_t)(secret - (char *)array1);
    size_t training_x = 5;

    memset(array2, 1, sizeof(array2));
    dift_set_mem_tags((void *)secret, TAG_SECRET, strlen(secret));
    (void)attacker_offset;
    (void)training_x;
    (void)teapot_poison_byte;
    victim_function(malicious_x);

    return temp == 0 ? 0 : 1;
}
