/*
 * Adapted from Paul Kocher's "Spectre Mitigations in Microsoft's C/C++
 * Compiler" examples. The original examples are MIT licensed.
 *
 * This file adds a small Teapot DIFT driver around the 15 victim functions so
 * each example can be run independently:
 *
 *   ./kocher15_dift <1..15>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TAG_ATTACKER
#define TAG_ATTACKER 1
#endif

#ifndef TAG_SECRET
#define TAG_SECRET 16
#endif

__attribute__((weak))
void dift_set_mem_tags(void *addr, unsigned char tag, size_t len) {
    (void)addr;
    (void)tag;
    (void)len;
}

struct kocher15_memory {
    uint8_t array1[512];
    uint8_t secret[64];
};

static struct kocher15_memory memory = {
    .array1 = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    },
    .secret = "The Magic Words are Squeamish Ossifrage.",
};

size_t array1_size = 16;
size_t array2_size = 256 * 512;
size_t array_size_mask = 15;
uint8_t array2[256 * 512];
volatile uint8_t temp = 0;
volatile int kocher_keep_external_refs = 0;

#define array1 (memory.array1)
#define secret (memory.secret)

static __attribute__((always_inline)) inline void leakByteLocalFunction_v02(uint8_t k) {
    temp &= array2[k * 512];
}

__attribute__((noinline)) void victim_function_v01(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}

__attribute__((noinline)) void victim_function_v02(size_t x) {
    if (x < array1_size) {
        leakByteLocalFunction_v02(array1[x]);
    }
}

__attribute__((noinline)) void leakByteNoinlineFunction_v03(uint8_t k) {
    temp &= array2[k * 512];
}

__attribute__((noinline)) void victim_function_v03(size_t x) {
    if (x < array1_size) {
        leakByteNoinlineFunction_v03(array1[x]);
    }
}

__attribute__((noinline)) void victim_function_v04(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x << 1] * 512];
    }
}

__attribute__((noinline)) void victim_function_v05(size_t x) {
    size_t i;
    if (x < array1_size) {
        for (i = x; i-- > 0;) {
            temp &= array2[array1[i] * 512];
        }
    }
}

__attribute__((noinline)) void victim_function_v06(size_t x) {
    volatile size_t original_x = x;
    if ((x & array_size_mask) == x) {
        temp &= array2[array1[original_x] * 512];
    }
}

__attribute__((noinline)) void victim_function_v07(size_t x) {
    static size_t last_x = 0;
    if (x == last_x) {
        temp &= array2[array1[x] * 512];
    }
    if (x < array1_size) {
        last_x = x;
    }
}

__attribute__((noinline)) void victim_function_v08(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x + 1] * 512];
    } else {
        temp &= array2[array1[0] * 512];
    }
}

__attribute__((noinline)) void victim_function_v09(size_t x, int *x_is_safe) {
    if (*x_is_safe) {
        temp &= array2[array1[x] * 512];
    }
}

__attribute__((noinline)) void victim_function_v10(size_t x, uint8_t k) {
    if (x < array1_size) {
        if (array1[x] == k) {
            temp &= array2[0];
        }
    }
}

__attribute__((noinline)) void victim_function_v11(size_t x) {
    if (x < array1_size) {
        temp = memcmp((const void *)&temp, array2 + (array1[x] * 512), 1);
    }
}

__attribute__((noinline)) void victim_function_v12(size_t x, size_t y) {
    if ((x + y) < array1_size) {
        temp &= array2[array1[x + y] * 512];
    }
}

static __attribute__((always_inline)) inline int is_x_safe_v13(size_t x) {
    if (x < array1_size) {
        return 1;
    }
    return 0;
}

__attribute__((noinline)) void victim_function_v13(size_t x) {
    if (is_x_safe_v13(x)) {
        temp &= array2[array1[x] * 512];
    }
}

__attribute__((noinline)) void victim_function_v14(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x ^ 255] * 512];
    }
}

__attribute__((noinline)) void victim_function_v15(size_t *x) {
    if (*x < array1_size) {
        temp &= array2[array1[*x] * 512];
    }
}

static size_t secret_offset(void) {
    return (size_t)((uintptr_t)secret - (uintptr_t)array1);
}

static __attribute__((used, noinline)) void keep_external_refs(int argc, char **argv) {
    if (kocher_keep_external_refs && argc > 0) {
        kocher_keep_external_refs += atoi(argv[0]);
        kocher_keep_external_refs += (int)strlen((const char *)secret);
    }
}

static int run_example(int example) {
#ifdef KOCHER_DIRECT_SECRET
    size_t off = 0;
    size_t x_value = 0;
    int x_is_safe = 1;
#else
    size_t off = secret_offset();
    size_t x_value = off;
    int x_is_safe = 0;
#endif
    uint8_t attacker_k = 0xa5;

#ifdef KOCHER_DIRECT_SECRET
    dift_set_mem_tags(array1, TAG_SECRET, sizeof(array1));
#else
    memset(array2, 1, sizeof(array2));
    dift_set_mem_tags(secret, TAG_SECRET, strlen((const char *)secret));
#endif

    switch (example) {
    case 1:
        victim_function_v01(off);
        break;
    case 2:
        victim_function_v02(off);
        break;
    case 3:
        victim_function_v03(off);
        break;
    case 4:
#ifdef KOCHER_DIRECT_SECRET
        victim_function_v04(0);
#else
        victim_function_v04(off >> 1);
#endif
        break;
    case 5:
#ifdef KOCHER_DIRECT_SECRET
        victim_function_v05(1);
#else
        victim_function_v05(off + 1);
#endif
        break;
    case 6:
        victim_function_v06(off);
        break;
    case 7:
        victim_function_v07(off);
        break;
    case 8:
#ifdef KOCHER_DIRECT_SECRET
        victim_function_v08(0);
#else
        victim_function_v08(off - 1);
#endif
        break;
    case 9:
        victim_function_v09(off, &x_is_safe);
        break;
    case 10:
        dift_set_mem_tags(&attacker_k, TAG_ATTACKER, sizeof(attacker_k));
        victim_function_v10(off, attacker_k);
        break;
    case 11:
        victim_function_v11(off);
        break;
    case 12:
#ifdef KOCHER_DIRECT_SECRET
        victim_function_v12(0, 0);
#else
        victim_function_v12(off - 1, 1);
#endif
        break;
    case 13:
        victim_function_v13(off);
        break;
    case 14:
#ifdef KOCHER_DIRECT_SECRET
        victim_function_v14(0);
#else
        victim_function_v14(off ^ 255);
#endif
        break;
    case 15:
        x_value = off;
        victim_function_v15(&x_value);
        break;
    default:
        return 2;
    }

    return temp == 0xff ? 1 : 0;
}

#ifdef KOCHER_CASE
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    int result = run_example(KOCHER_CASE);
    return result;
}
#else
int main(int argc, char **argv) {
    keep_external_refs(argc, argv);
    if (argc != 2) {
        return 2;
    }

    return run_example(atoi(argv[1]));
}
#endif
