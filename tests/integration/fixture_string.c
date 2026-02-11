/* fixture_string.c — memcpy/memmove/memset/strlen/strcmp under LD_PRELOAD
 * Part of glibc_rust C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <string.h>

static int test_memcpy(void) {
    char src[32] = "glibc_rust memcpy test";
    char dst[32] = {0};
    memcpy(dst, src, sizeof(src));
    if (memcmp(dst, src, sizeof(src)) != 0) {
        fprintf(stderr, "FAIL: memcpy content mismatch\n"); return 1;
    }
    return 0;
}

static int test_memmove_nonoverlap(void) {
    char src[16] = "non-overlap!!!!";
    char dst[16] = {0};
    memmove(dst, src, 16);
    if (memcmp(dst, src, 16) != 0) {
        fprintf(stderr, "FAIL: memmove non-overlapping\n"); return 1;
    }
    return 0;
}

static int test_memmove_overlap_forward(void) {
    char buf[32] = "ABCDEFGHIJKLMNOP";
    /* Move bytes 0..8 to bytes 4..12 (overlapping forward) */
    memmove(buf + 4, buf, 8);
    if (memcmp(buf + 4, "ABCDEFGH", 8) != 0) {
        fprintf(stderr, "FAIL: memmove overlap forward\n"); return 1;
    }
    return 0;
}

static int test_memmove_overlap_backward(void) {
    char buf[32] = "ABCDEFGHIJKLMNOP";
    /* Move bytes 4..12 to bytes 0..8 (overlapping backward) */
    memmove(buf, buf + 4, 8);
    if (memcmp(buf, "EFGHIJKL", 8) != 0) {
        fprintf(stderr, "FAIL: memmove overlap backward\n"); return 1;
    }
    return 0;
}

static int test_memset(void) {
    char buf[64];
    memset(buf, 0x42, sizeof(buf));
    for (int i = 0; i < 64; i++) {
        if (buf[i] != 0x42) {
            fprintf(stderr, "FAIL: memset byte %d\n", i); return 1;
        }
    }
    return 0;
}

static int test_strlen(void) {
    if (strlen("") != 0) { fprintf(stderr, "FAIL: strlen empty\n"); return 1; }
    if (strlen("abc") != 3) { fprintf(stderr, "FAIL: strlen 3\n"); return 1; }
    char buf[256];
    memset(buf, 'x', 255);
    buf[255] = '\0';
    if (strlen(buf) != 255) { fprintf(stderr, "FAIL: strlen 255\n"); return 1; }
    return 0;
}

static int test_strcmp(void) {
    if (strcmp("abc", "abc") != 0) { fprintf(stderr, "FAIL: strcmp equal\n"); return 1; }
    if (strcmp("abc", "abd") >= 0) { fprintf(stderr, "FAIL: strcmp less\n"); return 1; }
    if (strcmp("abd", "abc") <= 0) { fprintf(stderr, "FAIL: strcmp greater\n"); return 1; }
    if (strcmp("", "") != 0) { fprintf(stderr, "FAIL: strcmp empty\n"); return 1; }
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_memcpy();
    fails += test_memmove_nonoverlap();
    fails += test_memmove_overlap_forward();
    fails += test_memmove_overlap_backward();
    fails += test_memset();
    fails += test_strlen();
    fails += test_strcmp();

    if (fails) {
        fprintf(stderr, "fixture_string: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_string: PASS (7 tests)\n");
    return 0;
}
