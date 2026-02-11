/* fixture_malloc.c — malloc/free/realloc/calloc under LD_PRELOAD
 * Part of glibc_rust C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int test_malloc_free(void) {
    char *p = malloc(128);
    if (!p) { fprintf(stderr, "FAIL: malloc(128) returned NULL\n"); return 1; }
    memset(p, 'X', 128);
    if (p[0] != 'X' || p[127] != 'X') {
        fprintf(stderr, "FAIL: memset after malloc\n"); free(p); return 1;
    }
    free(p);
    return 0;
}

static int test_calloc_zeroed(void) {
    int *arr = calloc(256, sizeof(int));
    if (!arr) { fprintf(stderr, "FAIL: calloc returned NULL\n"); return 1; }
    for (int i = 0; i < 256; i++) {
        if (arr[i] != 0) {
            fprintf(stderr, "FAIL: calloc not zeroed at %d\n", i);
            free(arr); return 1;
        }
    }
    free(arr);
    return 0;
}

static int test_realloc_grow(void) {
    char *p = malloc(16);
    if (!p) { fprintf(stderr, "FAIL: malloc(16) returned NULL\n"); return 1; }
    memcpy(p, "hello, realloc!", 16);

    char *q = realloc(p, 256);
    if (!q) { fprintf(stderr, "FAIL: realloc(256) returned NULL\n"); free(p); return 1; }
    if (memcmp(q, "hello, realloc!", 16) != 0) {
        fprintf(stderr, "FAIL: realloc did not preserve contents\n"); free(q); return 1;
    }
    free(q);
    return 0;
}

static int test_realloc_shrink(void) {
    char *p = malloc(1024);
    if (!p) { fprintf(stderr, "FAIL: malloc(1024) returned NULL\n"); return 1; }
    memset(p, 'Z', 1024);

    char *q = realloc(p, 8);
    if (!q) { fprintf(stderr, "FAIL: realloc(8) returned NULL\n"); free(p); return 1; }
    if (q[0] != 'Z' || q[7] != 'Z') {
        fprintf(stderr, "FAIL: realloc shrink lost data\n"); free(q); return 1;
    }
    free(q);
    return 0;
}

static int test_malloc_zero(void) {
    /* malloc(0) is implementation-defined but must not crash */
    void *p = malloc(0);
    free(p); /* free(NULL) or free(valid) both fine */
    return 0;
}

static int test_realloc_null(void) {
    /* realloc(NULL, n) == malloc(n) */
    char *p = realloc(NULL, 64);
    if (!p) { fprintf(stderr, "FAIL: realloc(NULL, 64) returned NULL\n"); return 1; }
    p[0] = 'A';
    free(p);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_malloc_free();
    fails += test_calloc_zeroed();
    fails += test_realloc_grow();
    fails += test_realloc_shrink();
    fails += test_malloc_zero();
    fails += test_realloc_null();

    if (fails) {
        fprintf(stderr, "fixture_malloc: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_malloc: PASS (6 tests)\n");
    return 0;
}
