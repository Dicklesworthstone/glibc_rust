/* Integration test: compile and link against glibc_rust's libc.so */
/* Build: cc -o link_test link_test.c -L../../target/release -lglibc_rs_abi */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    /* Test memcpy */
    char src[] = "Hello, glibc_rust!";
    char dst[32] = {0};
    memcpy(dst, src, strlen(src) + 1);

    if (strcmp(dst, src) != 0) {
        fprintf(stderr, "FAIL: memcpy/strcmp\n");
        return 1;
    }

    /* Test malloc/free */
    char *p = malloc(64);
    if (p == NULL) {
        fprintf(stderr, "FAIL: malloc returned NULL\n");
        return 1;
    }
    memset(p, 'A', 63);
    p[63] = '\0';
    if (strlen(p) != 63) {
        fprintf(stderr, "FAIL: strlen after malloc\n");
        free(p);
        return 1;
    }
    free(p);

    /* Test calloc */
    int *arr = calloc(10, sizeof(int));
    if (arr == NULL) {
        fprintf(stderr, "FAIL: calloc returned NULL\n");
        return 1;
    }
    for (int i = 0; i < 10; i++) {
        if (arr[i] != 0) {
            fprintf(stderr, "FAIL: calloc not zeroed at index %d\n", i);
            free(arr);
            return 1;
        }
    }
    free(arr);

    printf("PASS: all integration tests passed\n");
    return 0;
}
