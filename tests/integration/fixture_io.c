/* fixture_io.c — read/write/open/close under LD_PRELOAD
 * Part of glibc_rust C fixture suite (bd-3jh).
 * Exit 0 = PASS, nonzero = FAIL with diagnostic to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static int test_open_read_close(void) {
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        /* /etc/hostname might not exist in all environments; try /etc/hosts */
        fd = open("/etc/hosts", O_RDONLY);
    }
    if (fd < 0) {
        fprintf(stderr, "FAIL: open /etc/hosts: %s\n", strerror(errno));
        return 1;
    }
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        fprintf(stderr, "FAIL: read: %s\n", strerror(errno));
        close(fd); return 1;
    }
    buf[n] = '\0';
    if (n == 0) {
        fprintf(stderr, "FAIL: read returned 0 bytes\n");
        close(fd); return 1;
    }
    close(fd);
    return 0;
}

static int test_write_to_devnull(void) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "FAIL: open /dev/null: %s\n", strerror(errno));
        return 1;
    }
    const char *msg = "fixture_io write test\n";
    ssize_t n = write(fd, msg, strlen(msg));
    if (n < 0) {
        fprintf(stderr, "FAIL: write /dev/null: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if ((size_t)n != strlen(msg)) {
        fprintf(stderr, "FAIL: write short: %zd/%zu\n", n, strlen(msg));
        close(fd); return 1;
    }
    close(fd);
    return 0;
}

static int test_open_create_write_read(void) {
    char path[] = "/tmp/glibc_rust_fixture_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "FAIL: mkstemp: %s\n", strerror(errno));
        return 1;
    }

    const char *data = "Hello from fixture_io!";
    ssize_t written = write(fd, data, strlen(data));
    if (written < 0 || (size_t)written != strlen(data)) {
        fprintf(stderr, "FAIL: write tmpfile\n");
        close(fd); unlink(path); return 1;
    }

    /* Seek back and read */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        fprintf(stderr, "FAIL: lseek: %s\n", strerror(errno));
        close(fd); unlink(path); return 1;
    }

    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0 || (size_t)n != strlen(data)) {
        fprintf(stderr, "FAIL: read back: got %zd\n", n);
        close(fd); unlink(path); return 1;
    }
    if (strcmp(buf, data) != 0) {
        fprintf(stderr, "FAIL: read content mismatch\n");
        close(fd); unlink(path); return 1;
    }

    close(fd);
    unlink(path);
    return 0;
}

static int test_open_nonexistent(void) {
    int fd = open("/nonexistent_glibc_rust_fixture_path", O_RDONLY);
    if (fd >= 0) {
        fprintf(stderr, "FAIL: open nonexistent succeeded\n");
        close(fd); return 1;
    }
    if (errno != ENOENT) {
        fprintf(stderr, "FAIL: expected ENOENT, got %d\n", errno);
        return 1;
    }
    return 0;
}

static int test_read_write_pipe(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        fprintf(stderr, "FAIL: pipe: %s\n", strerror(errno));
        return 1;
    }

    const char *msg = "pipe test data";
    ssize_t w = write(pipefd[1], msg, strlen(msg));
    if (w < 0 || (size_t)w != strlen(msg)) {
        fprintf(stderr, "FAIL: write pipe\n");
        close(pipefd[0]); close(pipefd[1]); return 1;
    }
    close(pipefd[1]);

    char buf[64] = {0};
    ssize_t r = read(pipefd[0], buf, sizeof(buf));
    if (r < 0 || (size_t)r != strlen(msg)) {
        fprintf(stderr, "FAIL: read pipe\n");
        close(pipefd[0]); return 1;
    }
    if (strcmp(buf, msg) != 0) {
        fprintf(stderr, "FAIL: pipe content mismatch\n");
        close(pipefd[0]); return 1;
    }
    close(pipefd[0]);
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_open_read_close();
    fails += test_write_to_devnull();
    fails += test_open_create_write_read();
    fails += test_open_nonexistent();
    fails += test_read_write_pipe();

    if (fails) {
        fprintf(stderr, "fixture_io: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_io: PASS (5 tests)\n");
    return 0;
}
