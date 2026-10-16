/* Standalone native wallet owner; fixtures are synthetic and remain local. */
#define _POSIX_C_SOURCE 200809L
#include "../include/lattica_prover_p3.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PROOF_CAP (4u << 20)

static void save(const char *path, const uint8_t *bytes, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "wb");
    assert(file && fwrite(bytes, 1, length, file) == length);
    assert(fflush(file) == 0 && fsync(fd) == 0 && fclose(file) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 7);
    int htlc = strcmp(argv[1], "htlc") == 0;
    assert(htlc || strcmp(argv[1], "joinsplit") == 0);
    char *end;
    errno = 0;
    unsigned long count = strtoul(argv[2], &end, 10);
    assert(!errno && !*end && (count == 8 || count == 16 || count == 32 || count == 64));
    assert(getenv("LATTICA_WALLET_WORKER_BUDGET"));
    size_t input_bytes = count * (htlc ? 2728u : 2464u);
    uint8_t *input = malloc(input_bytes), *proof = malloc(PROOF_CAP);
    assert(input && proof);
    int fd = open(argv[3], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat metadata;
    assert(fd >= 0 && fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode));
    assert(metadata.st_size == (off_t)input_bytes);
    FILE *file = fdopen(fd, "rb");
    assert(file && fread(input, 1, input_bytes, file) == input_bytes && fgetc(file) == EOF);
    assert(fclose(file) == 0);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    uint8_t root[32];
    size_t proof_len = 0, root_len = 0;
    struct timespec started, ended;
    assert(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    int result = htlc
        ? lattica_htlc_batch_prove(input, input_bytes, count, proof, PROOF_CAP, &proof_len, root, sizeof(root), &root_len)
        : lattica_batch_prove(input, input_bytes, count, proof, PROOF_CAP, &proof_len, root, sizeof(root), &root_len);
    assert(clock_gettime(CLOCK_MONOTONIC, &ended) == 0);
    assert(result == 0 && proof_len > 0 && proof_len <= PROOF_CAP && root_len == 32);
    assert(lattica_gpu_drain() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    save(argv[4], proof, proof_len);
    save(argv[5], root, root_len);
    double seconds = (double)(ended.tv_sec - started.tv_sec) + (double)(ended.tv_nsec - started.tv_nsec) / 1e9;
    char summary[512];
    int length = snprintf(summary, sizeof(summary), "{\"kind\":\"%s\",\"count\":%lu,\"proof_bytes\":%zu,\"proof_seconds\":%.9f,\"gpu_shutdown\":true,\"wallet_assignment\":true}\n", argv[1], count, proof_len, seconds);
    assert(length > 0 && (size_t)length < sizeof(summary));
    save(argv[6], (const uint8_t *)summary, (size_t)length);
    memset(input, 0, input_bytes);
    free(input);
    free(proof);
    printf("native_large_batch_saved kind=%s count=%lu wallet_assignment=true gpu_shutdown=true\n", argv[1], count);
    return 0;
}
