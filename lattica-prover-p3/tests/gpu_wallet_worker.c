/* Linux wallet-owned service admission. Uses synthetic inputs only. */
#define _POSIX_C_SOURCE 200809L
#include "../include/lattica_prover_p3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *assignment_env = "LATTICA_WALLET_WORKER_BUDGET";
static unsigned rejected;

static void proof_rejected(void) {
    uint8_t proof[1] = {0xa5}, public_values[1] = {0x5a};
    uint8_t joinsplit[2464] = {0}, htlc[2728] = {0};
    size_t length = 17, public_length = 19;
    assert(lattica_joinsplit_prove_demo(proof, 1, &length, public_values, 1, &public_length) == 1);
    assert(lattica_htlc_prove_demo(proof, 1, &length, public_values, 1, &public_length) == 1);
    assert(lattica_joinsplit_prove(joinsplit, sizeof joinsplit, proof, 1, &length,
        public_values, 1, &public_length) == 1);
    assert(lattica_htlc_prove(htlc, sizeof htlc, proof, 1, &length,
        public_values, 1, &public_length) == 1);
    assert(lattica_batch_prove(joinsplit, sizeof joinsplit, 1, proof, 1, &length,
        public_values, 1, &public_length) == 1);
    assert(lattica_htlc_batch_prove(htlc, sizeof htlc, 1, proof, 1, &length,
        public_values, 1, &public_length) == 1);
    assert(proof[0] == 0xa5 && public_values[0] == 0x5a && length == 17 && public_length == 19);
    rejected += 6;
}

static void changed_environment(const char *name, const char *value) {
    const char *previous = getenv(name);
    char *saved = previous ? strdup(previous) : NULL;
    assert(!previous || saved);
    assert(value ? setenv(name, value, 1) == 0 : unsetenv(name) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    /* Rejection must not retire the already running engine. */
    assert(lattica_gpu_drain() == LATTICA_GPU_OK);
    assert(saved ? setenv(name, saved, 1) == 0 : unsetenv(name) == 0);
    free(saved);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "reject") == 0) {
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
        assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
        proof_rejected();
        assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
        printf("wallet_worker_rejected abi_calls=%u no_engine=true\n", rejected);
        return 0;
    }
    const char *path = getenv(assignment_env);
    assert(path);
    char *saved_path = strdup(path);
    assert(saved_path);
    if (strcmp(argv[1], "unassigned") == 0) {
        assert(unsetenv(assignment_env) == 0);
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
        assert(setenv(assignment_env, saved_path, 1) == 0);
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
        proof_rejected();
        assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
        assert(unsetenv(assignment_env) == 0);
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
        assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
        puts("wallet_worker_unassigned_pin_survived_shutdown=true");
        free(saved_path);
        return 0;
    }
    assert(strcmp(argv[1], "mutations") == 0);
    /* Valid assignment alone cannot admit private work before native startup. */
    proof_rejected();
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    changed_environment("LATTICA_PROVING_POLICY", "compatible");
    changed_environment("LATTICA_PROVING_POLICY", "cpu-required");
    changed_environment("LATTICA_PROVING_POLICY", NULL);
    changed_environment("LATTICA_GPU_DEVICE_UUID", "GPU-00000000-0000-0000-0000-000000000000");
    changed_environment("LATTICA_V2_GPU_MANAGED_BYTES", "536870912");
    changed_environment("LATTICA_V2_GPU_CONTEXT_BYTES", "536870912");
    changed_environment("LATTICA_V2_HOST_OUTPUT_BYTES", "536870912");
    changed_environment("RAYON_NUM_THREADS", "2");
    changed_environment("LATTICA_V2_WORKER_BUDGET", "/unavailable-public-assignment");
    changed_environment(assignment_env, NULL);
    changed_environment(assignment_env, "/unavailable-wallet-assignment");
    assert(unsetenv(assignment_env) == 0);
    assert(setenv("LATTICA_PROVING_POLICY", "compatible", 1) == 0);
    assert(setenv("LATTICA_V2_GPU_WITNESS", "0", 1) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    assert(lattica_gpu_drain() == LATTICA_GPU_OK);
    assert(setenv("LATTICA_PROVING_POLICY", "gpu-required", 1) == 0);
    assert(setenv("LATTICA_V2_GPU_WITNESS", "1", 1) == 0);
    assert(setenv(assignment_env, saved_path, 1) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);

    struct stat metadata;
    assert(stat(saved_path, &metadata) == 0);
    assert(chmod(saved_path, 0644) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    assert(chmod(saved_path, metadata.st_mode & 0777) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);

    FILE *changed = fopen(saved_path, "r+b");
    assert(changed);
    int original = fgetc(changed);
    assert(original != EOF && fseek(changed, 0, SEEK_SET) == 0);
    assert(fputc('[', changed) != EOF && fflush(changed) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    assert(fseek(changed, 0, SEEK_SET) == 0);
    assert(fputc(original, changed) != EOF && fclose(changed) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);

    char backup[4096];
    assert(snprintf(backup, sizeof backup, "%s.saved", saved_path) < (int)sizeof backup);
    assert(rename(saved_path, backup) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    FILE *input = fopen(backup, "rb"), *output = fopen(saved_path, "wb");
    assert(input && output);
    assert(chmod(saved_path, 0600) == 0);
    int byte;
    while ((byte = fgetc(input)) != EOF) assert(fputc(byte, output) != EOF);
    assert(!ferror(input));
    assert(fclose(input) == 0 && fclose(output) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    assert(unlink(saved_path) == 0 && rename(backup, saved_path) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(unsetenv(assignment_env) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    proof_rejected();
    assert(setenv(assignment_env, saved_path, 1) == 0);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    printf("wallet_worker_mutations_complete abi_calls=%u pin_survived_shutdown=true\n", rejected);
    free(saved_path);
    return 0;
}
