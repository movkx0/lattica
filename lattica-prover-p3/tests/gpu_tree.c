/* Existing LJSTREE1 ABI: GPU arithmetic, unchanged CPU verification. */
#define _POSIX_C_SOURCE 200809L
#include "../include/lattica_prover_p3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TREE_CAP (1u << 29)
#define MAX_TX 1024u
#define WITNESS_BYTES 2464u
static uint8_t witnesses[MAX_TX * WITNESS_BYTES];
static uint8_t proof[TREE_CAP];
static uint8_t root[32];

static void rejected(size_t bytes, size_t count) {
    proof[0] = 0xa5;
    root[0] = 0x5a;
    size_t proof_len = 17, root_len = 19;
    assert(lattica_joinsplit_tree_prove(witnesses, bytes, count, proof, TREE_CAP,
        &proof_len, root, sizeof root, &root_len) == 1);
    assert(proof[0] == 0xa5 && root[0] == 0x5a && proof_len == 17 && root_len == 19);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "reject") == 0) {
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
        rejected(WITNESS_BYTES, 1);
        assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
        puts("legacy_gpu_tree_rejected preserved_outputs=true no_engine=true");
        return 0;
    }
    if (strcmp(argv[1], "budget-reject") == 0) {
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
        rejected(129 * WITNESS_BYTES, 129);
        assert(lattica_gpu_drain() == LATTICA_GPU_OK);
        assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
        puts("legacy_gpu_tree_budget_rejected preserved_outputs=true initialized_engine_preserved=true");
        return 0;
    }
    int cpu = strncmp(argv[1], "cpu-", 4) == 0;
    char *end;
    unsigned long count = strtoul(argv[1] + (cpu ? 4 : 0), &end, 10);
    assert(*end == '\0' && count > 0 && count <= MAX_TX);
    if (!cpu) {
        rejected(WITNESS_BYTES, 1);
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    }
    rejected(0, 0);
    rejected(sizeof witnesses, MAX_TX + 1);
    rejected(count * WITNESS_BYTES - 1, count);
    const char *assignment = getenv("LATTICA_WALLET_WORKER_BUDGET");
    if (assignment) {
        char *saved = strdup(assignment);
        assert(saved);
        assert(unsetenv("LATTICA_WALLET_WORKER_BUDGET") == 0);
        assert(setenv("LATTICA_PROVING_POLICY", "compatible", 1) == 0);
        assert(setenv("LATTICA_V2_GPU_WITNESS", "0", 1) == 0);
        rejected(WITNESS_BYTES, 1);
        assert(lattica_gpu_drain() == LATTICA_GPU_OK);
        assert(setenv("LATTICA_WALLET_WORKER_BUDGET", saved, 1) == 0);
        assert(setenv("LATTICA_PROVING_POLICY", "gpu-required", 1) == 0);
        assert(setenv("LATTICA_V2_GPU_WITNESS", "1", 1) == 0);
        free(saved);
    }
    size_t proof_len = 0, root_len = 0;
    assert(lattica_joinsplit_tree_prove(witnesses, count * WITNESS_BYTES, count,
        proof, TREE_CAP, &proof_len, root, sizeof root, &root_len) == 0);
    assert(proof_len > 44 && root_len == 32);
    if (!cpu) {
        assert(lattica_gpu_drain() == LATTICA_GPU_OK);
        assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    }
    assert(lattica_joinsplit_tree_verify(proof, proof_len, root, 32, count) == 0);
    assert(lattica_joinsplit_tree_verify(proof, proof_len, root, 32, count == 1 ? 2 : count - 1) == 1);
    assert(lattica_joinsplit_tree_verify(proof, proof_len - 1, root, 32, count) == 1);
    root[0] ^= 1;
    assert(lattica_joinsplit_tree_verify(proof, proof_len, root, 32, count) == 1);
    root[0] ^= 1;
    proof[44] ^= 1;
    assert(lattica_joinsplit_tree_verify(proof, proof_len, root, 32, count) == 1);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    printf("legacy_tree_c_verified backend=%s leaves=%lu proof_bytes=%zu cpu_verification=true tamper_checks=4\n", cpu ? "cpu" : "gpu", count, proof_len);
    return 0;
}
