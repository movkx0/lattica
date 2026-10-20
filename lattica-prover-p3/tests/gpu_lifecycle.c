/* Standalone native startup/prove/shutdown/CPU-verify conformance.
 * Run each storage configuration in a fresh, explicitly bounded GPU process.
 */
#include "../include/lattica_prover_p3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROOF_CAP (1u << 21)
struct proof {
    uint8_t bytes[PROOF_CAP];
    uint8_t public_values[248];
    size_t len;
    size_t public_len;
};
static struct proof results[5];
static uint8_t joinsplit_batch[3 * 2464];
static uint8_t htlc_batch[3 * 2728];

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "unavailable") == 0) {
        assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_UNAVAILABLE);
        assert(lattica_gpu_drain() == LATTICA_GPU_UNAVAILABLE);
        assert(lattica_gpu_shutdown() == LATTICA_GPU_UNAVAILABLE);
        puts("native_gpu_unavailable exports=3");
        return 0;
    }
    assert(argc == 1);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_joinsplit_prove_demo(results[0].bytes, PROOF_CAP, &results[0].len,
        results[0].public_values, 248, &results[0].public_len) == 0);
    assert(lattica_htlc_prove_demo(results[1].bytes, PROOF_CAP, &results[1].len,
        results[1].public_values, 248, &results[1].public_len) == 0);
    /* Zero records encode the AIR's canonical dummy wallet. Three records
     * exercise the existing four-tile padding path without a Rust fixture shim. */
    assert(lattica_batch_prove(joinsplit_batch, sizeof joinsplit_batch, 3,
        results[2].bytes, PROOF_CAP, &results[2].len,
        results[2].public_values, 248, &results[2].public_len) == 0);
    assert(lattica_htlc_batch_prove(htlc_batch, sizeof htlc_batch, 3,
        results[3].bytes, PROOF_CAP, &results[3].len,
        results[3].public_values, 248, &results[3].public_len) == 0);
#ifdef LATTICA_TEST_CUDA
    /* Repeat the same witness before retiring CUDA's single process runtime. */
    assert(lattica_joinsplit_prove_demo(results[4].bytes, PROOF_CAP, &results[4].len,
        results[4].public_values, 248, &results[4].public_len) == 0);
    assert(results[0].public_len == results[4].public_len &&
        memcmp(results[0].public_values, results[4].public_values, results[0].public_len) == 0);
    assert(results[0].len != results[4].len ||
        memcmp(results[0].bytes, results[4].bytes, results[0].len) != 0);
#endif
    assert(lattica_gpu_drain() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    assert(results[0].public_len == 208 && results[1].public_len == 248);
    assert(results[2].public_len == 32 && results[3].public_len == 32);
    assert(lattica_joinsplit_verify(results[0].bytes, results[0].len,
        results[0].public_values, results[0].public_len) == 0);
    assert(lattica_htlc_verify(results[1].bytes, results[1].len,
        results[1].public_values, results[1].public_len) == 0);
    assert(lattica_batch_verify(results[2].bytes, results[2].len,
        results[2].public_values, results[2].public_len) == 0);
    assert(lattica_htlc_batch_verify(results[3].bytes, results[3].len,
        results[3].public_values, results[3].public_len) == 0);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    for (int i = 0; i < 4; ++i)
        printf("native_gpu_cpu_verified proof=%d after_shutdown=true\n", i);

    uint8_t output[1] = {0xa5}, public_output[1] = {0x5a};
    size_t length = 17, public_length = 19;
    assert(lattica_joinsplit_prove_demo(output, 1, &length, public_output, 1,
        &public_length) == 1);
    assert(output[0] == 0xa5 && public_output[0] == 0x5a && length == 17 && public_length == 19);

#ifdef LATTICA_TEST_CUDA
    /* CUDA owns one admitted runtime per process. The separate Zig harness
       tests successful initialization again in a fresh process. */
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    assert(lattica_joinsplit_verify(results[4].bytes, results[4].len,
        results[4].public_values, results[4].public_len) == 0);
    puts("native_gpu_cpu_verified proof=4 after_shutdown=true fresh_hiding=true");
    puts("native_gpu_lifecycle_complete proofs=5 preserved_outputs=true standalone_c=true restart_requires_fresh_process=true");
#else
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_joinsplit_prove_demo(results[4].bytes, PROOF_CAP, &results[4].len,
        results[4].public_values, 248, &results[4].public_len) == 0);
    assert(results[0].public_len == results[4].public_len &&
        memcmp(results[0].public_values, results[4].public_values, results[0].public_len) == 0);
    assert(results[0].len != results[4].len ||
        memcmp(results[0].bytes, results[4].bytes, results[0].len) != 0);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_joinsplit_verify(results[4].bytes, results[4].len,
        results[4].public_values, results[4].public_len) == 0);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    puts("native_gpu_cpu_verified proof=4 after_shutdown=true fresh_hiding=true");
    puts("native_gpu_lifecycle_complete proofs=5 preserved_outputs=true standalone_c=true");
#endif
    return 0;
}
