/* Run only in a fresh assigned public worker process with an isolated capped
 * fleet. Proof production is qualified separately through the same C startup. */
#include "../include/lattica_prover_p3.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    assert(lattica_gpu_initialize_from_env() == LATTICA_GPU_REJECTED);
    assert(lattica_gpu_public_worker_initialize_from_env() == LATTICA_GPU_OK);
    assert(lattica_gpu_public_worker_initialize_from_env() == LATTICA_GPU_REJECTED);
    assert(lattica_gpu_drain() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    assert(lattica_gpu_drain() == LATTICA_GPU_REJECTED);
    /* A retired public worker cannot silently create a new Rayon runtime. */
    assert(lattica_gpu_public_worker_initialize_from_env() == LATTICA_GPU_REJECTED);
    assert(lattica_gpu_shutdown() == LATTICA_GPU_OK);
    puts("native_public_c_lifecycle_verified");
    return 0;
}
