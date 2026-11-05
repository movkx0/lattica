#ifndef LATTICA_CPU_GENERATION_H
#define LATTICA_CPU_GENERATION_H
#include <stddef.h>
#include <stdint.h>
/* Every operation and destructor holds the adapter's process-wide lock. */
typedef struct lattica_cpu_generation lattica_cpu_generation;
typedef struct { uint64_t max_attempts, random_call_limit, proposal_limit; }
  lattica_cpu_generation_limits;
typedef struct {
  uint64_t parameters_ns, inputs_ns, spend_ns, encoding_ns, cleanup_ns;
  uint64_t attempts, random_calls, random_blocks, proposals, parameter_cache_hits, status;
} lattica_cpu_generation_stats;
size_t lattica_cpu_generation_bytes(void);
lattica_cpu_generation *lattica_cpu_generation_new(const uint8_t setup_seed[32],
    const uint8_t context[32], unsigned cache_parameters, unsigned aes_lanes);
void lattica_cpu_generation_free(lattica_cpu_generation *owner);
int lattica_cpu_generation_spend(lattica_cpu_generation *owner,
    uint64_t index, uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    lattica_cpu_generation_limits limits, uint8_t *statement, size_t statement_len,
    uint8_t *proof, size_t proof_len, lattica_cpu_generation_stats *stats);
/* No-op outside bounded CPU generation. Refusals never cross a Rust frame. */
void lattica_cpu_generation_attempt(void);
void lattica_cpu_generation_random_request(uint64_t bytes);
void lattica_cpu_generation_proposals(uint64_t count);
unsigned lattica_cpu_generation_aes_lanes(void);
#ifdef LATTICA_CPU_GENERATION_ORACLE
int lattica_cpu_generation_test_seed(lattica_cpu_generation *owner, const uint8_t seed[32]);
void lattica_cpu_generation_test_failure(lattica_cpu_generation *owner, unsigned entropy_failure);
int lattica_cpu_generation_test_clean(lattica_cpu_generation *owner);
#endif
#endif
