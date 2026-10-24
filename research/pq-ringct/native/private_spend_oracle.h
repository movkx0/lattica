#ifndef LATTICA_PRIVATE_SPEND_ORACLE_H
#define LATTICA_PRIVATE_SPEND_ORACLE_H
#include <stddef.h>
#include <stdint.h>
#ifdef LATTICA_NATIVE_SPEND_ORACLE
/* Secret diagnostic digests and counters; never serialize or log these records. */
typedef struct {
  uint32_t phase,component;
  uint64_t bytes;
  uint8_t digest[32];
  uint64_t private_blocks;
} lattica_matrict_oracle_record;
void lattica_matrict_oracle_checkpoint(uint32_t phase,uint32_t component,
    const void *data,size_t bytes);
#define LATTICA_ORACLE_CHECKPOINT(phase,component,data,bytes) \
    lattica_matrict_oracle_checkpoint(phase,component,data,bytes)
int lattica_matrict_spend_oracle(const uint64_t *inputs,size_t words,
    const uint8_t private_seed[32],uint64_t attempt_limit,
    uint8_t *statement,size_t statement_len,uint8_t *proof,size_t proof_len,
    uint64_t *output_keys,size_t key_words,
    lattica_matrict_oracle_record *records,size_t capacity,size_t *record_count);
int lattica_matrict_sampler_oracle(const uint8_t private_seed[32],uint32_t kind,
    uint32_t one_rows,uint64_t *out,size_t words,uint64_t *blocks,uint64_t *calls);
#else
#define LATTICA_ORACLE_CHECKPOINT(phase,component,data,bytes) ((void)0)
#endif
#endif
