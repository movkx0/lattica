#ifndef LATTICA_MATRICT_ADAPTER_H
#define LATTICA_MATRICT_ADAPTER_H
#include <stddef.h>
#include <stdint.h>

/* Experimental author-code fixture adapter. Caller MUST serialize every call.
 * CPU must support AVX2, AES-NI and FMA. Amounts are restricted to [0, 2^52).
 * Statement contains the full ring, output accounts and serials, no witness.
 * 1 = success/valid; 0 = invalid input/proof; -1 = native/entropy failure.
 */
size_t lattica_matrict_statement_bytes(void);
size_t lattica_matrict_proof_bytes(void);
int lattica_matrict_fixture(const uint8_t context[32], uint64_t index,
    uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    uint8_t *statement, size_t statement_len,
    uint8_t *proof, size_t proof_len);
/* Public network parameter seed only; private randomness still comes from OS.
 * A NULL setup_seed preserves the original fresh-public-seed fixture behavior. */
int lattica_matrict_fixture_with_setup_seed(const uint8_t context[32],
    const uint8_t setup_seed[32], uint64_t index,
    uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    uint8_t *statement, size_t statement_len,
    uint8_t *proof, size_t proof_len);
int lattica_matrict_verify(const uint8_t context[32],
    const uint8_t *statement, size_t statement_len,
    const uint8_t *proof, size_t proof_len);
int lattica_matrict_challenge_selftest(void);
int lattica_matrict_reduction_selftest(void);
/* Secret witness export, no spend-proof creation. Caller owns and wipes all
 * 56965 returned u64 words, including failure buffers. Never log/serialize them.
 * Layout is the private GPU input ABI through scalars, excluding private entropy. */
int lattica_matrict_export_spend_fixture(const uint8_t context[32],
    const uint8_t setup_seed[32], uint64_t index,
    uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    uint64_t *out, size_t words);
#endif
