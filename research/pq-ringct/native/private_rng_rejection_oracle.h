#ifndef LATTICA_PRIVATE_RNG_REJECTION_ORACLE_H
#define LATTICA_PRIVATE_RNG_REJECTION_ORACLE_H
#ifdef LATTICA_NATIVE_SPEND_ORACLE
#include <stddef.h>
#include <stdint.h>

/* Caller must hold NATIVE_LOCK. All seed/input/output regions must be disjoint.
 * Results are private diagnostics: caller owns/wipes them and must not log them.
 * Return 1 on success, 0 for invalid shape, -1 for guarded native failure.
 * Raw calls: 1..256 lengths, total <= 1 MiB; zero lengths are allowed.
 * Progress is [blocks_after_call, calls_after_call] for each call, in order. */
int lattica_matrict_rng_calls_oracle(const uint8_t private_seed[32],
    const uint32_t *lengths, size_t count, uint8_t *out, size_t out_bytes,
    uint64_t *progress, size_t progress_words);

/* kind 0: rej_f(z[11],c[11]); kind 1: rej_z(z[8],c[8]).
 * kind 2: rej_op(z_out[18],z1[11],z2[11],z0[9],zb[10],x_rout[18],
 *                 x_rho[11],x_aut_rho[11],x_ri[9],x_rb[10]).
 * All arrays are row-major 256-u64 two's-complement coefficient bitpatterns.
 * Three result words: [decision (0 accept / 1 reject), private blocks, calls].
 * Counts include only this invocation; private AES is reset from seed at zero.
 * The original negative-dot rej_op exit returns reject without consuming RNG. */
int lattica_matrict_rejection_oracle(const uint8_t private_seed[32],
    uint32_t kind, const uint64_t *inputs, size_t input_words,
    uint64_t *result_words, size_t result_count);
#endif
#endif
