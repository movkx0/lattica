/* Source-derived C declared-object census, ABI version 1.
 * Include after state/bits and private_spend_fixture.inc in matrict.c.
 * This getter allocates nothing, samples nothing, reads no secret or global
 * mutable state, and may run before the native execution admission/lock.
 *
 * These are requested backing / declared object payloads, NOT compiler stack,
 * allocator, libc, Rust callback, driver, or physical RSS bounds. See the
 * source-census handoff for every declaration and hashed source preimage.
 * All static payloads in the linked native sources are charged once, including
 * legacy spend/gaussian storage not touched by the fresh fixture or verifier.
 * Automatic-object and parameter sums count every reachable nonrecursive
 * source function once and count all lexical scopes conservatively.
 */
#include <immintrin.h>
#include "declared_footprint.h"

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8 &&
    sizeof(unsigned long long) == 8 && sizeof(unsigned) == 4,
    "Declared footprint requires the pinned Linux x86_64 LP64 ABI");
_Static_assert(D == 256 && R == 64 && M == 2 && S == 2 && N_SPENT == 10 &&
    N == 4 && K == 4 && N_BAR == 4 && N_HAT == 5 && K_HAT == 5 &&
    CRYPTO_BYTES == 32 && W == 44 && WA == 39,
    "Declared footprint source census requires the pinned n10 profile");

int lattica_matrict_declared_footprint_v1(uint64_t *out, size_t words) {
  if (!out || words != LATTICA_MATRICT_DECLARED_FOOTPRINT_WORDS) return 0;
  out[0] = 1;
  out[1] = 0;
  out[2] = sizeof(state);
  out[3] =
      662 * sizeof(uint64_t) + 69 * sizeof(__m128i) +
      38 * sizeof(__m256i) + 5 * sizeof(__m256d) + 6 * sizeof(__m128d) +
      477160 * sizeof(unsigned char) + sizeof(jmp_buf) + sizeof(int) +
      46 * sizeof(uint8_t) + 218 * sizeof(POLY_R) + 574 * sizeof(POLY_Q) +
      89 * sizeof(POLY_QHAT);
  out[4] =
      7 * sizeof(__m128i) + sizeof(unsigned) + sizeof(ssize_t) +
      7 * sizeof(void *) + 6261 * sizeof(unsigned char) +
      2 * sizeof(unsigned long long) + 39 * sizeof(uint64_t) +
      18 * sizeof(size_t) + 23 * sizeof(POLY_Q) +
      173 * sizeof(uint8_t) + sizeof(int);
  out[5] = 64 * sizeof(void *) + 39 * sizeof(uint64_t) +
      5 * sizeof(size_t) + 4 * sizeof(unsigned long long);
  out[6] =
      7 * sizeof(__m128i) + 4 * sizeof(POLY_Q) + 665 * sizeof(uint64_t) +
      7689 * sizeof(unsigned char) + 2 * sizeof(unsigned long long) +
      3 * sizeof(uint32_t) + 3 * sizeof(unsigned) + 14 * sizeof(void *) +
      sizeof(int) + sizeof(POLY_R) + 2 * sizeof(POLY_QHAT) +
      141 * sizeof(uint8_t) + sizeof(bits) + 13 * sizeof(size_t) + sizeof(int64_t);
  out[7] = 130 * sizeof(void *) + 33 * sizeof(uint64_t) +
      4 * sizeof(unsigned long long) + 4 * sizeof(unsigned) +
      6 * sizeof(size_t) + sizeof(uint32_t) + sizeof(int64_t);
#ifdef LATTICA_NATIVE_SPEND_ORACLE
  out[1] = 1;
  out[3] += 4 * sizeof(uint64_t) + 7 * sizeof(size_t) + sizeof(void *);
  out[4] += sizeof(uint64_t);
#endif
  return 1;
}
