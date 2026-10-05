// Exact Goldilocks multiplication in SME streaming mode, using SVE integer
// lanes. No ZA tile, floating point, approximate reduction, or Apple private ABI.
// ACLE: https://arm-software.github.io/acle/main/acle.html
#include <arm_sve.h>
#include <arm_sme.h>
#include <stdint.h>
#include <stddef.h>

__arm_locally_streaming size_t lattica_sme2_lanes(void) { return svcntd(); }

__arm_locally_streaming void lattica_sme2_mul(
    const uint64_t *a, const uint64_t *b, uint64_t *out, size_t n) {
    const uint64_t epsilon = UINT64_C(0xffffffff);
    const uint64_t modulus = UINT64_C(0xffffffff00000001);
    for (size_t i = 0; i < n; i += svcntd()) {
        svbool_t pg = svwhilelt_b64_u64(i, n);
        svuint64_t x = svld1_u64(pg, a + i), y = svld1_u64(pg, b + i);
        svuint64_t lo = svmul_u64_x(pg, x, y);
        svuint64_t hi = svmulh_u64_x(pg, x, y);
        svuint64_t hi_hi = svlsr_n_u64_x(pg, hi, 32);
        svuint64_t hi_lo = svand_n_u64_x(pg, hi, epsilon);
        // 2^64 = epsilon and 2^96 = -1 (mod p).
        svuint64_t t0 = svsub_u64_x(pg, lo, hi_hi);
        svbool_t borrow = svcmplt_u64(pg, lo, hi_hi);
        t0 = svsub_u64_x(pg, t0, svsel_u64(borrow, svdup_u64(epsilon), svdup_u64(0)));
        svuint64_t t1 = svmul_n_u64_x(pg, hi_lo, epsilon);
        svuint64_t sum = svadd_u64_x(pg, t0, t1);
        svbool_t carry = svcmplt_u64(pg, sum, t0);
        sum = svadd_u64_x(pg, sum, svsel_u64(carry, svdup_u64(epsilon), svdup_u64(0)));
        svbool_t reduce = svcmpge_n_u64(pg, sum, modulus);
        sum = svsub_u64_x(pg, sum, svsel_u64(reduce, svdup_u64(modulus), svdup_u64(0)));
        svst1_u64(pg, out + i, sum);
    }
}
