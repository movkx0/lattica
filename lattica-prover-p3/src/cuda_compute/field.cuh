// Goldilocks arithmetic modulo 2^64 - 2^32 + 1. Intermediate words may be
// noncanonical; every kernel boundary explicitly canonicalizes its output.
// No floating point, approximate reciprocal, or signed-overflow arithmetic.
#ifndef LATTICA_CUDA_FIELD
#define LATTICA_CUDA_FIELD
using u64 = unsigned long long;
using u32 = unsigned int;
static_assert(sizeof(u64) == 8 && sizeof(u32) == 4, "field ABI widths");
constexpr u64 GP = 0xffffffff00000001ULL;
constexpr u64 NEG_ORDER = 0xffffffffULL;

__device__ __forceinline__ u64 gl_canon(u64 x) {
    return x >= GP ? x - GP : x;
}
__device__ __forceinline__ u64 gl_reduce128(u64 lo, u64 hi) {
    const u32 hh = (u32)(hi >> 32), hl = (u32)hi;
    u64 t0 = lo - (u64)hh;
    if (lo < (u64)hh) t0 -= NEG_ORDER;
    const u64 t1 = (u64)hl * NEG_ORDER;
    u64 t2 = t0 + t1;
    if (t2 < t0) t2 += NEG_ORDER;
    return t2;
}
__device__ __forceinline__ u64 gl_mul(u64 a, u64 b) {
    return gl_reduce128(a * b, __umul64hi(a, b));
}
__device__ __forceinline__ u64 gl_add(u64 a, u64 b) {
    const u64 s = a + b;
    const u64 t = s + (s < a ? NEG_ORDER : 0ULL);
    return t + (t < s ? NEG_ORDER : 0ULL);
}
__device__ __forceinline__ u64 gl_neg(u64 x) {
    const u64 c = gl_canon(x);
    return c == 0 ? 0 : GP - c;
}
__device__ __forceinline__ u64 gl_sub(u64 a, u64 b) {
    return gl_add(a, gl_neg(b));
}
__device__ __forceinline__ u64 gl_pow(u64 base, u64 exponent) {
    u64 result = 1;
    while (exponent) {
        if (exponent & 1) result = gl_mul(result, base);
        base = gl_mul(base, base);
        exponent >>= 1;
    }
    return result;
}
__device__ __forceinline__ u64 gl_inverse_or_zero(u64 value) {
    return gl_pow(value, GP - 2);
}
__device__ __forceinline__ u32 bit_reverse(u32 value, u32 bits) {
    return bits ? __brev(value) >> (32 - bits) : 0;
}

// Alias-safe operations in the existing bases: X^2 = 7 and X^3 = X + 1.
template<u32 D>
__device__ __forceinline__ void fe_mul(const u64 *a, const u64 *b, u64 *out) {
    static_assert(D >= 1 && D <= 3, "supported field degree");
    u64 r[D];
    if constexpr (D == 1) {
        r[0] = gl_mul(a[0], b[0]);
    } else if constexpr (D == 2) {
        r[0] = gl_add(gl_mul(a[0], b[0]), gl_mul(7, gl_mul(a[1], b[1])));
        r[1] = gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0]));
    } else {
        const u64 c3 = gl_add(gl_mul(a[1], b[2]), gl_mul(a[2], b[1]));
        const u64 c4 = gl_mul(a[2], b[2]);
        r[0] = gl_add(gl_mul(a[0], b[0]), c3);
        r[1] = gl_add(gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0])), gl_add(c3, c4));
        r[2] = gl_add(gl_add(gl_add(gl_mul(a[0], b[2]), gl_mul(a[1], b[1])), gl_mul(a[2], b[0])), c4);
    }
    #pragma unroll
    for (u32 i = 0; i < D; ++i) out[i] = r[i];
}

template<u32 D>
__device__ __forceinline__ void fe_inverse_or_zero(const u64 *a, u64 *out) {
    u64 r[D];
    if constexpr (D == 1) {
        r[0] = gl_inverse_or_zero(a[0]);
    } else if constexpr (D == 2) {
        const u64 norm = gl_sub(gl_mul(a[0], a[0]), gl_mul(7, gl_mul(a[1], a[1])));
        const u64 inverse = gl_inverse_or_zero(norm);
        r[0] = gl_mul(a[0], inverse);
        r[1] = gl_neg(gl_mul(a[1], inverse));
    } else {
        // Adjugate of multiplication by a in F[X]/(X^3-X-1).
        const u64 t = gl_add(a[0], a[2]);
        const u64 b0 = gl_sub(gl_mul(t, t), gl_mul(a[1], gl_add(a[1], a[2])));
        const u64 b1 = gl_sub(gl_mul(a[2], a[2]), gl_mul(a[0], a[1]));
        const u64 b2 = gl_sub(gl_mul(a[1], a[1]), gl_mul(a[2], t));
        const u64 norm = gl_add(gl_add(gl_mul(a[0], b0), gl_mul(a[2], b1)), gl_mul(a[1], b2));
        const u64 inverse = gl_inverse_or_zero(norm);
        r[0] = gl_mul(b0, inverse);
        r[1] = gl_mul(b1, inverse);
        r[2] = gl_mul(b2, inverse);
    }
    #pragma unroll
    for (u32 i = 0; i < D; ++i) out[i] = r[i];
}

template<u32 D>
__device__ __forceinline__ void fe_pow(const u64 *a, u64 exponent, u64 *out) {
    u64 base[D], result[D] = {1};
    #pragma unroll
    for (u32 i = 0; i < D; ++i) base[i] = a[i];
    while (exponent) {
        if (exponent & 1) fe_mul<D>(result, base, result);
        fe_mul<D>(base, base, base);
        exponent >>= 1;
    }
    #pragma unroll
    for (u32 i = 0; i < D; ++i) out[i] = result[i];
}
#endif
