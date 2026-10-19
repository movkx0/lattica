// Native adapters for the shared recursive execution kernels.
// The field, lookup and wallet adapters supply the integer arithmetic helpers.
#define LATTICA_WITNESS_FN __device__ __forceinline__
__device__ __forceinline__ void perm8(u64 *s, const u64 *rci,
    const u64 *rcp, const u64 *rcf, const u64 *diag) {
    extl(s);
    for (u32 r = 0; r < 4; ++r) {
        for (u32 j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rci[r * 8 + j]));
        extl(s);
    }
    for (u32 r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], rcp[r]));
        intl(s, diag);
    }
    for (u32 r = 0; r < 4; ++r) {
        for (u32 j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rcf[r * 8 + j]));
        extl(s);
    }
}
