// Compile the shared integer-only wallet kernel bodies as native CUDA.
using ulong = u64;
using uint = u32;
#define __global
#define __kernel extern "C" __global__
#define LATTICA_WALLET_FN __device__ __forceinline__
#define get_global_id(dimension) ((u64)blockIdx.x * blockDim.x + threadIdx.x)
#define extl poseidon_external
__device__ __forceinline__ void intl(u64 *s, const u64 *diag) {
    u64 sum = 0;
    for (u32 i = 0; i < 8; ++i) sum = gl_add(sum, s[i]);
    for (u32 i = 0; i < 8; ++i) s[i] = gl_add(gl_mul(s[i], diag[i]), sum);
}
// The shared tree kernel receives the same four separately owned constant
// buffers as wallet trace generation. Keep its permutation on the device.
__device__ __forceinline__ void perm8(u64 *s, const u64 *rci,
        const u64 *rcp, const u64 *rcf, const u64 *diag) {
    extl(s);
    for (u32 r = 0; r < 4; ++r) {
        for (u32 i = 0; i < 8; ++i)
            s[i] = gl_pow7(gl_add(s[i], rci[r * 8 + i]));
        extl(s);
    }
    for (u32 r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], rcp[r]));
        intl(s, diag);
    }
    for (u32 r = 0; r < 4; ++r) {
        for (u32 i = 0; i < 8; ++i)
            s[i] = gl_pow7(gl_add(s[i], rcf[r * 8 + i]));
        extl(s);
    }
}
