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
