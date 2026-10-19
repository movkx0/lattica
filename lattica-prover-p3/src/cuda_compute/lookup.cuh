// Compile the shared integer LogUp kernels against native CUDA field arithmetic.
using ulong = u64;
using uint = u32;
#define __global
#define __local __shared__
#define __kernel extern "C" __global__
#define LATTICA_LOOKUP_FN __device__ __forceinline__
#define get_global_id(dimension) ((u64)blockIdx.x * blockDim.x + threadIdx.x)
#define get_local_id(dimension) threadIdx.x
#define get_group_id(dimension) ((u64)blockIdx.x)
#define barrier(flags) __syncthreads()
#define atomic_or(pointer, value) atomicOr(pointer, value)
__device__ __forceinline__ void opening_cubic_mul(const u64 *a, const u64 *b, u64 *out) {
    fe_mul<3>(a, b, out);
}
