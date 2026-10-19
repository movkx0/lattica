// FRI operates on the rescaled polynomial's unit subgroup, matching Plonky3.
// Consecutive physical entries are conjugate points in bit-reversed order.
extern "C" __global__ void fri_copy(const u64 *input, u64 first, u64 *output, u32 words) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < words) output[i] = gl_canon(input[first + i]);
}

template<u32 D, u32 K>
__device__ void fri_fold(const u64 *input, const u64 *challenge, u64 *output,
    u32 log_rows, u64 inverse_root) {
    const u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= (1U << (log_rows - K))) return;
    u64 values[1U << K][D], beta[D], root = inverse_root;
    #pragma unroll
    for (u32 j = 0; j < (1U << K); ++j) {
        #pragma unroll
        for (u32 c = 0; c < D; ++c) values[j][c] = input[((u64)row * (1U << K) + j) * D + c];
    }
    #pragma unroll
    for (u32 c = 0; c < D; ++c) beta[c] = challenge[c];
    #pragma unroll
    for (u32 pass = 0; pass < K; ++pass) {
        const u32 count = 1U << (K - pass - 1), bits = log_rows - pass - 1;
        #pragma unroll
        for (u32 j = 0; j < count; ++j) {
            const u64 inverse = gl_pow(root, bit_reverse(row * count + j, bits));
            u64 delta[D], product[D];
            #pragma unroll
            for (u32 c = 0; c < D; ++c) delta[c] = gl_sub(values[2*j][c], values[2*j+1][c]);
            fe_mul<D>(beta, delta, product);
            #pragma unroll
            for (u32 c = 0; c < D; ++c)
                values[j][c] = gl_canon(gl_mul(gl_add(gl_add(values[2*j][c], values[2*j+1][c]),
                    gl_mul(product[c], inverse)), 9223372034707292161ULL));
        }
        fe_mul<D>(beta, beta, beta);
        root = gl_mul(root, root);
    }
    #pragma unroll
    for (u32 c = 0; c < D; ++c) output[(u64)row * D + c] = values[0][c];
}

template<u32 D>
__device__ void fri_mix(const u64 *folded, const u64 *input, const u64 *challenge,
    u64 *output, u32 rows, u32 log_arity) {
    const u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 beta[D], value[D], product[D];
    for (u32 c = 0; c < D; ++c) beta[c] = challenge[c];
    for (u32 k = 0; k < log_arity; ++k) fe_mul<D>(beta, beta, beta);
    for (u32 c = 0; c < D; ++c) value[c] = input[(u64)row * D + c];
    fe_mul<D>(beta, value, product);
    for (u32 c = 0; c < D; ++c) output[(u64)row * D + c] = gl_canon(gl_add(folded[(u64)row * D + c], product[c]));
}

extern "C" __global__ void fri_gather(const u64 *input, const u64 *indices,
    u64 *output, u32 width, u32 queries) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i < (u64)width * queries) output[i] = gl_canon(input[indices[i / width] * width + i % width]);
}

#define FRI_FOLD(D, K) \
extern "C" __global__ void fri_fold_##D##_##K(const u64 *i, const u64 *b, u64 *o, u32 log_rows, u64 root) { fri_fold<D,K>(i,b,o,log_rows,root); }
FRI_FOLD(2,1)
FRI_FOLD(2,2)
FRI_FOLD(2,3)
FRI_FOLD(2,4)
FRI_FOLD(3,1)
FRI_FOLD(3,2)
FRI_FOLD(3,3)
FRI_FOLD(3,4)

#define FRI_MIX(D) \
extern "C" __global__ void fri_mix_##D(const u64 *f, const u64 *i, const u64 *b, u64 *o, u32 rows, u32 arity) { fri_mix<D>(f,i,b,o,rows,arity); }
FRI_MIX(2)
FRI_MIX(3)
