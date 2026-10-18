extern "C" __global__ void poseidon_permutation(
    const u64 *input, u64 *output, u32 rows, const u64 *constants) {
    const u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 s[8];
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) s[i] = input[row * 8 + i];
    poseidon_permute(s, constants);
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) output[row * 8 + i] = gl_canon(s[i]);
}

// Absorb columns in physical row order. A fragment may end in the middle of
// the rate; pending tracks that position across launches. Overwrite absorption
// and permutation only at rate boundaries match PaddingFreeSponge<8,4,4>.
extern "C" __global__ void commitment_absorb(
    const u64 *input, u64 *states, u32 rows, u32 width, u32 pending,
    const u64 *constants) {
    const u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 s[8];
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) s[i] = states[row * 8 + i];
    for (u32 col = 0; col < width; ++col) {
        s[pending++] = input[row * width + col];
        if (pending == 4) {
            poseidon_permute(s, constants);
            pending = 0;
        }
    }
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) states[row * 8 + i] = gl_canon(s[i]);
}

extern "C" __global__ void commitment_finalize(
    const u64 *states, u64 *tree, u32 rows, u32 pending, const u64 *constants) {
    const u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 s[8];
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) s[i] = states[row * 8 + i];
    if (pending) poseidon_permute(s, constants);
    #pragma unroll
    for (u32 i = 0; i < 4; ++i) tree[row * 4 + i] = gl_canon(s[i]);
}

// Finalize a streamed height group, optionally injecting its row digest into
// the already-compressed parent layer. No intermediate digest is downloaded.
extern "C" __global__ void commitment_finalize_at(const u64 *states, u64 *tree,
    u64 first, u32 rows, u32 pending, u32 inject, const u64 *constants) {
    const u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 s[8];
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) s[i] = states[row * 8 + i];
    if (pending) poseidon_permute(s, constants);
    if (inject) {
        #pragma unroll
        for (u32 i = 0; i < 4; ++i) s[4 + i] = s[i];
        #pragma unroll
        for (u32 i = 0; i < 4; ++i) s[i] = tree[first + row * 4 + i];
        poseidon_permute(s, constants);
    }
    #pragma unroll
    for (u32 i = 0; i < 4; ++i) tree[first + row * 4 + i] = gl_canon(s[i]);
}

// Adjacent, non-overlapping regions in one retained allocation. Each output
// thread reads its two children and owns a separate four-word parent digest.
extern "C" __global__ void commitment_compress(
    u64 *tree, u64 input_first, u64 output_first, u32 parents,
    const u64 *constants) {
    const u64 row = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= parents) return;
    u64 s[8];
    #pragma unroll
    for (u32 i = 0; i < 8; ++i) s[i] = tree[input_first + row * 8 + i];
    poseidon_permute(s, constants);
    #pragma unroll
    for (u32 i = 0; i < 4; ++i) tree[output_first + row * 4 + i] = gl_canon(s[i]);
}

extern "C" __global__ void commitment_paths(
    const u64 *tree, const u64 *indices, u64 *output, u32 height,
    u32 path_len, u32 queries) {
    const u64 item = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (item >= (u64)queries * path_len) return;
    const u32 query = (u32)(item / path_len), level = (u32)(item % path_len);
    const u64 rows = (u64)height >> level;
    const u64 preceding = 2ULL * height - 2ULL * rows;
    const u64 sibling = (indices[query] >> level) ^ 1ULL;
    #pragma unroll
    for (u32 i = 0; i < 4; ++i)
        output[item * 4 + i] = tree[(preceding + sibling) * 4 + i];
}
