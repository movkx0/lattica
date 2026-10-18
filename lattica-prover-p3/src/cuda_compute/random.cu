// CUDA port of the maintained rand_chacha 0.10 / Goldilocks sampler.
// ChaCha blocks use a 64-bit block counter and a 64-bit stream identifier.
__device__ __forceinline__ u32 random_rotate(u32 value, u32 shift) {
    return (value << shift) | (value >> (32 - shift));
}

#define RANDOM_QR(a,b,c,d) { \
    x[a] += x[b]; x[d] = random_rotate(x[d] ^ x[a], 16U); \
    x[c] += x[d]; x[b] = random_rotate(x[b] ^ x[c], 12U); \
    x[a] += x[b]; x[d] = random_rotate(x[d] ^ x[a], 8U); \
    x[c] += x[d]; x[b] = random_rotate(x[b] ^ x[c], 7U); \
}
extern "C" __global__ void device_random_chacha20(const u64 *seed,
    u64 *raw, u64 first_block, u64 stream, u32 blocks) {
    u64 block = (blockIdx.x * blockDim.x + threadIdx.x);
    if (block >= blocks) return;
    u64 counter = first_block + block;
    u32 initial[16] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        (u32)seed[0], (u32)(seed[0] >> 32),
        (u32)seed[1], (u32)(seed[1] >> 32),
        (u32)seed[2], (u32)(seed[2] >> 32),
        (u32)seed[3], (u32)(seed[3] >> 32),
        (u32)counter, (u32)(counter >> 32), (u32)stream, (u32)(stream >> 32)
    };
    u32 x[16];
    for (u32 i = 0; i < 16; ++i) x[i] = initial[i];
    for (u32 round = 0; round < 10; ++round) {
        RANDOM_QR(0,4,8,12); RANDOM_QR(1,5,9,13);
        RANDOM_QR(2,6,10,14); RANDOM_QR(3,7,11,15);
        RANDOM_QR(0,5,10,15); RANDOM_QR(1,6,11,12);
        RANDOM_QR(2,7,8,13); RANDOM_QR(3,4,9,14);
    }
    for (u32 i = 0; i < 16; ++i) x[i] += initial[i];
    for (u32 i = 0; i < 8; ++i)
        raw[block * 8 + i] = (u64)x[2*i] | ((u64)x[2*i+1] << 32);
}
#undef RANDOM_QR
__device__ __forceinline__ u32 random_u32(const u64 *raw, u32 at) {
    return (u32)(raw[at >> 1] >> (32U * (at & 1U)));
}
__device__ __forceinline__ u64 random_u64(const u64 *raw, u32 offset, u32 index) {
    u32 at = offset + 2U * index;
    return (u64)random_u32(raw, at) | ((u64)random_u32(raw, at + 1U) << 32);
}
// Each tile keeps the reference order. Counts and their exclusive offsets
// are integer bookkeeping, never field reductions of rejected samples.
// All 128 lanes participate, including the last partial tile. Each lane
// handles two words; global reads and accepted writes are contiguous.

extern "C" __global__ void device_random_counts(const u64 *raw,
    u64 *counts, u32 offset, u32 count) {
    u32 tile = blockIdx.x, lane = threadIdx.x;
    u32 first = tile * 256U + lane, second = first + 128U;
    __shared__ u32 accepted[128];
    u32 a = first < count && random_u64(raw, offset, first) < 0xffffffff00000001ULL;
    u32 b = second < count && random_u64(raw, offset, second) < 0xffffffff00000001ULL;
    accepted[lane] = a + b;
    for (u32 stride = 64U; stride != 0U; stride >>= 1U) {
        __syncthreads();
        if (lane < stride) accepted[lane] += accepted[lane + stride];
    }
    __syncthreads();
    if (lane == 0U) counts[tile] = accepted[0];
}
// BATCH_WORDS / TILE_WORDS is at most 4096. Counts are at most 256,
// so every scan sum fits in u32. The host rejects larger batches before
// dispatch. Pad only to the next power of two, including partial tiles.

extern "C" __global__ void device_random_offsets(const u64 *counts,
    u64 *offsets, u64 *total, u32 tiles) {
    u32 lane = threadIdx.x, width = 1U;
    while (width < tiles) width <<= 1U;
    __shared__ u32 prefix[4096];
    for (u32 i = lane; i < width; i += 128U)
        prefix[i] = i < tiles ? (u32)counts[i] : 0U;
    __syncthreads();
    for (u32 stride = 1U; stride < width; stride <<= 1U) {
        for (u32 at = (lane + 1U) * (stride << 1U) - 1U;
             at < width; at += 128U * (stride << 1U))
            prefix[at] += prefix[at - stride];
        __syncthreads();
    }
    if (lane == 0U) {
        total[0] = (u64)prefix[width - 1U];
        prefix[width - 1U] = 0U;
    }
    __syncthreads();
    for (u32 stride = width >> 1U; stride != 0U; stride >>= 1U) {
        for (u32 at = (lane + 1U) * (stride << 1U) - 1U;
             at < width; at += 128U * (stride << 1U)) {
            u32 left = prefix[at - stride];
            prefix[at - stride] = prefix[at];
            prefix[at] += left;
        }
        __syncthreads();
    }
    for (u32 i = lane; i < tiles; i += 128U) offsets[i] = (u64)prefix[i];
}

extern "C" __global__ void device_random_scatter(const u64 *raw,
    const u64 *offsets, u64 *output,
    u32 offset, u32 count, u64 output_start) {
    u32 tile = blockIdx.x, lane = threadIdx.x;
    u32 first = tile * 256U + lane, second = first + 128U;
    u64 a = first < count ? random_u64(raw, offset, first) : 0UL;
    u64 b = second < count ? random_u64(raw, offset, second) : 0UL;
    u32 valid_a = first < count && a < 0xffffffff00000001ULL;
    u32 valid_b = second < count && b < 0xffffffff00000001ULL;
    __shared__ u32 prefix[256];
    prefix[lane] = valid_a;
    prefix[lane + 128U] = valid_b;
    // Blelloch exclusive scan: offsets remain in original sample order,
    // regardless of which lanes execute first or which samples are rejected.
    for (u32 stride = 1U; stride < 256U; stride <<= 1U) {
        __syncthreads();
        u32 at = (lane + 1U) * (stride << 1U) - 1U;
        if (at < 256U) prefix[at] += prefix[at - stride];
    }
    __syncthreads();
    if (lane == 0U) prefix[255] = 0U;
    for (u32 stride = 128U; stride != 0U; stride >>= 1U) {
        __syncthreads();
        u32 at = (lane + 1U) * (stride << 1U) - 1U;
        if (at < 256U) {
            u32 left = prefix[at - stride];
            prefix[at - stride] = prefix[at];
            prefix[at] += left;
        }
    }
    __syncthreads();
    u64 base = output_start + offsets[tile];
    if (valid_a) output[base + prefix[lane]] = a;
    if (valid_b) output[base + prefix[lane + 128U]] = b;
}
