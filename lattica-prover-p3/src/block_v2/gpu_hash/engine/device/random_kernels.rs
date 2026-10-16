//! ChaCha20's original 64-bit counter/64-bit stream layout, as used by
//! rand_chacha 0.10. Field sampling follows p3-goldilocks 0.6.1 exactly.
pub(crate) const KERNEL_SRC: &str = r#"
#define RANDOM_QR(a,b,c,d) { \
    x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 16U); \
    x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 12U); \
    x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 8U); \
    x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 7U); \
}
__kernel void device_random_chacha20(__global const ulong *seed,
    __global ulong *raw, ulong first_block, ulong stream, uint blocks) {
    size_t block = get_global_id(0);
    if (block >= blocks) return;
    ulong counter = first_block + block;
    uint initial[16] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        (uint)seed[0], (uint)(seed[0] >> 32),
        (uint)seed[1], (uint)(seed[1] >> 32),
        (uint)seed[2], (uint)(seed[2] >> 32),
        (uint)seed[3], (uint)(seed[3] >> 32),
        (uint)counter, (uint)(counter >> 32), (uint)stream, (uint)(stream >> 32)
    };
    uint x[16];
    for (uint i = 0; i < 16; ++i) x[i] = initial[i];
    for (uint round = 0; round < 10; ++round) {
        RANDOM_QR(0,4,8,12); RANDOM_QR(1,5,9,13);
        RANDOM_QR(2,6,10,14); RANDOM_QR(3,7,11,15);
        RANDOM_QR(0,5,10,15); RANDOM_QR(1,6,11,12);
        RANDOM_QR(2,7,8,13); RANDOM_QR(3,4,9,14);
    }
    for (uint i = 0; i < 16; ++i) x[i] += initial[i];
    for (uint i = 0; i < 8; ++i)
        raw[block * 8 + i] = (ulong)x[2*i] | ((ulong)x[2*i+1] << 32);
}
#undef RANDOM_QR
inline uint random_u32(__global const ulong *raw, uint at) {
    return (uint)(raw[at >> 1] >> (32U * (at & 1U)));
}
inline ulong random_u64(__global const ulong *raw, uint offset, uint index) {
    uint at = offset + 2U * index;
    return (ulong)random_u32(raw, at) | ((ulong)random_u32(raw, at + 1U) << 32);
}
// Each tile keeps the reference order. Counts and their exclusive offsets
// are integer bookkeeping, never field reductions of rejected samples.
// All 128 lanes participate, including the last partial tile. Each lane
// handles two words; global reads and accepted writes are contiguous.
__attribute__((reqd_work_group_size(128, 1, 1)))
__kernel void device_random_counts(__global const ulong *raw,
    __global ulong *counts, uint offset, uint count) {
    uint tile = get_group_id(0), lane = get_local_id(0);
    uint first = tile * 256U + lane, second = first + 128U;
    __local uint accepted[128];
    uint a = first < count && random_u64(raw, offset, first) < 0xffffffff00000001UL;
    uint b = second < count && random_u64(raw, offset, second) < 0xffffffff00000001UL;
    accepted[lane] = a + b;
    for (uint stride = 64U; stride != 0U; stride >>= 1U) {
        barrier(CLK_LOCAL_MEM_FENCE);
        if (lane < stride) accepted[lane] += accepted[lane + stride];
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    if (lane == 0U) counts[tile] = accepted[0];
}
// BATCH_WORDS / TILE_WORDS is at most 4096. Counts are at most 256,
// so every scan sum fits in uint. The host rejects larger batches before
// dispatch. Pad only to the next power of two, including partial tiles.
__attribute__((reqd_work_group_size(128, 1, 1)))
__kernel void device_random_offsets(__global const ulong *counts,
    __global ulong *offsets, __global ulong *total, uint tiles) {
    uint lane = get_local_id(0), width = 1U;
    while (width < tiles) width <<= 1U;
    __local uint prefix[4096];
    for (uint i = lane; i < width; i += 128U)
        prefix[i] = i < tiles ? (uint)counts[i] : 0U;
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = 1U; stride < width; stride <<= 1U) {
        for (uint at = (lane + 1U) * (stride << 1U) - 1U;
             at < width; at += 128U * (stride << 1U))
            prefix[at] += prefix[at - stride];
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (lane == 0U) {
        total[0] = (ulong)prefix[width - 1U];
        prefix[width - 1U] = 0U;
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = width >> 1U; stride != 0U; stride >>= 1U) {
        for (uint at = (lane + 1U) * (stride << 1U) - 1U;
             at < width; at += 128U * (stride << 1U)) {
            uint left = prefix[at - stride];
            prefix[at - stride] = prefix[at];
            prefix[at] += left;
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    for (uint i = lane; i < tiles; i += 128U) offsets[i] = (ulong)prefix[i];
}
__attribute__((reqd_work_group_size(128, 1, 1)))
__kernel void device_random_scatter(__global const ulong *raw,
    __global const ulong *offsets, __global ulong *output,
    uint offset, uint count, ulong output_start) {
    uint tile = get_group_id(0), lane = get_local_id(0);
    uint first = tile * 256U + lane, second = first + 128U;
    ulong a = first < count ? random_u64(raw, offset, first) : 0UL;
    ulong b = second < count ? random_u64(raw, offset, second) : 0UL;
    uint valid_a = first < count && a < 0xffffffff00000001UL;
    uint valid_b = second < count && b < 0xffffffff00000001UL;
    __local uint prefix[256];
    prefix[lane] = valid_a;
    prefix[lane + 128U] = valid_b;
    // Blelloch exclusive scan: offsets remain in original sample order,
    // regardless of which lanes execute first or which samples are rejected.
    for (uint stride = 1U; stride < 256U; stride <<= 1U) {
        barrier(CLK_LOCAL_MEM_FENCE);
        uint at = (lane + 1U) * (stride << 1U) - 1U;
        if (at < 256U) prefix[at] += prefix[at - stride];
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    if (lane == 0U) prefix[255] = 0U;
    for (uint stride = 128U; stride != 0U; stride >>= 1U) {
        barrier(CLK_LOCAL_MEM_FENCE);
        uint at = (lane + 1U) * (stride << 1U) - 1U;
        if (at < 256U) {
            uint left = prefix[at - stride];
            prefix[at - stride] = prefix[at];
            prefix[at] += left;
        }
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    ulong base = output_start + offsets[tile];
    if (valid_a) output[base + prefix[lane]] = a;
    if (valid_b) output[base + prefix[lane + 128U]] = b;
}
"#;

// The preceding production offset kernel is available only to GPU tests.
// Paired diagnostics keep the parallel count and scatter kernels identical.
#[cfg(test)]
pub(crate) const REFERENCE_KERNEL_SRC: &str = r#"
__kernel void device_random_offsets_serial_reference(__global const ulong *counts,
    __global ulong *offsets, __global ulong *total, uint tiles) {
    ulong sum = 0;
    for (uint i = 0; i < tiles; ++i) {
        offsets[i] = sum;
        sum += counts[i];
    }
    total[0] = sum;
}
"#;
