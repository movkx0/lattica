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
__kernel void device_random_counts(__global const ulong *raw,
    __global ulong *counts, uint offset, uint count) {
    uint tile = get_global_id(0), begin = tile * 256U;
    if (begin >= count) return;
    uint end = min(begin + 256U, count);
    ulong accepted = 0;
    for (uint i = begin; i < end; ++i)
        accepted += random_u64(raw, offset, i) < 0xffffffff00000001UL;
    counts[tile] = accepted;
}
__kernel void device_random_offsets(__global const ulong *counts,
    __global ulong *offsets, __global ulong *total, uint tiles) {
    ulong sum = 0;
    for (uint i = 0; i < tiles; ++i) {
        offsets[i] = sum;
        sum += counts[i];
    }
    total[0] = sum;
}
__kernel void device_random_scatter(__global const ulong *raw,
    __global const ulong *offsets, __global ulong *output,
    uint offset, uint count, ulong output_start) {
    uint tile = get_global_id(0), begin = tile * 256U;
    if (begin >= count) return;
    uint end = min(begin + 256U, count);
    ulong at = output_start + offsets[tile];
    for (uint i = begin; i < end; ++i) {
        ulong sample = random_u64(raw, offset, i);
        if (sample < 0xffffffff00000001UL) output[at++] = sample;
    }
}
"#;
