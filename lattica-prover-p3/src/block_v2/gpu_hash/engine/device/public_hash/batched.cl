// Each workgroup owns one independent sequential sponge. Chunks are rate
// aligned except for the final suffix. A zero-count group preserves its state.
__attribute__((reqd_work_group_size(8, 1, 1)))
__kernel void device_public_hash_batch(__global ulong *states,
    __global const ulong *inputs, __global const ulong *metadata,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    const uint group = get_group_id(0), lane = get_local_id(0);
    __global const ulong *meta = metadata + (size_t)group * 4;
    __global const ulong *input = inputs + (size_t)group * 4096;
    __global ulong *state = states + (size_t)group * 4;
    const uint first = (uint)meta[2], count = (uint)meta[3];
    __local ulong words[8];
    ulong value = lane < 4u && !first ? state[lane] : 0UL;
    if (first && lane < 2u) value = meta[lane];
    const ulong diagonal = diag[lane];
    for (uint offset = 0; offset < count; offset += 4u) {
        if (lane >= 4u) {
            const uint index = offset + lane - 4u;
            value = index < count ? input[index] : 0UL;
        }
        value = public_hash_external(value, lane, words);
        #pragma unroll
        for (uint round = 0; round < 4u; ++round) {
            value = gl_pow7(gl_add(value, rci[round * 8u + lane]));
            value = public_hash_external(value, lane, words);
        }
        #pragma unroll
        for (uint round = 0; round < 22u; ++round) {
            if (lane == 0u) value = gl_pow7(gl_add(value, rcp[round]));
            value = public_hash_internal(value, lane, diagonal, words);
        }
        #pragma unroll
        for (uint round = 0; round < 4u; ++round) {
            value = gl_pow7(gl_add(value, rcf[round * 8u + lane]));
            value = public_hash_external(value, lane, words);
        }
    }
    if (lane < 4u) state[lane] = gl_canon(value);
}

#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void device_public_hash_batch_pair(__global ulong *states,
    __global const ulong *inputs, __global const ulong *metadata,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    const uint group = get_group_id(0), physical = get_local_id(0);
    const uint lane = physical >> 1, role = physical & 1u;
    __global const ulong *meta = metadata + (size_t)group * 4;
    __global const ulong *input = inputs + (size_t)group * 4096;
    __global ulong *state = states + (size_t)group * 4;
    const uint first = (uint)meta[2], count = (uint)meta[3];
    ulong value = lane < 4u && !first ? state[lane] : 0UL;
    if (first && lane < 2u) value = meta[lane];
    const ulong diagonal = diag[lane];
    for (uint offset = 0; offset < count; offset += 4u) {
        if (lane >= 4u) {
            const uint index = offset + lane - 4u;
            value = index < count ? input[index] : 0UL;
        }
        value = public_hash_pair_external(value, lane, role);
        #pragma unroll
        for (uint round = 0; round < 4u; ++round) {
            value = public_hash_pair_pow7(gl_add(value, rci[round * 8u + lane]), physical);
            value = public_hash_pair_external(value, lane, role);
        }
        #pragma unroll
        for (uint round = 0; round < 22u; ++round) {
            const ulong powered = public_hash_pair_pow7(gl_add(value, rcp[round]), physical);
            if (lane == 0u) value = powered;
            value = public_hash_pair_internal(value, lane, role, diagonal);
        }
        #pragma unroll
        for (uint round = 0; round < 4u; ++round) {
            value = public_hash_pair_pow7(gl_add(value, rcf[round * 8u + lane]), physical);
            value = public_hash_pair_external(value, lane, role);
        }
    }
    if (role == 0u && lane < 4u) state[lane] = gl_canon(value);
}
#endif
