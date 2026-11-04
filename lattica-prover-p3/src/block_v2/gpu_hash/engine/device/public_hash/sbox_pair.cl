// Opt-in public hash kernel; shared pair helpers are always compiled.
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void device_public_hash_sbox_pair(__global ulong *state,
    __global const ulong *input, const ulong domain, const ulong length,
    const uint first, const uint count, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf,
    __global const ulong *diag) {
    const uint physical = get_local_id(0);
    const uint lane = physical >> 1;
    const uint role = physical & 1u;
    ulong value = lane < 4u && !first ? state[lane] : 0UL;
    if (first && lane < 2u) value = lane == 0u ? domain : length;
    const ulong diagonal = diag[lane];
    for (uint offset = 0; offset < count; offset += 4u) {
        if (lane >= 4u) {
            uint index = offset + lane - 4u;
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
            // Uniform execution is required by the sixteen-lane member mask.
            // Only logical word zero adopts the partial-round S-box result.
            ulong powered = public_hash_pair_pow7(gl_add(value, rcp[round]), physical);
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
