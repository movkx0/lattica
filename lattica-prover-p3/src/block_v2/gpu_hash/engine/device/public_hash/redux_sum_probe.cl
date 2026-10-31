// Standalone source-only SM80+ experiment, absent from production KERNEL_SRC.
// See redux_sum_probe.md for exact limb bounds, participation, and raw-value
// obligations. S-boxes, diagonal products, matrix, and sponge framing are intact.
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE) && defined(LATTICA_PUBLIC_HASH_NVIDIA_REDUX_PROBE)
inline uint public_hash_redux_limb(uint value, uint role) {
    uint total;
    // Two disjoint eight-thread groups. All sixteen threads execute this exact
    // instruction; every named thread supplies the same mask as its peers.
    uint members = role ? 43690u : 21845u; // 0xaaaa / 0x5555
    asm volatile("redux.sync.add.u32 %0, %1, %2;" : "=r"(total) : "r"(value), "r"(members));
    return total;
}

inline ulong public_hash_redux_sum(ulong value, uint physical) {
    uint role = physical & 1u;
    // Equal raw words in each lane pair are a kernel invariant, not merely
    // equal field classes. Each role reduces two limbs of its assigned word.
    uint word = (uint)(value >> (32u * role));
    uint low = public_hash_redux_limb(word & 65535u, role);
    uint high = public_hash_redux_limb(word >> 16, role);
    // Each limb total is <=8*(2^16-1); subtotal is <=8*(2^32-1).
    ulong subtotal = (ulong)low + ((ulong)high << 16);
    ulong other = public_hash_pair_exchange(subtotal, physical ^ 1u);
    ulong lower = role ? other : subtotal;
    ulong upper = role ? subtotal : other;
    ulong bottom = lower + (upper << 32);
    ulong top = (upper >> 32) + (ulong)(bottom < lower);
    // The exact sum is bottom + top*2^64, with top<=7. Existing gl_add supports
    // every u64 representative and folds 2^64 == 2^32-1 (mod GP).
    return gl_add(bottom, top * NEG_ORDER);
}

inline ulong public_hash_redux_internal(ulong value, uint physical, ulong diagonal) {
    return gl_add(gl_mul(value, diagonal), public_hash_redux_sum(value, physical));
}

__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void device_public_hash_redux_sum_probe(__global ulong *state,
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
            ulong powered = public_hash_pair_pow7(gl_add(value, rcp[round]), physical);
            if (lane == 0u) value = powered;
            value = public_hash_redux_internal(value, physical, diagonal);
        }
#pragma unroll
        for (uint round = 0; round < 4u; ++round) {
            value = public_hash_pair_pow7(gl_add(value, rcf[round * 8u + lane]), physical);
            value = public_hash_pair_external(value, lane, role);
        }
    }
    if (role == 0u && lane < 4u) state[lane] = gl_canon(value);
}

__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void public_hash_redux_sum_raw_probe(__global ulong *scratch,
    __global const ulong *diag, ulong round_constant) {
    const uint physical = get_local_id(0);
    const uint lane = physical >> 1;
    const uint role = physical & 1u;
    const ulong original = scratch[lane];
    const ulong diagonal = diag[lane];
    const ulong candidate_sum = public_hash_redux_sum(original, physical);
    ulong baseline_sum = gl_add(original, public_hash_pair_logical(original, lane ^ 1u, role));
    baseline_sum = gl_add(baseline_sum, public_hash_pair_logical(baseline_sum, lane ^ 2u, role));
    baseline_sum = gl_add(baseline_sum, public_hash_pair_logical(baseline_sum, lane ^ 4u, role));
    scratch[8u + physical] = candidate_sum;
    scratch[24u + physical] = baseline_sum;
    scratch[40u + physical] = public_hash_redux_internal(original, physical, diagonal);
    scratch[56u + physical] = public_hash_pair_internal(original, lane, role, diagonal);
    ulong candidate = original;
    ulong baseline = original;
    // Deliberately retain each path's own possibly different raw representative
    // between rounds. Both use the same arbitrary full-u64 test constant.
    for (uint round = 0; round < 22u; ++round) {
        ulong powered = public_hash_pair_pow7(gl_add(candidate, round_constant), physical);
        if (lane == 0u) candidate = powered;
        candidate = public_hash_redux_internal(candidate, physical, diagonal);
        powered = public_hash_pair_pow7(gl_add(baseline, round_constant), physical);
        if (lane == 0u) baseline = powered;
        baseline = public_hash_pair_internal(baseline, lane, role, diagonal);
    }
    scratch[72u + physical] = candidate;
    scratch[88u + physical] = baseline;
}
#endif
