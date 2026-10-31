// Standalone source-only experiment, intentionally absent from KERNEL_SRC.
// Requires sbox_pair.cl's uniform sixteen-lane helpers. No protocol constants,
// message layout, transcript state or production selector is changed.
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)

// Exact raw-representative equivalent of gl_mul(value, GP-2), including inputs
// in [GP,2^64). Let B=2^32, M=2^64, GP-2=M-(B+1). First construct both halves
// of value*(B+1), then subtract them from value*M. Calling the SAME reducer on
// the exact product halves preserves more than congruence modulo GP.
inline ulong public_hash_fused_neg2_raw(ulong value) {
    ulong high_word = value >> 32;
    ulong low_word = (ulong)(uint)value;
    ulong middle = high_word + low_word;
    ulong weighted_low = (middle << 32) | low_word;
    ulong weighted_high = high_word + (middle >> 32);
    ulong product_low = 0UL - weighted_low;
    ulong product_high = value - weighted_high - (ulong)(weighted_low != 0UL);
    return gl_reduce128(product_low, product_high);
}

inline ulong public_hash_fused_partial(ulong original, uint physical,
                                      ulong round_constant, ulong diagonal) {
    uint lane = physical >> 1;
    uint role = physical & 1u;
    uint nonlinear = lane == 0u;
    ulong input = gl_add(original, round_constant);
    // Word zero uses the established pair x^7 schedule. Every other word
    // computes its diagonal product in role zero and the unit in role one.
    // Those products use otherwise unnecessary S-box multiply instructions.
    ulong left = nonlinear ? input : (role ? 1UL : original);
    ulong right = nonlinear ? input : (role ? 1UL : diagonal);
    ulong first = gl_mul(left, right);
    ulong factor = nonlinear ? (role ? first : input) : 1UL;
    ulong partial = gl_mul(first, factor);
    ulong partner = public_hash_pair_exchange(partial, physical ^ 1u);
    ulong product = gl_mul(partial, partner);
    // Both roles again contain the exact same representative. Preserve the
    // untouched words for the sum; only logical word zero adopts the S-box.
    ulong value = nonlinear ? product : original;
    ulong diagonal_product = nonlinear ? public_hash_fused_neg2_raw(product) : product;
    ulong sum = gl_add(value, public_hash_pair_logical(value, lane ^ 1u, role));
    sum = gl_add(sum, public_hash_pair_logical(sum, lane ^ 2u, role));
    sum = gl_add(sum, public_hash_pair_logical(sum, lane ^ 4u, role));
    return gl_add(diagonal_product, sum);
}

__attribute__((reqd_work_group_size(16, 1, 1)))
__kernel void device_public_hash_fused_partial_probe(__global ulong *state,
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
            value = public_hash_fused_partial(value, physical, rcp[round], diagonal);
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
__kernel void public_hash_fused_partial_raw_probe(__global ulong *scratch,
    __global const ulong *diag, ulong round_constant) {
    const uint physical = get_local_id(0);
    const uint lane = physical >> 1;
    const uint role = physical & 1u;
    const ulong original = scratch[lane];
    const ulong diagonal = diag[lane];
    const ulong candidate = public_hash_fused_partial(original, physical, round_constant, diagonal);
    // Uniform reference schedule identical to sbox-pair-v1 partial rounds.
    ulong powered = public_hash_pair_pow7(gl_add(original, round_constant), physical);
    ulong value = lane == 0u ? powered : original;
    ulong baseline = public_hash_pair_internal(value, lane, role, diagonal);
    scratch[8u + physical] = candidate;
    scratch[24u + physical] = baseline;
    scratch[40u + physical] = public_hash_fused_neg2_raw(original);
    scratch[56u + physical] = gl_mul(original, GP - 2UL);
}
#endif
