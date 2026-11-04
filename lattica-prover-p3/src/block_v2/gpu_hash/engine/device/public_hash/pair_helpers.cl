// Shared NVIDIA sponge helpers for raw fields and the opt-in public hash. Two physical lanes represent one
// logical word; all sixteen lanes execute every exchange with the same mask.
// The four-word rate, domain/length prefix, permutation and output are unchanged.
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
inline ulong public_hash_pair_exchange(ulong value, uint physical_source) {
    uint low, high;
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, 65535;" : "=r"(low) : "r"((uint)value), "r"(physical_source));
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, 65535;" : "=r"(high) : "r"((uint)(value >> 32)), "r"(physical_source));
    return ((ulong)high << 32) | (ulong)low;
}

inline ulong public_hash_pair_logical(ulong value, uint logical_source, uint role) {
    return public_hash_pair_exchange(value, 2u * logical_source + role);
}

inline ulong public_hash_pair_pow7(ulong value, uint physical_lane) {
    ulong squared = gl_mul(value, value);
    // x^3 and x^4 execute in parallel in the two lanes. Selection changes only
    // the multiplicand, never which lanes participate in the exchange.
    ulong factor = (physical_lane & 1u) ? squared : value;
    ulong partial = gl_mul(squared, factor);
    ulong other = public_hash_pair_exchange(partial, physical_lane ^ 1u);
    return gl_mul(partial, other);
}

inline ulong public_hash_pair_external(ulong value, uint lane, uint role) {
    ulong sum = gl_add(value, public_hash_pair_logical(value, lane ^ 1u, role));
    sum = gl_add(sum, public_hash_pair_logical(sum, lane ^ 2u, role));
    ulong next = public_hash_pair_logical(value, (lane & 4u) | ((lane + 1u) & 3u), role);
    ulong own = gl_add(sum, gl_add(value, gl_add(next, next)));
    ulong partner = public_hash_pair_logical(own, lane ^ 4u, role);
    return gl_add(gl_add(own, own), partner);
}

inline ulong public_hash_pair_internal(ulong value, uint lane, uint role, ulong diagonal) {
    ulong sum = gl_add(value, public_hash_pair_logical(value, lane ^ 1u, role));
    sum = gl_add(sum, public_hash_pair_logical(sum, lane ^ 2u, role));
    sum = gl_add(sum, public_hash_pair_logical(sum, lane ^ 4u, role));
    return gl_add(gl_mul(value, diagonal), sum);
}

#endif
