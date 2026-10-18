// NVIDIA SM7+ only. Full 32-lane warps contain four independent eight-lane
// sponges. Padded rows participate in every shuffle; only memory accesses are
// masked. The public-statement sponge's fixed 0xff mask cannot be reused here.
inline ulong commitment_exchange(ulong value, uint lane) {
    uint source = ((uint)get_local_id(0) & 24u) | lane;
    uint low, high;
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, -1;"
        : "=r"(low) : "r"((uint)value), "r"(source));
    asm volatile("shfl.sync.idx.b32 %0, %1, %2, 31, -1;"
        : "=r"(high) : "r"((uint)(value >> 32)), "r"(source));
    return ((ulong)high << 32) | low;
}
inline ulong commitment_external(ulong value, uint lane) {
    ulong sum = gl_add(value, commitment_exchange(value, lane ^ 1u));
    sum = gl_add(sum, commitment_exchange(sum, lane ^ 2u));
    ulong next = commitment_exchange(value, (lane & 4u) | ((lane + 1u) & 3u));
    ulong own = gl_add(sum, gl_add(value, gl_add(next, next)));
    return gl_add(gl_add(own, own), commitment_exchange(own, lane ^ 4u));
}
inline ulong commitment_perm(ulong value, uint lane,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    value = commitment_external(value, lane);
    for (uint r = 0; r < 4; ++r) {
        value = gl_pow7(gl_add(value, rci[r * 8 + lane]));
        value = commitment_external(value, lane);
    }
    for (uint r = 0; r < 22; ++r) {
        if (lane == 0) value = gl_pow7(gl_add(value, rcp[r]));
        ulong sum = gl_add(value, commitment_exchange(value, lane ^ 1u));
        sum = gl_add(sum, commitment_exchange(sum, lane ^ 2u));
        sum = gl_add(sum, commitment_exchange(sum, lane ^ 4u));
        value = gl_add(gl_mul(value, diag[lane]), sum);
    }
    for (uint r = 0; r < 4; ++r) {
        value = gl_pow7(gl_add(value, rcf[r * 8 + lane]));
        value = commitment_external(value, lane);
    }
    return value;
}

__kernel void leaf_hash_shuffle(__global const ulong *input, __global ulong *out,
    uint row0, uint rows, uint width, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0) / 8;
    uint lane = get_local_id(0) & 7u, at = 0;
    ulong value = 0;
    for (uint col = 0; col < width; ++col) {
        if (row < rows && lane == at) value = input[row * (size_t)width + col];
        if (++at == 4) { value = commitment_perm(value, lane, rci, rcp, rcf, diag); at = 0; }
    }
    if (at != 0) value = commitment_perm(value, lane, rci, rcp, rcf, diag);
    if (row < rows && lane < 4) out[((size_t)row0 + row) * 4 + lane] = gl_canon(value);
}

__kernel void compress_layer_shuffle(__global const ulong *input, __global ulong *out,
    uint rows, __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0) / 8;
    uint lane = get_local_id(0) & 7u;
    ulong value = row < rows ? input[row * 8 + lane] : 0;
    value = commitment_perm(value, lane, rci, rcp, rcf, diag);
    if (row < rows && lane < 4) out[row * 4 + lane] = gl_canon(value);
}

__kernel void lde_absorb_shuffle(__global const ulong *input, __global ulong *states,
    uint row0, uint rows, uint width, uint rate_offset,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0) / 8;
    uint lane = get_local_id(0) & 7u, at = rate_offset;
    size_t base = ((size_t)row0 + row) * 8;
    ulong value = row < rows ? states[base + lane] : 0;
    for (uint col = 0; col < width; ++col) {
        if (row < rows && lane == at) value = input[row * (size_t)width + col];
        if (++at == 4) { value = commitment_perm(value, lane, rci, rcp, rcf, diag); at = 0; }
    }
    if (row < rows) states[base + lane] = value;
}

__kernel void lde_leaf_finalize_shuffle(__global const ulong *states, __global ulong *out,
    uint rows, uint rate_offset, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    size_t row = get_global_id(0) / 8;
    uint lane = get_local_id(0) & 7u;
    ulong value = row < rows ? states[row * 8 + lane] : 0;
    if (rate_offset != 0) value = commitment_perm(value, lane, rci, rcp, rcf, diag);
    if (row < rows && lane < 4) out[row * 4 + lane] = gl_canon(value);
}
