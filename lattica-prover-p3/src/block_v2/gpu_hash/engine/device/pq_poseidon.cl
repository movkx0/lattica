#ifndef LATTICA_PQ_POSEIDON_TRACE_CL
#define LATTICA_PQ_POSEIDON_TRACE_CL
// Exact p3_poseidon2_air::Poseidon2Cols<_,8,7,0,4,22> layout (94 words).
// Constants and Goldilocks helpers are those of the initialized proving engine.
// No subgroup operations, host state transitions, or private trace readback.
inline void pq_poseidon_permute(ulong s[8],
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    extl(s);
    for (uint r = 0; r < 4; ++r) {
        for (uint j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rci[8*r+j]));
        extl(s);
    }
    for (uint r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], rcp[r]));
        intl(s, diag);
    }
    for (uint r = 0; r < 4; ++r) {
        for (uint j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rcf[8*r+j]));
        extl(s);
    }
    for (uint j = 0; j < 8; ++j) s[j] = gl_canon(s[j]);
}

inline void pq_poseidon_trace_row(__global ulong *trace,
    uint width, uint pose_offset, ulong row,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    __global ulong *columns = trace + row * (ulong)width + pose_offset;
    ulong s[8];
    for (uint j = 0; j < 8; ++j) {
        s[j] = gl_canon(columns[j]);
        columns[j] = s[j];
    }
    extl(s);
    // FullRound.sbox is empty with SBOX_REGISTERS=0; post follows directly.
    for (uint r = 0; r < 4; ++r) {
        for (uint j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rci[8*r+j]));
        extl(s);
        for (uint j = 0; j < 8; ++j) columns[8 + 8*r + j] = gl_canon(s[j]);
    }
    // PartialRound stores post_sbox, before the internal linear layer.
    for (uint r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], rcp[r]));
        columns[40 + r] = gl_canon(s[0]);
        intl(s, diag);
    }
    for (uint r = 0; r < 4; ++r) {
        for (uint j = 0; j < 8; ++j) s[j] = gl_pow7(gl_add(s[j], rcf[8*r+j]));
        extl(s);
        for (uint j = 0; j < 8; ++j) columns[62 + 8*r + j] = gl_canon(s[j]);
    }
}

__kernel void pq_poseidon_trace_columns(__global ulong *trace,
    uint width, uint pose_offset, uint rows,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    ulong row = get_global_id(0);
    if (row < rows) pq_poseidon_trace_row(trace, width, pose_offset, row, rci, rcp, rcf, diag);
}

#endif
