//! Pinned p3-challenger 0.6.1 duplex and ordinary grinding semantics.
//! State: sponge[8], pending[4], output[4], pending_len, output_len.
pub const KERNEL_SRC: &str = r#"
inline void transcript_duplex(ulong* t,
    __global const ulong* rci, __global const ulong* rcp,
    __global const ulong* rcf, __global const ulong* diag) {
    uint n = (uint)t[16];
    if (n != 0) {
        for (uint i = 0; i < 4; i++) t[i] = i < n ? t[8 + i] : 0UL;
        t[4] = gl_add(t[4], (ulong)n);
    }
    perm8(t, rci, rcp, rcf, diag);
    for (uint i = 0; i < 4; i++) t[12 + i] = t[i];
    t[16] = 0UL;
    t[17] = 4UL;
}

__kernel void device_transcript_copy(__global const ulong* src, __global ulong* dst) {
    uint i = (uint)get_global_id(0);
    if (i < 18) dst[i] = src[i];
}

__kernel void device_transcript_observe(__global ulong* state,
    __global const ulong* input, const uint count,
    __global const ulong* rci, __global const ulong* rcp,
    __global const ulong* rcf, __global const ulong* diag) {
    ulong t[18];
    for (uint i = 0; i < 18; i++) t[i] = state[i];
    for (uint i = 0; i < count; i++) {
        t[17] = 0UL;
        t[8 + (uint)t[16]] = input[i];
        t[16]++;
        if (t[16] == 4UL) transcript_duplex(t, rci, rcp, rcf, diag);
    }
    for (uint i = 0; i < 18; i++) state[i] = t[i];
}

__kernel void device_transcript_sample(__global ulong* state,
    __global ulong* output, const uint count, const ulong mask,
    __global const ulong* rci, __global const ulong* rcp,
    __global const ulong* rcf, __global const ulong* diag) {
    ulong t[18];
    for (uint i = 0; i < 18; i++) t[i] = state[i];
    for (uint i = 0; i < count; i++) {
        if (t[16] != 0UL || t[17] == 0UL) transcript_duplex(t, rci, rcp, rcf, diag);
        t[17]--;
        output[i] = gl_canon(t[12 + (uint)t[17]]) & mask;
    }
    for (uint i = 0; i < 18; i++) state[i] = t[i];
}

inline void transcript_grind_state(__global const ulong* state, ulong* s,
    const ulong witness) {
    uint n = (uint)state[16];
    for (uint i = 0; i < 4; i++) s[i] = i < n ? state[8 + i] : 0UL;
    s[n] = witness;
    s[4] = gl_add(state[4], (ulong)(n + 1));
    for (uint i = 5; i < 8; i++) s[i] = state[i];
}

// Every candidate is independent. Explicit reduction avoids optional 64-bit
// atomics and always selects the minimum witness, regardless of launch order.
__kernel void device_transcript_grind_candidates(__global const ulong* state,
    __global ulong* candidates, const ulong base, const uint count, const ulong mask,
    __global const ulong* rci, __global const ulong* rcp,
    __global const ulong* rcf, __global const ulong* diag) {
    uint i = (uint)get_global_id(0);
    if (i >= count) return;
    ulong witness = base + (ulong)i;
    ulong s[8];
    transcript_grind_state(state, s, witness);
    perm8(s, rci, rcp, rcf, diag);
    candidates[i] = (gl_canon(s[3]) & mask) == 0UL ? witness : ~(ulong)0;
}

__kernel void device_transcript_grind_reduce(__global const ulong* candidates,
    __global ulong* minima, const uint count) {
    uint tile = (uint)get_global_id(0);
    uint start = tile * 256;
    ulong best = ~(ulong)0;
    for (uint i = start; i < min(start + 256, count); i++) best = min(best, candidates[i]);
    minima[tile] = best;
}

__kernel void device_transcript_grind_commit(__global ulong* state,
    __global const ulong* minima, __global ulong* status, const uint tiles,
    const ulong mask,
    __global const ulong* rci, __global const ulong* rcp,
    __global const ulong* rcf, __global const ulong* diag) {
    ulong best = ~(ulong)0;
    for (uint i = 0; i < tiles; i++) best = min(best, minima[i]);
    status[0] = best;
    status[1] = 0UL;
    if (best == ~(ulong)0) return;
    ulong s[8];
    transcript_grind_state(state, s, best);
    perm8(s, rci, rcp, rcf, diag);
    // Check once more on GPU before advancing the real transcript.
    if ((gl_canon(s[3]) & mask) != 0UL) { status[1] = 2UL; return; }
    for (uint i = 0; i < 8; i++) state[i] = s[i];
    for (uint i = 0; i < 4; i++) state[12 + i] = s[i];
    state[16] = 0UL;
    state[17] = 3UL;
    status[1] = 1UL;
}
"#;
