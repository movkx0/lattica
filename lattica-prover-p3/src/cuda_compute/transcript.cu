// Exact p3-challenger 0.6.1 duplex semantics. State stays resident; only public
// observations, samples and grinding witnesses cross the host boundary.
__device__ __forceinline__ void transcript_duplex(u64 *t, const u64 *constants) {
    const u32 n = (u32)t[16];
    if (n != 0) {
        for (u32 i = 0; i < 4; ++i) t[i] = i < n ? t[8 + i] : 0;
        t[4] = gl_add(t[4], n);
    }
    poseidon_permute(t, constants);
    for (u32 i = 0; i < 4; ++i) t[12 + i] = t[i];
    t[16] = 0;
    t[17] = 4;
}

extern "C" __global__ void transcript_observe(
    u64 *state, const u64 *input, u64 first, u32 count, const u64 *constants) {
    u64 t[18];
    for (u32 i = 0; i < 18; ++i) t[i] = state[i];
    for (u32 i = 0; i < count; ++i) {
        t[17] = 0;
        t[8 + (u32)t[16]] = gl_canon(input[first + i]);
        ++t[16];
        if (t[16] == 4) transcript_duplex(t, constants);
    }
    for (u32 i = 0; i < 18; ++i) state[i] = t[i];
}

extern "C" __global__ void transcript_sample(
    u64 *state, u64 *output, u32 count, u64 mask, const u64 *constants) {
    u64 t[18];
    for (u32 i = 0; i < 18; ++i) t[i] = state[i];
    for (u32 i = 0; i < count; ++i) {
        if (t[16] != 0 || t[17] == 0) transcript_duplex(t, constants);
        --t[17];
        output[i] = gl_canon(t[12 + (u32)t[17]]) & mask;
    }
    for (u32 i = 0; i < 18; ++i) state[i] = t[i];
}

__device__ __forceinline__ void transcript_candidate(const u64 *state, u64 *s, u64 witness) {
    const u32 n = (u32)state[16];
    for (u32 i = 0; i < 4; ++i) s[i] = i < n ? state[8 + i] : 0;
    s[n] = witness;
    s[4] = gl_add(state[4], n + 1);
    for (u32 i = 5; i < 8; ++i) s[i] = state[i];
}

extern "C" __global__ void transcript_grind_candidates(
    const u64 *state, u64 *candidates, u64 base, u32 count, u64 mask, const u64 *constants) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    const u64 witness = base + i;
    u64 s[8];
    transcript_candidate(state, s, witness);
    poseidon_permute(s, constants);
    candidates[i] = (gl_canon(s[3]) & mask) == 0 ? witness : ~0ULL;
}

// Deterministic minimum witness without optional 64-bit atomic operations.
extern "C" __global__ void transcript_grind_reduce(
    const u64 *candidates, u64 *minima, u32 count, u32 tile_words) {
    const u32 tile = blockIdx.x * blockDim.x + threadIdx.x;
    const u32 start = tile * tile_words;
    if (start >= count) return;
    u64 best = ~0ULL;
    for (u32 i = start; i < count && i < start + tile_words; ++i)
        if (candidates[i] < best) best = candidates[i];
    minima[tile] = best;
}

extern "C" __global__ void transcript_grind_commit(
    u64 *state, const u64 *minima, u64 *status, u32 tiles, u64 mask, const u64 *constants) {
    u64 best = ~0ULL;
    for (u32 i = 0; i < tiles; ++i) if (minima[i] < best) best = minima[i];
    status[0] = best;
    status[1] = 0;
    if (best == ~0ULL) return;
    u64 s[8];
    transcript_candidate(state, s, best);
    poseidon_permute(s, constants);
    if ((gl_canon(s[3]) & mask) != 0) { status[1] = 2; return; }
    for (u32 i = 0; i < 8; ++i) state[i] = s[i];
    for (u32 i = 0; i < 4; ++i) state[12 + i] = s[i];
    state[16] = 0;
    state[17] = 3;
    status[1] = 1;
}
