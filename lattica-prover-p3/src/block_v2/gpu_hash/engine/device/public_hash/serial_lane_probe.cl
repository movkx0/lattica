// Disconnected single-lane experiment. Named state words avoid taking the
// address of a private state array; physical register residency is not claimed.
// The existing arithmetic, constants, round counts and sponge framing remain.
// Keep the 4/22/4 round loops rolled. Forced full unrolling triggered deep
// NVIDIA NVVM compiler recursion and overflowed the unchanged test-thread stack.
#if defined(LATTICA_PUBLIC_HASH_SERIAL_LANE_PROBE)

// M4 row i = sum(x[0..4]) + x[i] + 2*x[(i+1) mod 4]. The outer
// width-eight layer doubles one's own M4 result and adds the other group's.
#define PH_SERIAL_EXTERNAL() do { \
    const ulong lo = gl_add(gl_add(s0, s1), gl_add(s2, s3)); \
    const ulong hi = gl_add(gl_add(s4, s5), gl_add(s6, s7)); \
    const ulong m0 = gl_add(lo, gl_add(s0, gl_add(s1, s1))); \
    const ulong m1 = gl_add(lo, gl_add(s1, gl_add(s2, s2))); \
    const ulong m2 = gl_add(lo, gl_add(s2, gl_add(s3, s3))); \
    const ulong m3 = gl_add(lo, gl_add(s3, gl_add(s0, s0))); \
    const ulong m4 = gl_add(hi, gl_add(s4, gl_add(s5, s5))); \
    const ulong m5 = gl_add(hi, gl_add(s5, gl_add(s6, s6))); \
    const ulong m6 = gl_add(hi, gl_add(s6, gl_add(s7, s7))); \
    const ulong m7 = gl_add(hi, gl_add(s7, gl_add(s4, s4))); \
    s0 = gl_add(gl_add(m0, m0), m4); \
    s1 = gl_add(gl_add(m1, m1), m5); \
    s2 = gl_add(gl_add(m2, m2), m6); \
    s3 = gl_add(gl_add(m3, m3), m7); \
    s4 = gl_add(gl_add(m4, m4), m0); \
    s5 = gl_add(gl_add(m5, m5), m1); \
    s6 = gl_add(gl_add(m6, m6), m2); \
    s7 = gl_add(gl_add(m7, m7), m3); \
} while (0)

#define PH_SERIAL_FULL(constants, base) do { \
    s0 = gl_pow7(gl_add(s0, constants[(base) + 0u])); \
    s1 = gl_pow7(gl_add(s1, constants[(base) + 1u])); \
    s2 = gl_pow7(gl_add(s2, constants[(base) + 2u])); \
    s3 = gl_pow7(gl_add(s3, constants[(base) + 3u])); \
    s4 = gl_pow7(gl_add(s4, constants[(base) + 4u])); \
    s5 = gl_pow7(gl_add(s5, constants[(base) + 5u])); \
    s6 = gl_pow7(gl_add(s6, constants[(base) + 6u])); \
    s7 = gl_pow7(gl_add(s7, constants[(base) + 7u])); \
    PH_SERIAL_EXTERNAL(); \
} while (0)

__attribute__((reqd_work_group_size(1, 1, 1)))
__kernel void device_public_hash_serial_lane_probe(__global ulong *state,
    __global const ulong *input, const ulong domain, const ulong length,
    const uint first, const uint count, __global const ulong *rci,
    __global const ulong *rcp, __global const ulong *rcf,
    __global const ulong *diag) {
    // Exactly one global and local work item; no lane exits or collectives.
    ulong s0 = first ? domain : state[0];
    ulong s1 = first ? length : state[1];
    ulong s2 = first ? 0UL : state[2];
    ulong s3 = first ? 0UL : state[3];
    const ulong d0 = diag[0], d1 = diag[1], d2 = diag[2], d3 = diag[3];
    const ulong d4 = diag[4], d5 = diag[5], d6 = diag[6], d7 = diag[7];
    for (uint offset = 0; offset < count; offset += 4u) {
        ulong s4 = input[offset];
        ulong s5 = offset + 1u < count ? input[offset + 1u] : 0UL;
        ulong s6 = offset + 2u < count ? input[offset + 2u] : 0UL;
        ulong s7 = offset + 3u < count ? input[offset + 3u] : 0UL;
        PH_SERIAL_EXTERNAL();
#pragma unroll 1
        for (uint round = 0; round < 4u; ++round) {
            PH_SERIAL_FULL(rci, round * 8u);
        }
#pragma unroll 1
        for (uint round = 0; round < 22u; ++round) {
            s0 = gl_pow7(gl_add(s0, rcp[round]));
            const ulong sum = gl_add(
                gl_add(gl_add(s0, s1), gl_add(s2, s3)),
                gl_add(gl_add(s4, s5), gl_add(s6, s7)));
            s0 = gl_add(gl_mul(s0, d0), sum);
            s1 = gl_add(gl_mul(s1, d1), sum);
            s2 = gl_add(gl_mul(s2, d2), sum);
            s3 = gl_add(gl_mul(s3, d3), sum);
            s4 = gl_add(gl_mul(s4, d4), sum);
            s5 = gl_add(gl_mul(s5, d5), sum);
            s6 = gl_add(gl_mul(s6, d6), sum);
            s7 = gl_add(gl_mul(s7, d7), sum);
        }
#pragma unroll 1
        for (uint round = 0; round < 4u; ++round) {
            PH_SERIAL_FULL(rcf, round * 8u);
        }
    }
    state[0] = gl_canon(s0);
    state[1] = gl_canon(s1);
    state[2] = gl_canon(s2);
    state[3] = gl_canon(s3);
}

#undef PH_SERIAL_FULL
#undef PH_SERIAL_EXTERNAL
#endif
