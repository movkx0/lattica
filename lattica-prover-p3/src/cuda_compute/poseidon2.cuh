// The existing width-8 Poseidon2 permutation. Constants come from the same p3
// implementation as the independent CPU verifier. One thread owns each state.
#ifndef LATTICA_CUDA_POSEIDON2
#define LATTICA_CUDA_POSEIDON2
__device__ __forceinline__ u64 gl_pow7(u64 x) {
    const u64 x2 = gl_mul(x, x), x3 = gl_mul(x2, x);
    return gl_mul(gl_mul(x2, x2), x3);
}
__device__ __forceinline__ void poseidon_mat4(u64 *x) {
    const u64 t01 = gl_add(x[0], x[1]), t23 = gl_add(x[2], x[3]);
    const u64 t0123 = gl_add(t01, t23);
    const u64 t01123 = gl_add(t0123, x[1]), t01233 = gl_add(t0123, x[3]);
    x[3] = gl_add(t01233, gl_add(x[0], x[0]));
    x[1] = gl_add(t01123, gl_add(x[2], x[2]));
    x[0] = gl_add(t01123, t01);
    x[2] = gl_add(t01233, t23);
}
__device__ __forceinline__ void poseidon_external(u64 *s) {
    poseidon_mat4(s);
    poseidon_mat4(s + 4);
    #pragma unroll
    for (u32 i = 0; i < 4; ++i) {
        const u64 z = gl_add(s[i], s[i + 4]);
        s[i] = gl_add(s[i], z);
        s[i + 4] = gl_add(s[i + 4], z);
    }
}
// Constants: 32 initial round constants, 22 internal, 32 final, 8 diagonal.
__device__ __forceinline__ void poseidon_permute(u64 *s, const u64 *constants) {
    poseidon_external(s);
    for (u32 r = 0; r < 4; ++r) {
        #pragma unroll
        for (u32 i = 0; i < 8; ++i)
            s[i] = gl_pow7(gl_add(s[i], constants[r * 8 + i]));
        poseidon_external(s);
    }
    for (u32 r = 0; r < 22; ++r) {
        s[0] = gl_pow7(gl_add(s[0], constants[32 + r]));
        u64 sum = 0;
        #pragma unroll
        for (u32 i = 0; i < 8; ++i) sum = gl_add(sum, s[i]);
        #pragma unroll
        for (u32 i = 0; i < 8; ++i)
            s[i] = gl_add(gl_mul(s[i], constants[86 + i]), sum);
    }
    for (u32 r = 0; r < 4; ++r) {
        #pragma unroll
        for (u32 i = 0; i < 8; ++i)
            s[i] = gl_pow7(gl_add(s[i], constants[54 + r * 8 + i]));
        poseidon_external(s);
    }
}
#endif
