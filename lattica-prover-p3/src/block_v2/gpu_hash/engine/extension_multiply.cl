#ifndef LATTICA_EXTENSION_MULTIPLY
#define LATTICA_EXTENSION_MULTIPLY
// Cubic basis X^3 = X + 1; quadratic basis X^2 = 7.
#ifdef LATTICA_NVIDIA_FIELD_CARRY
// The V100 path accumulates three full-width products before one reduction.
// Put B=2^32. A three-product sum is low + high*B^2 + top*B^4,
// with top <= 2. Since B^2=B-1 and B^4=-B (mod p), reduce
// low - (high>>32) - top*B + (uint)high*(B-1).
// The subtrahend is below 3*B, so one borrow correction suffices;
// the final carry correction cannot overflow. Inputs may be any u64.
// Keep each carry chain within its assembly block.
inline ulong opening_dot3(ulong a0, ulong a1, ulong a2, ulong b0, ulong b1, ulong b2) {
    ulong result;
    asm("{ .reg .u64 low, high, negative, v, correction; .reg .u32 top, flag;\n"
        "add.cc.u64 low, %1, %3;\n"
        "addc.cc.u64 high, %2, %4;\n"
        "addc.u32 top, 0, 0;\n"
        "add.cc.u64 low, low, %5;\n"
        "addc.cc.u64 high, high, %6;\n"
        "addc.u32 top, top, 0;\n"
        "shr.u64 negative, high, 32;\n"
        "cvt.u64.u32 correction, top;\n"
        "shl.b64 correction, correction, 32;\n"
        "add.u64 negative, negative, correction;\n"
        "cvt.u32.u64 flag, high;\n"
        "mul.wide.u32 v, flag, 0xffffffff;\n"
        "sub.cc.u64 low, low, negative;\n"
        "subc.u32 flag, 0, 0;\n"
        "cvt.u64.u32 correction, flag;\n"
        "sub.u64 low, low, correction;\n"
        "add.cc.u64 low, low, v;\n"
        "addc.u32 flag, 0, 0;\n"
        "mul.wide.u32 correction, flag, 0xffffffff;\n"
        "add.u64 %0, low, correction; }"
        : "=l"(result)
        : "l"(a0*b0), "l"(mul_hi(a0,b0)), "l"(a1*b1), "l"(mul_hi(a1,b1)),
          "l"(a2*b2), "l"(mul_hi(a2,b2)));
    return result;
}
#endif
inline void opening_cubic_mul(ulong a[3], ulong b[3], ulong out[3]) {
#ifdef LATTICA_NVIDIA_FIELD_CARRY
    ulong b02=gl_add(b[0],b[2]), b12=gl_add(b[1],b[2]);
    out[0]=opening_dot3(a[0],a[1],a[2],b[0],b[2],b[1]);
    out[1]=opening_dot3(a[0],a[1],a[2],b[1],b02,b12);
    out[2]=opening_dot3(a[0],a[1],a[2],b[2],b[1],b02);
#else
    ulong c3 = gl_add(gl_mul(a[1], b[2]), gl_mul(a[2], b[1]));
    ulong c4 = gl_mul(a[2], b[2]);
    out[0] = gl_add(gl_mul(a[0], b[0]), c3);
    out[1] = gl_add(gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0])), gl_add(c3, c4));
    out[2] = gl_add(gl_add(gl_add(gl_mul(a[0], b[2]), gl_mul(a[1], b[1])), gl_mul(a[2], b[0])), c4);
#endif
}
inline void opening_quadratic_mul(__private const ulong *a, __private const ulong *b, __private ulong *out) {
    out[0] = gl_add(gl_mul(a[0], b[0]), gl_mul(7UL, gl_mul(a[1], b[1])));
    out[1] = gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0]));
}
#endif
