#ifndef LATTICA_EXTENSION_MULTIPLY
#define LATTICA_EXTENSION_MULTIPLY
// Cubic basis X^3 = X + 1; quadratic basis X^2 = 7.
inline void opening_cubic_mul(ulong a[3], ulong b[3], ulong out[3]) {
    ulong c3 = gl_add(gl_mul(a[1], b[2]), gl_mul(a[2], b[1]));
    ulong c4 = gl_mul(a[2], b[2]);
    out[0] = gl_add(gl_mul(a[0], b[0]), c3);
    out[1] = gl_add(gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0])), gl_add(c3, c4));
    out[2] = gl_add(gl_add(gl_add(gl_mul(a[0], b[2]), gl_mul(a[1], b[1])), gl_mul(a[2], b[0])), c4);
}
inline void opening_quadratic_mul(__private const ulong *a, __private const ulong *b, __private ulong *out) {
    out[0] = gl_add(gl_mul(a[0], b[0]), gl_mul(7UL, gl_mul(a[1], b[1])));
    out[1] = gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0]));
}
#endif
