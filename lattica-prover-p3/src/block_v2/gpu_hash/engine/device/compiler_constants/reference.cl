// Test-only arithmetic baseline, retained for differential timing.
__kernel void device_compiler_constants_reference(__global const ulong *input,
    __global ulong *output, uint operation, uint count, uint size, ulong exponent) {
    uint k = get_global_id(0);
    if (k >= count) return;
    if (operation == 0) {
        output[k] = gl_canon(compiler_inv(input[0]));
    } else if (operation == 1) {
        ulong denominator = 1UL;
        for (uint j = 0; j < count; ++j) {
            if (j != k)
                denominator = gl_mul(denominator, gl_sub(input[0] + (ulong)k, input[0] + (ulong)j));
        }
        output[k] = gl_canon(compiler_inv(denominator));
    } else if (operation == 3) {
        if (k < size) {
            output[k] = gl_canon(compiler_inv(gl_mul(7UL, gl_pow(input[0], (ulong)k))));
        } else {
            uint i = (k - size) / size, j = (k - size) % size;
            if (i == j) { output[k] = 0UL; return; }
            ulong a = gl_mul(7UL, gl_pow(input[0], (ulong)i));
            ulong b = gl_mul(7UL, gl_pow(input[0], (ulong)j));
            ulong den = gl_sub(gl_pow(gl_mul(a, compiler_inv(b)), exponent), 1UL);
            output[k] = gl_canon(compiler_inv(den));
        }
    }
}
