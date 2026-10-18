// The Rust launcher validates all spans and rejects partial output aliasing.
template<u32 D>
__device__ void apply_field(const u64 *a, const u64 *b, u64 *out,
    u64 first_a, u64 first_b, u64 first_out, u64 count, u32 operation, u64 exponent) {
    const u64 index = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= count) return;
    u64 x[D], y[D], result[D];
    #pragma unroll
    for (u32 i = 0; i < D; ++i) {
        x[i] = a[first_a + index * D + i];
        y[i] = b[first_b + index * D + i];
    }
    if (operation == 2) fe_inverse_or_zero<D>(x, result);
    else if (operation == 3) fe_pow<D>(x, exponent, result);
    else if (operation == 6) fe_mul<D>(x, y, result);
    else {
        #pragma unroll
        for (u32 i = 0; i < D; ++i) {
            if (operation == 0) result[i] = x[i];
            else if (operation == 1) result[i] = gl_neg(x[i]);
            else if (operation == 4) result[i] = gl_add(x[i], y[i]);
            else result[i] = gl_sub(x[i], y[i]);
        }
    }
    #pragma unroll
    for (u32 i = 0; i < D; ++i) out[first_out + index * D + i] = gl_canon(result[i]);
}
extern "C" __global__ void field_apply(const u64 *a, const u64 *b, u64 *out,
    u64 first_a, u64 first_b, u64 first_out, u64 count, u32 degree, u32 operation, u64 exponent) {
    if (degree == 1) apply_field<1>(a, b, out, first_a, first_b, first_out, count, operation, exponent);
    else if (degree == 2) apply_field<2>(a, b, out, first_a, first_b, first_out, count, operation, exponent);
    else if (degree == 3) apply_field<3>(a, b, out, first_a, first_b, first_out, count, operation, exponent);
}
