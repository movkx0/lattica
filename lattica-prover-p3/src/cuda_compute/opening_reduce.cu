// Combine columns before extending, so reduction needs one extension-field
// LDE vector instead of a full-width LDE. Prefixes are evaluations, not coefficients.
template<u32 D>
__device__ void opening_weights(const u64 *alpha, u64 *weights, u32 width) {
    const u32 col = blockIdx.x * blockDim.x + threadIdx.x;
    if (col >= width) return;
    u64 a[D], power[D];
    for (u32 j = 0; j < D; ++j) a[j] = alpha[j];
    fe_pow<D>(a, col, power);
    for (u32 j = 0; j < D; ++j) weights[col * D + j] = gl_canon(power[j]);
}

template<u32 D>
__device__ void opening_terms(const u64 *alpha, const u64 *weights,
    const u64 *values, u64 *terms, u32 width, u32 points, u64 first_power) {
    const u32 p = blockIdx.x * blockDim.x + threadIdx.x;
    if (p >= points) return;
    u64 sum[D] = {0}, a[D], offset[D];
    for (u32 j = 0; j < D; ++j) a[j] = alpha[j];
    fe_pow<D>(a, first_power + (u64)p * width, offset);
    for (u32 col = 0; col < width; ++col) {
        u64 weight[D], value[D], product[D];
        for (u32 j = 0; j < D; ++j) {
            weight[j] = weights[col * D + j];
            value[j] = values[((u64)p * width + col) * D + j];
        }
        fe_mul<D>(weight, value, product);
        for (u32 j = 0; j < D; ++j) sum[j] = gl_add(sum[j], product[j]);
    }
    for (u32 j = 0; j < D; ++j) {
        terms[p * 2 * D + j] = gl_canon(offset[j]);
        terms[p * 2 * D + D + j] = gl_canon(sum[j]);
    }
}

template<u32 D>
__device__ void opening_compress(const u64 *input, const u64 *weights,
    u64 *output, u32 width, u32 rows, u32 log_rows) {
    const u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 sum[D] = {0};
    for (u32 col = 0; col < width; ++col) {
        const u64 value = input[(u64)row * width + col];
        for (u32 j = 0; j < D; ++j)
            sum[j] = gl_add(sum[j], gl_mul(value, weights[col * D + j]));
    }
    const u32 natural = bit_reverse(row, log_rows);
    for (u32 j = 0; j < D; ++j) output[(u64)natural * D + j] = gl_canon(sum[j]);
}

template<u32 D>
__device__ void opening_reduce(const u64 *expanded, const u64 *inverses,
    const u64 *terms, u64 *output, u32 first, u32 rows, u32 points) {
    const u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    u64 sum[D] = {0};
    for (u32 p = 0; p < points; ++p) {
        u64 offset[D], delta[D], inverse[D], product[D], scaled[D];
        for (u32 j = 0; j < D; ++j) {
            offset[j] = terms[p * 2 * D + j];
            delta[j] = gl_sub(terms[p * 2 * D + D + j], expanded[((u64)first + row) * D + j]);
            inverse[j] = inverses[((u64)row * points + p) * D + j];
        }
        // (f(z) - f(x))/(z - x) equals (f(x) - f(z))/(x - z).
        fe_mul<D>(delta, inverse, product);
        fe_mul<D>(offset, product, scaled);
        for (u32 j = 0; j < D; ++j) sum[j] = gl_add(sum[j], scaled[j]);
    }
    for (u32 j = 0; j < D; ++j) {
        const u64 at = ((u64)first + row) * D + j;
        output[at] = gl_canon(gl_add(output[at], sum[j]));
    }
}

#define OPENING_REDUCE_KERNELS(D) \
extern "C" __global__ void opening_weights_##D(const u64 *a, u64 *w, u32 width) { opening_weights<D>(a,w,width); } \
extern "C" __global__ void opening_terms_##D(const u64 *a, const u64 *w, const u64 *v, u64 *t, u32 width, u32 n, u64 first) { opening_terms<D>(a,w,v,t,width,n,first); } \
extern "C" __global__ void opening_compress_##D(const u64 *i, const u64 *w, u64 *o, u32 width, u32 rows, u32 log_rows) { opening_compress<D>(i,w,o,width,rows,log_rows); } \
extern "C" __global__ void opening_reduce_##D(const u64 *v, const u64 *i, const u64 *t, u64 *o, u32 first, u32 rows, u32 n) { opening_reduce<D>(v,i,t,o,first,rows,n); }

OPENING_REDUCE_KERNELS(2)
OPENING_REDUCE_KERNELS(3)
