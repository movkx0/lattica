// Barycentric evaluation of bit-reversed coset prefixes. All points,
// inverses, partial sums and claimed values remain device-resident.
template<u32 D>
__device__ void opening_parameters(const u64 *points, u64 *parameters,
    u64 *status, u32 count, u32 height, u64 shift) {
    const u32 p = blockIdx.x * blockDim.x + threadIdx.x;
    if (p >= count) return;
    u64 z[D], inverse[D], power[D], scale[D];
    bool zero = true, canonical = true;
    for (u32 j = 0; j < D; ++j) {
        z[j] = points[p * D + j];
        zero = zero && z[j] == 0;
        canonical = canonical && z[j] < GP;
    }
    if (zero || !canonical) atomicOr(status, 1ULL);
    fe_inverse_or_zero<D>(z, inverse);
    fe_pow<D>(z, height, power);
    const u64 shift_power = gl_pow(shift, height);
    power[0] = gl_sub(power[0], shift_power);
    bool on_coset = true;
    for (u32 j = 0; j < D; ++j) on_coset = on_coset && gl_canon(power[j]) == 0;
    if (on_coset) atomicOr(status, 2ULL);
    fe_mul<D>(z, power, scale);
    const u64 normalization = gl_inverse_or_zero(gl_mul(height, shift_power));
    for (u32 j = 0; j < D; ++j) {
        parameters[2 * D * p + j] = gl_canon(inverse[j]);
        parameters[2 * D * p + D + j] = gl_canon(gl_mul(scale[j], normalization));
    }
}

template<u32 D>
__device__ void opening_inverses(const u64 *points, u64 *inverse, u64 *status,
    u32 count, u32 first, u32 rows, u32 log_rows, u64 shift, u64 root) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)rows * count) return;
    const u32 row = first + (u32)(i / count), p = i % count;
    const u64 x = gl_mul(shift, gl_pow(root, bit_reverse(row, log_rows)));
    u64 denominator[D], result[D];
    for (u32 j = 0; j < D; ++j)
        denominator[j] = j == 0 ? gl_sub(points[p * D], x) : points[p * D + j];
    bool zero = true;
    for (u32 j = 0; j < D; ++j) zero = zero && gl_canon(denominator[j]) == 0;
    if (zero) atomicOr(status, 2ULL);
    fe_inverse_or_zero<D>(denominator, result);
    for (u32 j = 0; j < D; ++j) inverse[i * D + j] = gl_canon(result[j]);
}

template<u32 D>
__device__ void opening_dot(const u64 *input, const u64 *inverse,
    const u64 *parameters, u64 *partial, u32 width, u32 points, u32 first, u32 rows) {
    __shared__ u64 sums[128 * D];
    const u64 group = blockIdx.x, pc = group % ((u64)width * points);
    const u32 lane = threadIdx.x, p = pc / width, col = pc % width;
    const u64 row = group / ((u64)width * points) * 128 + lane;
    for (u32 j = 0; j < D; ++j) {
        u64 value = 0;
        if (row < rows) {
            const u64 weight = gl_sub(inverse[(row * points + p) * D + j],
                parameters[2 * D * p + j]);
            value = gl_mul(input[((u64)first + row) * width + col], weight);
        }
        sums[lane * D + j] = value;
    }
    __syncthreads();
    for (u32 stride = 64; stride; stride >>= 1) {
        if (lane < stride) for (u32 j = 0; j < D; ++j)
            sums[lane * D + j] = gl_add(sums[lane * D + j], sums[(lane + stride) * D + j]);
        __syncthreads();
    }
    if (lane == 0) for (u32 j = 0; j < D; ++j) partial[group * D + j] = gl_canon(sums[j]);
}

template<u32 D>
__device__ void opening_accumulate(const u64 *partial, u64 *values,
    u32 width, u32 points, u32 blocks) {
    const u64 pc = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    const u64 count = (u64)width * points;
    if (pc >= count) return;
    for (u32 j = 0; j < D; ++j) {
        u64 sum = values[pc * D + j];
        for (u32 b = 0; b < blocks; ++b) sum = gl_add(sum, partial[(b * count + pc) * D + j]);
        values[pc * D + j] = gl_canon(sum);
    }
}

template<u32 D>
__device__ void opening_scale(u64 *values, const u64 *parameters, u32 width, u32 points) {
    const u64 pc = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (pc >= (u64)width * points) return;
    const u32 p = pc / width;
    u64 sum[D], factor[D], result[D];
    for (u32 j = 0; j < D; ++j) {
        sum[j] = values[pc * D + j];
        factor[j] = parameters[2 * D * p + D + j];
    }
    fe_mul<D>(sum, factor, result);
    for (u32 j = 0; j < D; ++j) values[pc * D + j] = gl_canon(result[j]);
}

#define OPENING_KERNELS(D) \
extern "C" __global__ void opening_parameters_##D(const u64 *p, u64 *v, u64 *s, u32 n, u32 h, u64 shift) { opening_parameters<D>(p,v,s,n,h,shift); } \
extern "C" __global__ void opening_inverses_##D(const u64 *p, u64 *v, u64 *s, u32 n, u32 first, u32 rows, u32 log_rows, u64 shift, u64 root) { opening_inverses<D>(p,v,s,n,first,rows,log_rows,shift,root); } \
extern "C" __global__ void opening_dot_##D(const u64 *x, const u64 *i, const u64 *p, u64 *out, u32 w, u32 n, u32 first, u32 rows) { opening_dot<D>(x,i,p,out,w,n,first,rows); } \
extern "C" __global__ void opening_accumulate_##D(const u64 *p, u64 *v, u32 w, u32 n, u32 blocks) { opening_accumulate<D>(p,v,w,n,blocks); } \
extern "C" __global__ void opening_scale_##D(u64 *v, const u64 *p, u32 w, u32 n) { opening_scale<D>(v,p,w,n); }

OPENING_KERNELS(2)
OPENING_KERNELS(3)
