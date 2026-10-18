template<u32 D>
__device__ void scalar_power_values(const u64 *input, u64 *output, u64 first,
    u64 exponent, u32 count) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    u64 value[D];
    fe_pow<D>(input + first, exponent + i, value);
    for (u32 c = 0; c < D; ++c) output[(u64)D * i + c] = gl_canon(value[c]);
}
extern "C" __global__ void scalar_powers(const u64 *input, u64 *output,
    u64 first, u64 exponent, u32 count, u32 degree) {
    if (degree == 1) scalar_power_values<1>(input, output, first, exponent, count);
    else if (degree == 2) scalar_power_values<2>(input, output, first, exponent, count);
    else scalar_power_values<3>(input, output, first, exponent, count);
}

template<u32 D>
__device__ void scalar_lookup_values(const u64 *sampled, const u64 *ids, u64 *output,
    u64 first, u32 width, u32 count, u32 mapped) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    u64 gamma[D];
    fe_pow<D>(sampled + first + D, width, gamma);
    const u64 id = mapped ? ids[i] : i;
    const u64 offset = (u64)D * i * (mapped ? 2 : 1);
    for (u32 c = 0; c < D; ++c) {
        output[offset + c] = gl_canon(gl_add(sampled[first + c], gl_mul(id + 1, gamma[c])));
        if (mapped) output[offset + D + c] = gl_canon(sampled[first + D + c]);
    }
}
extern "C" __global__ void scalar_lookup(const u64 *sampled, const u64 *ids,
    u64 *output, u64 first, u32 width, u32 count, u32 degree, u32 mapped) {
    if (degree == 1) scalar_lookup_values<1>(sampled, ids, output, first, width, count, mapped);
    else if (degree == 2) scalar_lookup_values<2>(sampled, ids, output, first, width, count, mapped);
    else scalar_lookup_values<3>(sampled, ids, output, first, width, count, mapped);
}

extern "C" __global__ void scalar_next_points(const u64 *point, const u64 *roots,
    u64 *output, u64 first, u32 count, u32 degree) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    for (u32 c = 0; c < degree; ++c)
        output[(u64)degree * i + c] = gl_canon(gl_mul(point[first + c], roots[i]));
}

extern "C" __global__ void scalar_domain_shifts(u64 *output, u64 shift,
    u64 root, u32 first, u32 count) {
    const u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) output[i] = gl_canon(gl_mul(shift, gl_pow(root, (u64)first + i)));
}
