//! Cubic barycentric evaluation and opening-combination metadata on OpenCL.
//! Uses the shared cubic multiplication and 128-lane batch inverse kernels.
pub(crate) const KERNEL_SRC: &str = r#"
inline void device_opening_pow(const ulong input[3], ulong exponent, ulong output[3]) {
    ulong base[3], result[3] = {1, 0, 0}, next[3];
    for (uint j = 0; j < 3; ++j) base[j] = input[j];
    while (exponent != 0) {
        if (exponent & 1) {
            opening_cubic_mul(result, base, next);
            for (uint j = 0; j < 3; ++j) result[j] = next[j];
        }
        exponent >>= 1;
        if (exponent != 0) {
            opening_cubic_mul(base, base, next);
            for (uint j = 0; j < 3; ++j) base[j] = next[j];
        }
    }
    for (uint j = 0; j < 3; ++j) output[j] = gl_canon(result[j]);
}
__kernel void device_opening_parameters(__global const ulong *points, __global ulong *parameters, uint count, uint height, ulong shift) {
    uint p = get_global_id(0);
    if (p >= count) return;
    ulong z[3], inverse[3], power[3], scale[3];
    for (uint j = 0; j < 3; ++j) z[j] = points[3 * p + j];
    lookup_cubic_inverse(z, inverse);
    device_opening_pow(z, (ulong)height, power);
    ulong shift_power = gl_pow(shift, (ulong)height);
    power[0] = gl_sub(power[0], shift_power);
    opening_cubic_mul(z, power, scale);
    ulong normalization = gl_inverse(gl_mul((ulong)height, shift_power));
    for (uint j = 0; j < 3; ++j) {
        parameters[6 * p + j] = gl_canon(inverse[j]);
        parameters[6 * p + 3 + j] = gl_canon(gl_mul(scale[j], normalization));
    }
}
__kernel void device_opening_denominators(__global const ulong *points, __global ulong *values, uint count, uint first_row, uint rows, uint log_rows, ulong shift, ulong root) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * count) return;
    uint row = first_row + (uint)(i / count), p = (uint)(i % count);
    ulong x = gl_mul(shift, gl_pow(root, (ulong)brev(row, log_rows)));
    for (uint j = 0; j < 3; ++j) values[3 * i + j] = gl_canon(j == 0 ? gl_sub(points[3 * p], x) : points[3 * p + j]);
}
__kernel void device_opening_dot(__global const ulong *input, __global const ulong *inverse, __global const ulong *parameters, __global ulong *partial, uint width, uint points, uint first_row, uint rows) {
    __local ulong sums[128 * 3];
    size_t group = get_group_id(0), point_column = group % ((size_t)width * points);
    uint lane = get_local_id(0), p = (uint)(point_column / width), col = (uint)(point_column % width);
    size_t row = (group / ((size_t)width * points)) * 128 + lane;
    for (uint j = 0; j < 3; ++j) {
        ulong value = 0;
        if (row < rows) {
            ulong adjusted = gl_sub(inverse[(row * points + p) * 3 + j], parameters[6 * p + j]);
            value = gl_mul(input[((size_t)first_row + row) * width + col], adjusted);
        }
        sums[3 * lane + j] = value;
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = 64; stride > 0; stride >>= 1) {
        if (lane < stride) for (uint j = 0; j < 3; ++j) sums[3 * lane + j] = gl_add(sums[3 * lane + j], sums[3 * (lane + stride) + j]);
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (lane == 0) for (uint j = 0; j < 3; ++j) partial[3 * group + j] = gl_canon(sums[j]);
}
__kernel void device_opening_accumulate(__global const ulong *partial, __global ulong *opened, uint width, uint points, uint blocks) {
    size_t pc = get_global_id(0), count = (size_t)width * points;
    if (pc >= count) return;
    for (uint j = 0; j < 3; ++j) {
        ulong sum = opened[3 * pc + j];
        for (uint block = 0; block < blocks; ++block) sum = gl_add(sum, partial[3 * (block * count + pc) + j]);
        opened[3 * pc + j] = gl_canon(sum);
    }
}
__kernel void device_opening_scale(__global ulong *opened, __global const ulong *parameters, uint width, uint points) {
    size_t pc = get_global_id(0);
    if (pc >= (size_t)width * points) return;
    uint p = (uint)(pc / width);
    ulong sum[3], factor[3], result[3];
    for (uint j = 0; j < 3; ++j) { sum[j] = opened[3 * pc + j]; factor[j] = parameters[6 * p + 3 + j]; }
    opening_cubic_mul(sum, factor, result);
    for (uint j = 0; j < 3; ++j) opened[3 * pc + j] = gl_canon(result[j]);
}
__kernel void device_opening_weights(__global const ulong *alpha, __global ulong *weights, uint width) {
    uint col = get_global_id(0);
    if (col >= width) return;
    ulong a[3], power[3];
    for (uint j = 0; j < 3; ++j) a[j] = alpha[j];
    device_opening_pow(a, (ulong)col, power);
    for (uint j = 0; j < 3; ++j) weights[3 * col + j] = power[j];
}
__kernel void device_opening_terms(__global const ulong *alpha, __global const ulong *weights, __global const ulong *opened, __global ulong *terms, uint width, uint points, ulong first_power) {
    uint p = get_global_id(0);
    if (p >= points) return;
    ulong sum[3] = {0, 0, 0}, a[3], offset[3];
    for (uint j = 0; j < 3; ++j) a[j] = alpha[j];
    device_opening_pow(a, first_power + (ulong)p * width, offset);
    for (uint col = 0; col < width; ++col) {
        ulong weight[3], value[3], product[3];
        for (uint j = 0; j < 3; ++j) { weight[j] = weights[3 * col + j]; value[j] = opened[((size_t)p * width + col) * 3 + j]; }
        opening_cubic_mul(weight, value, product);
        for (uint j = 0; j < 3; ++j) sum[j] = gl_add(sum[j], product[j]);
    }
    for (uint j = 0; j < 3; ++j) { terms[6 * p + j] = offset[j]; terms[6 * p + 3 + j] = gl_canon(sum[j]); }
}
"#;
