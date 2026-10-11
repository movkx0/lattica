//! Pinned quadratic (u^2 = 7) opening kernels. Like the cubic path,
//! denominator inversion uses one inverse per 128-lane product tree.
pub(crate) const KERNEL_SRC: &str = r#"
inline void opening_quadratic_mul(__private const ulong *a, __private const ulong *b, __private ulong *out) {
    out[0] = gl_add(gl_mul(a[0], b[0]), gl_mul(7UL, gl_mul(a[1], b[1])));
    out[1] = gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0]));
}
inline void opening_quadratic_inverse(__private const ulong *a, __private ulong *out) {
    ulong norm = gl_sub(gl_mul(a[0], a[0]), gl_mul(7UL, gl_mul(a[1], a[1])));
    ulong inverse = gl_pow(norm, 0xfffffffeffffffffUL);
    out[0] = gl_mul(a[0], inverse);
    out[1] = gl_neg(gl_mul(a[1], inverse));
}
inline void device_opening_pow_quadratic(const ulong input[2], ulong exponent, ulong output[2]) {
    ulong base[2], result[2] = {1, 0}, next[2];
    for (uint j = 0; j < 2; ++j) base[j] = input[j];
    while (exponent != 0) {
        if (exponent & 1) {
            opening_quadratic_mul(result, base, next);
            for (uint j = 0; j < 2; ++j) result[j] = next[j];
        }
        exponent >>= 1;
        if (exponent != 0) {
            opening_quadratic_mul(base, base, next);
            for (uint j = 0; j < 2; ++j) base[j] = next[j];
        }
    }
    for (uint j = 0; j < 2; ++j) output[j] = gl_canon(result[j]);
}
__kernel void device_opening_parameters_quadratic(__global const ulong *points, __global ulong *parameters, uint count, uint height, ulong shift) {
    uint p = get_global_id(0);
    if (p >= count) return;
    ulong z[2], inverse[2], power[2], scale[2];
    for (uint j = 0; j < 2; ++j) z[j] = points[2 * p + j];
    opening_quadratic_inverse(z, inverse);
    device_opening_pow_quadratic(z, (ulong)height, power);
    ulong shift_power = gl_pow(shift, (ulong)height);
    power[0] = gl_sub(power[0], shift_power);
    opening_quadratic_mul(z, power, scale);
    ulong normalization = gl_pow(gl_mul((ulong)height, shift_power), 0xfffffffeffffffffUL);
    for (uint j = 0; j < 2; ++j) {
        parameters[4 * p + j] = gl_canon(inverse[j]);
        parameters[4 * p + 2 + j] = gl_canon(gl_mul(scale[j], normalization));
    }
}
__kernel void device_opening_denominators_quadratic(__global const ulong *points, __global ulong *values, uint count, uint first_row, uint rows, uint log_rows, ulong shift, ulong root) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * count) return;
    uint row = first_row + (uint)(i / count), p = (uint)(i % count);
    ulong x = gl_mul(shift, gl_pow(root, (ulong)brev(row, log_rows)));
    for (uint j = 0; j < 2; ++j) values[2 * i + j] = gl_canon(j == 0 ? gl_sub(points[2 * p], x) : points[2 * p + j]);
}
__kernel void device_opening_dot_quadratic(__global const ulong *input, __global const ulong *inverse, __global const ulong *parameters, __global ulong *partial, uint width, uint points, uint first_row, uint rows) {
    __local ulong sums[128 * 2];
    size_t group = get_group_id(0), point_column = group % ((size_t)width * points);
    uint lane = get_local_id(0), p = (uint)(point_column / width), col = (uint)(point_column % width);
    size_t row = (group / ((size_t)width * points)) * 128 + lane;
    for (uint j = 0; j < 2; ++j) {
        ulong value = 0;
        if (row < rows) {
            ulong adjusted = gl_sub(inverse[(row * points + p) * 2 + j], parameters[4 * p + j]);
            value = gl_mul(input[((size_t)first_row + row) * width + col], adjusted);
        }
        sums[2 * lane + j] = value;
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = 64; stride > 0; stride >>= 1) {
        if (lane < stride) for (uint j = 0; j < 2; ++j) sums[2 * lane + j] = gl_add(sums[2 * lane + j], sums[2 * (lane + stride) + j]);
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (lane == 0) for (uint j = 0; j < 2; ++j) partial[2 * group + j] = gl_canon(sums[j]);
}
__kernel void device_opening_accumulate_quadratic(__global const ulong *partial, __global ulong *opened, uint width, uint points, uint blocks) {
    size_t pc = get_global_id(0), count = (size_t)width * points;
    if (pc >= count) return;
    for (uint j = 0; j < 2; ++j) {
        ulong sum = opened[2 * pc + j];
        for (uint block = 0; block < blocks; ++block) sum = gl_add(sum, partial[2 * (block * count + pc) + j]);
        opened[2 * pc + j] = gl_canon(sum);
    }
}
__kernel void device_opening_scale_quadratic(__global ulong *opened, __global const ulong *parameters, uint width, uint points) {
    size_t pc = get_global_id(0);
    if (pc >= (size_t)width * points) return;
    uint p = (uint)(pc / width);
    ulong sum[2], factor[2], result[2];
    for (uint j = 0; j < 2; ++j) { sum[j] = opened[2 * pc + j]; factor[j] = parameters[4 * p + 2 + j]; }
    opening_quadratic_mul(sum, factor, result);
    for (uint j = 0; j < 2; ++j) opened[2 * pc + j] = gl_canon(result[j]);
}
__kernel void device_opening_weights_quadratic(__global const ulong *alpha, __global ulong *weights, uint width) {
    uint col = get_global_id(0);
    if (col >= width) return;
    ulong a[2], power[2];
    for (uint j = 0; j < 2; ++j) a[j] = alpha[j];
    device_opening_pow_quadratic(a, (ulong)col, power);
    for (uint j = 0; j < 2; ++j) weights[2 * col + j] = power[j];
}
__kernel void device_opening_terms_quadratic(__global const ulong *alpha, __global const ulong *weights, __global const ulong *opened, __global ulong *terms, uint width, uint points, ulong first_power) {
    uint p = get_global_id(0);
    if (p >= points) return;
    ulong sum[2] = {0, 0}, a[2], offset[2];
    for (uint j = 0; j < 2; ++j) a[j] = alpha[j];
    device_opening_pow_quadratic(a, first_power + (ulong)p * width, offset);
    for (uint col = 0; col < width; ++col) {
        ulong weight[2], value[2], product[2];
        for (uint j = 0; j < 2; ++j) { weight[j] = weights[2 * col + j]; value[j] = opened[((size_t)p * width + col) * 2 + j]; }
        opening_quadratic_mul(weight, value, product);
        for (uint j = 0; j < 2; ++j) sum[j] = gl_add(sum[j], product[j]);
    }
    for (uint j = 0; j < 2; ++j) { terms[4 * p + j] = offset[j]; terms[4 * p + 2 + j] = gl_canon(sum[j]); }
}
__kernel void opening_compress_low_quadratic(__global const ulong *input,
    __global const ulong *weights, __global ulong *output,
    uint row0, uint rows, uint width, uint log_low_height) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong sum[2] = {0, 0};
    for (uint col = 0; col < width; ++col)
        for (uint k = 0; k < 2; ++k)
            sum[k] = gl_add(sum[k], gl_mul(input[row * (size_t)width + col],
                                         weights[2 * (size_t)col + k]));
    size_t at = (size_t)brev(row0 + (uint)row, log_low_height) * 2;
    for (uint k = 0; k < 2; ++k) output[at + k] = gl_canon(sum[k]);
}
__kernel void opening_reduce_compact_quadratic(__global const ulong *compressed,
    __global const ulong *denominators, __global const ulong *terms,
    __global ulong *output, uint row0, uint rows, uint points) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    size_t at = ((size_t)row0 + row) * 2;
    ulong sum[2] = {0, 0};
    for (uint point = 0; point < points; ++point) {
        ulong offset[2], delta[2], inverse[2], product[2], scaled[2];
        for (uint k = 0; k < 2; ++k) {
            offset[k] = terms[4 * point + k];
            delta[k] = gl_sub(terms[4 * point + 2 + k], compressed[at + k]);
            inverse[k] = denominators[(row * (size_t)points + point) * 2 + k];
        }
        opening_quadratic_mul(delta, inverse, product);
        opening_quadratic_mul(offset, product, scaled);
        for (uint k = 0; k < 2; ++k) sum[k] = gl_add(sum[k], scaled[k]);
    }
    for (uint k = 0; k < 2; ++k)
        output[at + k] = gl_canon(gl_add(output[at + k], sum[k]));
}
"#;
