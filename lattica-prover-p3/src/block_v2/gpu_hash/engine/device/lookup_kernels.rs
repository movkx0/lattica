//! OpenCL quadratic/cubic LogUp generation. Workgroups are bounded to 128 lanes.
pub(crate) const KERNEL_SRC: &str = r#"
inline void lookup_cubic_inverse(const ulong a[3], ulong out[3]) {
    // Adjugate of multiplication by a in F[X]/(X^3-X-1).
    ulong t = gl_add(a[0], a[2]);
    ulong b0 = gl_sub(gl_mul(t, t), gl_mul(a[1], gl_add(a[1], a[2])));
    ulong b1 = gl_sub(gl_mul(a[2], a[2]), gl_mul(a[0], a[1]));
    ulong b2 = gl_sub(gl_mul(a[1], a[1]), gl_mul(a[2], t));
    ulong norm = gl_add(gl_add(gl_mul(a[0], b0), gl_mul(a[2], b1)), gl_mul(a[1], b2));
    ulong inv = gl_pow(norm, 0xfffffffeffffffffUL);
    out[0] = gl_mul(b0, inv); out[1] = gl_mul(b1, inv); out[2] = gl_mul(b2, inv);
}
// D=2 uses Goldilocks[X]/(X^2-7); D=3 retains X^3-X-1.
inline void lookup_mul(uint degree, const ulong a[3], const ulong b[3], ulong out[3]) {
    if (degree == 2) {
        out[0] = gl_add(gl_mul(a[0], b[0]), gl_mul(7UL, gl_mul(a[1], b[1])));
        out[1] = gl_add(gl_mul(a[0], b[1]), gl_mul(a[1], b[0]));
    } else {
        opening_cubic_mul(a, b, out);
    }
}
inline void lookup_inverse(uint degree, const ulong a[3], ulong out[3]) {
    if (degree == 2) {
        ulong norm = gl_sub(gl_mul(a[0], a[0]), gl_mul(7UL, gl_mul(a[1], a[1])));
        ulong inverse = gl_pow(norm, 0xfffffffeffffffffUL);
        out[0] = gl_mul(a[0], inverse);
        out[1] = gl_neg(gl_mul(a[1], inverse));
    } else {
        lookup_cubic_inverse(a, out);
    }
}
__kernel void device_lookup_expressions(__global const ulong *code, uint instructions,
    __global const ulong *input, uint input_width, __global const ulong *public_values,
    __global ulong *scratch, __global ulong *output, uint output_width,
    uint rows, uint first_row, uint height) {
    uint row = get_global_id(0);
    if (row >= rows) return;
    for (uint k = 0; k < instructions; ++k) {
        size_t at = (size_t)k * 5;
        uint op = code[at]; size_t dst = code[at + 1]; ulong aa = code[at + 2], bb = code[at + 3];
        ulong a = 0, b = 0, r = 0;
        if (op >= 8) a = scratch[aa * rows + row];
        if (op >= 8 && op <= 10) b = scratch[bb * rows + row];
        switch (op) {
        case 0: r = (ulong)aa; break;
        case 1: r = input[(size_t)row * input_width + aa]; break;
        case 3: r = public_values[aa]; break;
        case 5: r = first_row + row == 0; break;
        case 6: r = first_row + row + 1 == height; break;
        case 7: r = first_row + row + 1 < height; break;
        case 8: r = gl_add(a, b); break;
        case 9: r = gl_sub(a, b); break;
        case 10: r = gl_mul(a, b); break;
        case 11: r = gl_neg(a); break;
        case 18: output[(size_t)row * output_width + bb] = gl_canon(a); break;
        }
        if (op != 18) scratch[dst * rows + row] = r;
    }
}
__kernel void device_lookup_denominators(__global const ulong *expressions,
    uint expression_width, __global const ulong *tuples, uint tuple_count,
    __global const ulong *challenges, __global ulong *denominators, uint rows, uint degree) {
    size_t i = get_global_id(0);
    if (i >= (size_t)rows * tuple_count) return;
    size_t row = i / tuple_count, tuple = i % tuple_count;
    uint lookup = tuples[3 * tuple], first = tuples[3 * tuple + 1], width = tuples[3 * tuple + 2];
    size_t base = row * expression_width + first;
    ulong result[3] = {1, 0, 0};
    if (expressions[base] != 0) {
        ulong combined[3] = {0, 0, 0}, beta[3], next[3];
        for (uint j = 0; j < degree; ++j) beta[j] = challenges[(2 * degree) * lookup + degree + j];
        for (uint k = 0; k < width; ++k) {
            lookup_mul(degree, combined, beta, next);
            next[0] = gl_add(next[0], expressions[base + 1 + k]);
            for (uint j = 0; j < degree; ++j) combined[j] = next[j];
        }
        for (uint j = 0; j < degree; ++j) result[j] = gl_sub(challenges[(2 * degree) * lookup + j], combined[j]);
    }
    for (uint j = 0; j < degree; ++j) denominators[degree * i + j] = gl_canon(result[j]);
}
__kernel void device_lookup_batch_inverse(__global ulong *values, uint count,
    __global uint *status, uint degree) {
    __local ulong tree[256 * 3];
    uint lane = get_local_id(0);
    size_t i = get_group_id(0) * 128 + lane;
    ulong a[3] = {1, 0, 0};
    if (i < count) for (uint j = 0; j < degree; ++j) a[j] = values[degree * i + j];
    if (a[0] == 0 && a[1] == 0 && (degree == 2 || a[2] == 0)) {
        atomic_or(status, 1U);
        a[0] = 1; // Drain safely, then reject the result on the host.
    }
    for (uint j = 0; j < degree; ++j) tree[degree * (128 + lane) + j] = a[j];
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint offset = 64; offset > 0; offset >>= 1) {
        if (lane < offset) {
            uint node = offset + lane;
            ulong left[3], right[3], product[3];
            for (uint j = 0; j < degree; ++j) { left[j] = tree[(2 * degree) * node + j]; right[j] = tree[(2 * degree) * node + degree + j]; }
            lookup_mul(degree, left, right, product);
            for (uint j = 0; j < degree; ++j) tree[degree * node + j] = product[j];
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (lane == 0) {
        ulong product[3], inverse[3];
        for (uint j = 0; j < degree; ++j) product[j] = tree[degree + j];
        lookup_inverse(degree, product, inverse);
        for (uint j = 0; j < degree; ++j) tree[degree + j] = inverse[j];
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint offset = 1; offset < 128; offset <<= 1) {
        if (lane < offset) {
            uint node = offset + lane;
            ulong inverse[3], left[3], right[3], il[3], ir[3];
            for (uint j = 0; j < degree; ++j) {
                inverse[j] = tree[degree * node + j]; left[j] = tree[(2 * degree) * node + j]; right[j] = tree[(2 * degree) * node + degree + j];
            }
            lookup_mul(degree, inverse, right, il); lookup_mul(degree, inverse, left, ir);
            for (uint j = 0; j < degree; ++j) { tree[(2 * degree) * node + j] = il[j]; tree[(2 * degree) * node + degree + j] = ir[j]; }
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (i < count) for (uint j = 0; j < degree; ++j) values[degree * i + j] = gl_canon(tree[degree * (128 + lane) + j]);
}
__kernel void device_lookup_fractions(__global const ulong *inverses,
    __global const ulong *expressions, uint expression_width, __global const ulong *tuples,
    __global const ulong *boundaries, uint lookups, uint tuple_count,
    __global ulong *output, __global ulong *totals, uint rows, uint first_row, uint degree) {
    uint row = get_global_id(0);
    if (row >= rows) return;
    ulong sum[3] = {0, 0, 0};
    for (uint lookup = 0; lookup < lookups; ++lookup) {
        ulong fraction[3] = {0, 0, 0};
        for (uint t = boundaries[lookup]; t < boundaries[lookup + 1]; ++t) {
            ulong mult = expressions[(size_t)row * expression_width + tuples[3 * t + 1]];
            for (uint j = 0; j < degree; ++j) fraction[j] = gl_add(fraction[j], gl_mul(mult, inverses[((size_t)row * tuple_count + t) * degree + j]));
        }
        for (uint j = 0; j < degree; ++j) {
            output[((size_t)(first_row + row) * (lookups + 1) + lookup + 1) * degree + j] = gl_canon(fraction[j]);
            sum[j] = gl_add(sum[j], fraction[j]);
        }
    }
    for (uint j = 0; j < degree; ++j) totals[(size_t)(first_row + row) * degree + j] = gl_canon(sum[j]);
}
__kernel void device_lookup_scan_blocks(__global ulong *values, __global ulong *totals, uint count, uint degree) {
    __local ulong sums[128 * 3];
    uint lane = get_local_id(0);
    size_t row = get_group_id(0) * 128 + lane;
    ulong original[3] = {0, 0, 0};
    if (row < count) for (uint j = 0; j < degree; ++j) original[j] = values[degree * row + j];
    for (uint j = 0; j < degree; ++j) sums[degree * lane + j] = original[j];
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = 1; stride < 128; stride <<= 1) {
        uint i = (lane + 1) * 2 * stride - 1;
        if (i < 128) for (uint j = 0; j < degree; ++j) sums[degree * i + j] = gl_add(sums[degree * i + j], sums[degree * (i - stride) + j]);
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (lane == 0) for (uint j = 0; j < degree; ++j) { totals[degree * get_group_id(0) + j] = gl_canon(sums[degree * 127 + j]); sums[degree * 127 + j] = 0; }
    barrier(CLK_LOCAL_MEM_FENCE);
    for (uint stride = 64; stride > 0; stride >>= 1) {
        uint i = (lane + 1) * 2 * stride - 1;
        if (i < 128) for (uint j = 0; j < degree; ++j) {
            ulong left = sums[degree * (i - stride) + j], parent = sums[degree * i + j];
            sums[degree * (i - stride) + j] = parent; sums[degree * i + j] = gl_add(parent, left);
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    if (row < count) for (uint j = 0; j < degree; ++j) values[degree * row + j] = gl_canon(gl_add(sums[degree * lane + j], original[j]));
}
__kernel void device_lookup_scan_offsets(__global ulong *values, __global const ulong *offsets, uint count, uint degree) {
    size_t row = get_global_id(0);
    if (row >= count || row < 128) return;
    size_t block = row / 128;
    for (uint j = 0; j < degree; ++j) values[degree * row + j] = gl_canon(gl_add(values[degree * row + j], offsets[degree * (block - 1) + j]));
}
__kernel void device_lookup_accumulator(__global const ulong *inclusive, __global ulong *output, uint rows, uint columns, uint degree) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    for (uint j = 0; j < degree; ++j) output[row * columns * degree + j] = row == 0 ? 0UL : inclusive[degree * (row - 1) + j];
}
"#;
