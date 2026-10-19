// Copy the low-coset (physical bit-reversed) prefix while each LDE column tile
// is resident. Prefixes are evaluations, not polynomial coefficients.
extern "C" __global__ void hiding_retain_prefix(const u64 *tile, u64 *prefix,
    u32 rows, u32 columns, u32 prefix_columns, u32 first) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)rows * columns) return;
    prefix[(i / columns) * prefix_columns + first + i % columns] = tile[i];
}

// Reference HidingFriPcs draw order and uniform quotient partition. These
// kernels only consume resident randomness; no host field arithmetic occurs.
extern "C" __global__ void hiding_trace_columns(const u64 *trace,
    const u64 *random, u64 *output, u32 height, u32 trace_width,
    u32 random_columns, u32 first, u32 columns) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)height * columns) return;
    const u64 row = i / columns, original = row / 2;
    const u32 column = first + (u32)(i % columns);
    u64 value;
    if ((row & 1) == 0 && column < trace_width)
        value = trace[original * trace_width + column];
    else if (random_columns == 0)
        value = 0; // Preprocessing interleaves zero rows, with no RNG access.
    else {
        u64 at = original * (trace_width + 2 * random_columns);
        at += (row & 1) == 0 ? column - trace_width : random_columns + column;
        value = random[at];
    }
    output[i] = gl_canon(value);
}

extern "C" __global__ void hiding_quotient_parameters(u64 *parameters,
    u32 height, u32 chunks, u64 shift, u64 omega, u64 generator) {
    const u32 chunk = blockIdx.x * blockDim.x + threadIdx.x;
    if (chunk >= chunks) return;
    const u64 chunk_shift = gl_mul(shift, gl_pow(omega, chunk));
    const u64 ratio = gl_mul(generator, gl_inverse_or_zero(chunk_shift));
    parameters[3 * chunk] = gl_canon(gl_inverse_or_zero(height));
    parameters[3 * chunk + 1] = gl_canon(ratio);
    parameters[3 * chunk + 2] = gl_canon(gl_pow(ratio, height));
}

extern "C" __global__ void hiding_quotient_columns(const u64 *quotient,
    const u64 *random, u64 *output, u32 height, u32 chunks, u32 chunk,
    u32 degree, u32 random_columns, u32 first, u32 columns) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)height * columns) return;
    const u64 row = i / columns;
    const u32 column = first + (u32)(i % columns);
    const u64 value = column < degree
        ? quotient[(row * chunks + chunk) * degree + column]
        : random[((u64)chunk * height + row) * random_columns + column - degree];
    output[i] = gl_canon(value);
}

extern "C" __global__ void hiding_quotient_coefficients(const u64 *coefficients,
    const u64 *masks, const u64 *parameters, u64 *output, u32 height,
    u32 chunks, u32 chunk, u32 width, u32 first, u32 columns, u64 generator) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    const u64 elements = (u64)height * columns;
    if (i >= elements) return;
    const u64 row = i / columns, column = first + i % columns;
    const u64 at = row * width + column, chunk_words = (u64)height * width;
    u64 mask = 0;
    if (chunk + 1 < chunks) mask = masks[(u64)chunk * chunk_words + at];
    else {
        // Normalized vanishing weights of the complete uniform partition
        // are equal. The final mask cancels every earlier chunk's mask.
        for (u32 c = 0; c + 1 < chunks; ++c)
            mask = gl_sub(mask, masks[(u64)c * chunk_words + at]);
    }
    const u64 scaled = gl_mul(gl_mul(coefficients[i], parameters[3 * chunk]),
        gl_pow(parameters[3 * chunk + 1], row));
    const u64 hidden = gl_mul(mask, gl_pow(generator, row));
    output[i] = gl_canon(gl_sub(scaled, hidden));
    output[elements + i] = gl_canon(gl_mul(parameters[3 * chunk + 2], hidden));
}

// Direct randomization polynomials already include their masking columns.
// Copy the selected natural-order columns without changing their row layout.
extern "C" __global__ void hiding_randomization_columns(const u64 *samples,
    u64 *output, u32 rows, u32 width, u32 first, u32 columns) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)rows * columns) return;
    output[i] = gl_canon(samples[(i / columns) * width + first + i % columns]);
}
