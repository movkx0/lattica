// Device transforms retain natural/bit-reversed layout explicitly. One block
// owns disjoint row/column tiles; only first/last permutations use distinct
// input/output allocations. Dynamic shared memory is charged by the launcher.
extern "C" __global__ void ntt_tile(const u64 *input, u64 *output,
    u32 width, u32 height, u32 first_stage, u32 stages, u32 log_columns,
    u32 reverse_input, u32 log_height, u32 reverse_output, const u64 *roots) {
    extern __shared__ u64 tile[];
    const u32 columns = 1u << log_columns;
    const u32 row_tiles = height >> stages;
    const u32 row_tile = blockIdx.x % row_tiles;
    const u32 column_tile = blockIdx.x / row_tiles;
    const u32 lo = row_tile & ((1u << first_stage) - 1);
    const u32 hi = row_tile >> first_stage;
    const u32 row0 = (hi << (first_stage + stages)) | lo;
    const u32 col0 = column_tile << log_columns;
    const u32 elements = (1u << stages) << log_columns;
    for (u32 e = threadIdx.x; e < elements; e += blockDim.x) {
        const u32 t = e >> log_columns, col = col0 + (e & (columns - 1));
        const u32 row = row0 + (t << first_stage);
        const u32 source = reverse_input ? bit_reverse(row, log_height) : row;
        tile[e] = col < width ? input[(u64)source * width + col] : 0;
    }
    __syncthreads();
    for (u32 k = 1; k <= stages; ++k) {
        const u32 half = 1u << (k - 1);
        const u64 outer = gl_pow(roots[first_stage + k - 1], lo);
        for (u32 b = threadIdx.x; b < elements / 2; b += blockDim.x) {
            const u32 t = b >> log_columns, col = b & (columns - 1);
            const u32 j = t & (half - 1);
            const u32 left = ((((t >> (k - 1)) << k) | j) << log_columns) | col;
            const u32 right = left + (half << log_columns);
            const u64 twiddle = gl_mul(outer, gl_pow(roots[k - 1], j));
            const u64 u = tile[left], v = gl_mul(tile[right], twiddle);
            tile[left] = gl_add(u, v);
            tile[right] = gl_sub(u, v);
        }
        __syncthreads();
    }
    for (u32 e = threadIdx.x; e < elements; e += blockDim.x) {
        const u32 t = e >> log_columns, col = col0 + (e & (columns - 1));
        if (col < width) {
            const u32 row = row0 + (t << first_stage);
            const u32 target = reverse_output ? bit_reverse(row, log_height) : row;
            output[(u64)target * width + col] = gl_canon(tile[e]);
        }
    }
}

extern "C" __global__ void transform_parameters(u64 *parameters, u32 rows,
    u64 input_shift, u64 output_shift) {
    parameters[0] = gl_canon(gl_inverse_or_zero(rows));
    parameters[1] = gl_canon(gl_mul(output_shift, gl_inverse_or_zero(input_shift)));
}
extern "C" __global__ void transform_scale(const u64 *coefficients,
    u64 *output, const u64 *parameters, u32 width, u32 input_rows, u32 output_rows) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)output_rows * width) return;
    const u32 row = (u32)(i / width);
    output[i] = row < input_rows
        ? gl_canon(gl_mul(gl_mul(coefficients[i], parameters[0]), gl_pow(parameters[1], row))) : 0;
}
extern "C" __global__ void query_prefix(const u64 *input, u64 *output,
    u32 input_width, u32 first, u32 width, u32 rows, u32 log_rows) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)rows * width) return;
    const u32 row = (u32)(i / width);
    output[i] = input[(u64)bit_reverse(row, log_rows) * input_width + first + i % width];
}
extern "C" __global__ void gather_rows(const u64 *input, const u64 *indices,
    u64 *output, u32 width, u32 queries) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= (u64)queries * width) return;
    output[i] = input[indices[i / width] * width + i % width];
}
