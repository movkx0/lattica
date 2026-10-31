// Device transforms retain natural/bit-reversed layout explicitly. One block
// owns disjoint row/column tiles; only first/last permutations use distinct
// input/output allocations. Dynamic shared memory is charged by the launcher.
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
// The uploaded roots already contain the squaring chain in descending order.
// Every exponent here is smaller than 2^order, in both transform directions.
__device__ __forceinline__ u64 ntt_root_power(const u64 *roots, u32 order, u32 exponent) {
    u64 value = 1;
    while (exponent) {
        if (exponent & 1) value = gl_mul(value, roots[order - 1]);
        exponent >>= 1;
        --order;
    }
    return value;
}

template<u32 TileStages, u32 ColumnBits>
__device__ __forceinline__ void ntt_body(const u64 *input, u64 *output,
    u32 width, u32 height, u32 first_stage, u32 stages_input, u32 columns_input,
    u32 reverse_input, u32 log_height, u32 reverse_output, const u64 *roots) {
    const u32 stages = TileStages ? TileStages : stages_input;
    const u32 log_columns = ColumnBits ? ColumnBits : columns_input;
    const u32 lane_count = TileStages ? 256 : blockDim.x;
#else
extern "C" __global__ void ntt_tile(const u64 *input, u64 *output,
    u32 width, u32 height, u32 first_stage, u32 stages, u32 log_columns,
    u32 reverse_input, u32 log_height, u32 reverse_output, const u64 *roots) {
    const u32 lane_count = blockDim.x;
#endif
    extern __shared__ u64 tile[];
    const u32 columns = 1u << log_columns;
    const u32 row_tiles = height >> stages;
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
    const u32 row_tile = blockIdx.x & (row_tiles - 1);
    const u32 column_tile = blockIdx.x >> (log_height - stages);
#else
    const u32 row_tile = blockIdx.x % row_tiles;
    const u32 column_tile = blockIdx.x / row_tiles;
#endif
    const u32 lo = row_tile & ((1u << first_stage) - 1);
    const u32 hi = row_tile >> first_stage;
    const u32 row0 = (hi << (first_stage + stages)) | lo;
    const u32 col0 = column_tile << log_columns;
    const u32 elements = (1u << stages) << log_columns;
#ifdef LATTICA_CUDA_TRANSFORM_REUSE
    // One immutable power table per tile, shared by every column and stage.
    // roots[k-1]^j == roots[stages-1]^(j << (stages-k)), for inverse roots too.
    // The host charges both tables in this launch's shared-memory geometry.
    const u32 powers_len = 1u << (stages - 1);
    u64 *powers = tile + elements;
    u64 *outer = powers + powers_len;
#ifdef LATTICA_CUDA_TRANSFORM_TWIDDLE_TABLE
    // All stages' distinct twiddles fit in 2^stages - 1 words. Reuse them
    // across columns and row groups instead of multiplying per butterfly.
    // Narrow tiles retain the original path to avoid extra shared storage.
    u64 *twiddles = outer + stages;
#endif
    for (u32 j = threadIdx.x; j < powers_len; j += lane_count)
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
        powers[j] = ntt_root_power(roots, stages, j);
#else
        powers[j] = gl_pow(roots[stages - 1], j);
#endif
    for (u32 k = threadIdx.x; k < stages; k += lane_count)
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
        outer[k] = ntt_root_power(roots, first_stage + k + 1, lo);
#else
        outer[k] = gl_pow(roots[first_stage + k], lo);
#endif
#endif
    for (u32 e = threadIdx.x; e < elements; e += lane_count) {
        const u32 t = e >> log_columns, col = col0 + (e & (columns - 1));
        const u32 row = row0 + (t << first_stage);
        const u32 source = reverse_input ? bit_reverse(row, log_height) : row;
        tile[e] = col < width ? input[(u64)source * width + col] : 0;
    }
    __syncthreads();
#ifdef LATTICA_CUDA_TRANSFORM_TWIDDLE_TABLE
    if (log_columns >= 2) {
        for (u32 i = threadIdx.x; i < (1u << stages) - 1; i += lane_count) {
            const u32 k = 31u - __clz(i + 1);
            const u32 j = i - ((1u << k) - 1);
            const u64 power = powers[j << (stages - k - 1)];
            twiddles[i] = first_stage ? gl_mul(outer[k], power) : power;
        }
        __syncthreads();
    }
#endif
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
    #pragma unroll
#endif
    for (u32 k = 1; k <= stages; ++k) {
        const u32 half = 1u << (k - 1);
#ifdef LATTICA_CUDA_TRANSFORM_REUSE
        const u64 outer_power = outer[k - 1];
#else
        const u64 outer_power = gl_pow(roots[first_stage + k - 1], lo);
#endif
        for (u32 b = threadIdx.x; b < elements / 2; b += lane_count) {
            const u32 t = b >> log_columns, col = b & (columns - 1);
            const u32 j = t & (half - 1);
            const u32 left = ((((t >> (k - 1)) << k) | j) << log_columns) | col;
            const u32 right = left + (half << log_columns);
#ifdef LATTICA_CUDA_TRANSFORM_REUSE
#ifdef LATTICA_CUDA_TRANSFORM_TWIDDLE_TABLE
            const u64 twiddle = log_columns >= 2 ? twiddles[half - 1 + j]
                : gl_mul(outer_power, powers[j << (stages - k)]);
#else
            const u64 twiddle = gl_mul(outer_power, powers[j << (stages - k)]);
#endif
#else
            const u64 twiddle = gl_mul(outer_power, gl_pow(roots[k - 1], j));
#endif
            const u64 u = tile[left];
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
            // The first group's j=0 butterflies have exactly unit twiddles.
            const u64 v = first_stage == 0 && j == 0 ? tile[right] : gl_mul(tile[right], twiddle);
#else
            const u64 v = gl_mul(tile[right], twiddle);
#endif
            tile[left] = gl_add(u, v);
            tile[right] = gl_sub(u, v);
        }
        __syncthreads();
    }
    for (u32 e = threadIdx.x; e < elements; e += lane_count) {
        const u32 t = e >> log_columns, col = col0 + (e & (columns - 1));
        if (col < width) {
            const u32 row = row0 + (t << first_stage);
            const u32 target = reverse_output ? bit_reverse(row, log_height) : row;
            output[(u64)target * width + col] = gl_canon(tile[e]);
        }
    }
}

#ifdef LATTICA_CUDA_TRANSFORM_STATIC
#define NTT_ARGUMENTS const u64 *input, u64 *output, u32 width, u32 height, \
    u32 first_stage, u32 stages, u32 log_columns, u32 reverse_input, \
    u32 log_height, u32 reverse_output, const u64 *roots
#define NTT_VALUES input, output, width, height, first_stage, stages, log_columns, \
    reverse_input, log_height, reverse_output, roots
extern "C" __global__ void ntt_tile(NTT_ARGUMENTS) { ntt_body<0, 0>(NTT_VALUES); }
extern "C" __global__ __launch_bounds__(256) void ntt_tile_s6(NTT_ARGUMENTS) { ntt_body<6, 4>(NTT_VALUES); }
extern "C" __global__ __launch_bounds__(256) void ntt_tile_s7(NTT_ARGUMENTS) { ntt_body<7, 4>(NTT_VALUES); }
extern "C" __global__ __launch_bounds__(256) void ntt_tile_s8(NTT_ARGUMENTS) { ntt_body<8, 4>(NTT_VALUES); }
#undef NTT_ARGUMENTS
#undef NTT_VALUES
#endif

extern "C" __global__ void transform_parameters(u64 *parameters, u32 rows,
    u64 input_shift, u64 output_shift) {
    parameters[0] = gl_canon(gl_inverse_or_zero(rows));
    parameters[1] = gl_canon(gl_mul(output_shift, gl_inverse_or_zero(input_shift)));
}
extern "C" __global__ void transform_scale(const u64 *coefficients,
    u64 *output, const u64 *parameters, u32 width, u32 input_rows, u32 output_rows) {
    const u64 begin = (u64)blockIdx.x * blockDim.x;
    const u64 i = begin + threadIdx.x;
#ifdef LATTICA_CUDA_TRANSFORM_REUSE
    // Each block computes one factor per distinct row it touches. All threads
    // reach the barrier, including padded lanes in a partial final block.
    // This also handles non-power-of-two widths and rows spanning blocks.
    extern __shared__ u64 factors[];
    const u64 first_row = begin / width;
    const u64 last_row = (begin + blockDim.x - 1) / width;
    const u64 factor_row = first_row + threadIdx.x;
    if (factor_row <= last_row)
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
        factors[threadIdx.x] = factor_row < input_rows
            ? gl_mul(parameters[0], gl_pow(parameters[1], factor_row)) : 0;
#else
        factors[threadIdx.x] = factor_row < input_rows
            ? gl_pow(parameters[1], factor_row) : 0;
#endif
    __syncthreads();
#endif
    if (i >= (u64)output_rows * width) return;
    const u32 row = (u32)(i / width);
#ifdef LATTICA_CUDA_TRANSFORM_REUSE
#ifdef LATTICA_CUDA_TRANSFORM_STATIC
    output[i] = row < input_rows
        ? gl_canon(gl_mul(coefficients[i], factors[row - first_row])) : 0;
#else
    output[i] = row < input_rows
        ? gl_canon(gl_mul(gl_mul(coefficients[i], parameters[0]), factors[row - first_row])) : 0;
#endif
#else
    output[i] = row < input_rows
        ? gl_canon(gl_mul(gl_mul(coefficients[i], parameters[0]), gl_pow(parameters[1], row))) : 0;
#endif
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
