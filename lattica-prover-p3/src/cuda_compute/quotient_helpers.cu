extern "C" __global__ void quotient_domain(u64 *status, u32 log_rows, u64 shift) {
    status[0] = gl_canon(gl_pow(shift, 1ULL << log_rows)) == 1 ? 1 : 0;
}

// Concatenate current/next main, preprocessing and permutation rows into the
// exact shared AIR bytecode layout. Each input may have a different row order.
extern "C" __global__ void quotient_gather(
    const u64 *main, const u64 *preprocessed, const u64 *permutation, u64 *output,
    u32 main_width, u32 pre_width, u32 perm_width,
    u32 main_reversed, u32 pre_reversed, u32 perm_reversed,
    u32 log_rows, u32 next_step, u32 first_row, u32 rows) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    const u32 width = 2 * (main_width + pre_width + perm_width);
    if (i >= (u64)rows * width) return;
    const u32 row = first_row + (u32)(i / width);
    u32 col = (u32)(i % width), columns, reverse;
    const u64 *input;
    if (col < 2 * main_width) {
        input = main; columns = main_width; reverse = main_reversed;
    } else if (col < 2 * (main_width + pre_width)) {
        col -= 2 * main_width;
        input = preprocessed; columns = pre_width; reverse = pre_reversed;
    } else {
        col -= 2 * (main_width + pre_width);
        input = permutation; columns = perm_width; reverse = perm_reversed;
    }
    const u32 at = col < columns ? row : (row + next_step) & ((1u << log_rows) - 1u);
    const u32 physical = reverse ? bit_reverse(at, log_rows) : at;
    output[i] = input[(u64)physical * columns + col % columns];
}
