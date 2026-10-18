// Each workgroup computes each covered row's public coset scale once.
__kernel void device_transform_scale_shared(__global const ulong *coefficients,
    __global ulong *output, __global const ulong *parameters,
    uint width, uint input_rows, uint output_rows, __local ulong *scales) {
    const size_t first = get_group_id(0) * get_local_size(0);
    const size_t total = (size_t)output_rows * width;
    if (first >= total) return; // Uniform across the workgroup.
    const uint lane = get_local_id(0);
    const uint first_row = (uint)(first / width);
    const size_t end = min(first + get_local_size(0), total);
    const uint row_count = (uint)((end - 1) / width) - first_row + 1;
    if (lane < row_count) {
        const uint row = first_row + lane;
        scales[lane] = row < input_rows
            ? gl_mul(parameters[0], gl_pow(parameters[1], (ulong)row)) : 0UL;
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    const size_t i = first + lane;
    if (i >= total) return;
    const uint row = (uint)(i / width);
    output[i] = row < input_rows
        ? gl_canon(gl_mul(coefficients[i], scales[row - first_row])) : 0UL;
}
