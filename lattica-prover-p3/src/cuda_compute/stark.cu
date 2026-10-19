// Public periodic tables are supplied once and expanded before interpolation.
extern "C" __global__ void stark_periodic_expand(const u64 *source,
    const u64 *metadata, u64 *output, u64 rows, u64 columns) {
    const u64 i = (u64)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= rows * columns) return;
    const u64 row = i / columns, column = i % columns;
    const u64 offset = metadata[2 * column], length = metadata[2 * column + 1];
    output[i] = source[offset + (row & (length - 1))];
}
