// Same-point polynomial compression commutes with interpolation and division.
// Preserve the original per-matrix alpha offset, including alpha=0.
__kernel void OPENING_GROUP(__global const ulong *input,
    __global const ulong *weights, __global const ulong *member_terms,
    __global ulong *output, __global ulong *group_terms,
    uint rows, uint width, uint log_rows, uint first) {
    size_t row = get_global_id(0);
    if (row >= rows) return;
    ulong sum[OPENING_DEGREE], offset[OPENING_DEGREE], scaled[OPENING_DEGREE];
    for (uint k = 0; k < OPENING_DEGREE; ++k) {
        sum[k] = 0;
        offset[k] = member_terms[k];
    }
    for (uint col = 0; col < width; ++col)
        for (uint k = 0; k < OPENING_DEGREE; ++k)
            sum[k] = gl_add(sum[k], gl_mul(input[row * (size_t)width + col],
                weights[OPENING_DEGREE * (size_t)col + k]));
    OPENING_MUL(offset, sum, scaled);
    size_t at = (size_t)brev((uint)row, log_rows) * OPENING_DEGREE;
    for (uint k = 0; k < OPENING_DEGREE; ++k)
        output[at + k] = gl_canon(first ? scaled[k] : gl_add(output[at + k], scaled[k]));
    if (row == 0) {
        for (uint k = 0; k < OPENING_DEGREE; ++k) sum[k] = member_terms[OPENING_DEGREE + k];
        OPENING_MUL(offset, sum, scaled);
        for (uint k = 0; k < OPENING_DEGREE; ++k) {
            group_terms[k] = k == 0 ? 1UL : 0UL;
            group_terms[OPENING_DEGREE + k] = gl_canon(first ? scaled[k]
                : gl_add(group_terms[OPENING_DEGREE + k], scaled[k]));
        }
    }
}
