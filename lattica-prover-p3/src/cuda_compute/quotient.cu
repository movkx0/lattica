// Included once per extension. The shared specializer supplies the same
// 64-instruction blocks used by OpenCL; other shapes execute this GPU IR.
extern "C" __global__ void QUOTIENT_ALPHA(
    u64 *weights, u32 count, const u64 *alpha) {
    u64 power[QUOTIENT_DEGREE] = {1};
    for (u32 k = count; k > 0; --k) {
        #pragma unroll
        for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
            weights[QUOTIENT_DEGREE * (u64)(k - 1) + j] = gl_canon(power[j]);
        fe_mul<QUOTIENT_DEGREE>(power, alpha, power);
    }
}

extern "C" __global__ void QUOTIENT_EVALUATE(
    const u64 *code, u32 instructions, const u64 *input, u32 width,
    const u64 *parameters, const u64 *weights, u64 *scratch, u64 *output,
    u32 rows, u32 first_row, u32 output_first, u32 log_trace,
    u64 quotient_shift, u64 quotient_root, u64 trace_last) {
    const u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= rows) return;
    const u64 x = gl_mul(quotient_shift, gl_pow(quotient_root, (u64)first_row + row));
    u64 z = x;
    for (u32 j = 0; j < log_trace; ++j) z = gl_mul(z, z);
    z = gl_sub(z, 1);
    const u64 transition = gl_sub(x, trace_last);
    // The domain kernel has already rejected intersecting cosets. Keep the
    // sentinel for defense in depth; no division by a zero selector is valid.
    if (gl_canon(z) == 0 || gl_canon(gl_sub(x, 1)) == 0 || gl_canon(transition) == 0) {
        for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
            output[QUOTIENT_DEGREE * ((u64)output_first + row) + j] = GP;
        return;
    }
    const u64 inverse_z = gl_inverse_or_zero(z);
    const u64 first = gl_mul(z, gl_inverse_or_zero(gl_sub(x, 1)));
    const u64 last = gl_mul(z, gl_inverse_or_zero(transition));
    u64 accumulator[QUOTIENT_DEGREE] = {0};
#ifdef QUOTIENT_SPECIALIZED
    QUOTIENT_SPECIALIZED(input, width, parameters, weights, scratch, rows, row,
        first, last, transition, accumulator);
#else
    for (u32 pc = 0; pc < instructions; ++pc) {
        const u64 at = (u64)pc * 5;
        const u32 op = (u32)code[at], dst = (u32)code[at + 1];
        const u64 aa = code[at + 2], bb = code[at + 3], cc = code[at + 4];
        u64 a[QUOTIENT_DEGREE], b[QUOTIENT_DEGREE], value[QUOTIENT_DEGREE] = {0};
        if (op >= 8) {
            for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
                a[j] = scratch[(aa * QUOTIENT_DEGREE + j) * rows + row];
            if (op == 8 || op == 9 || op == 10 || op == 12 || op == 13 || op == 14)
                for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
                    b[j] = scratch[(bb * QUOTIENT_DEGREE + j) * rows + row];
        }
        switch (op) {
            case 0: value[0] = aa; value[1] = bb;
#if QUOTIENT_DEGREE == 3
                value[2] = cc;
#endif
                break;
            case 1: value[0] = input[(u64)row * width + aa]; break;
            case 2: for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) value[j] = input[(u64)row * width + aa + j]; break;
            case 3: value[0] = parameters[aa]; break;
            case 4: for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) value[j] = parameters[aa + j]; break;
            case 5: value[0] = first; break;
            case 6: value[0] = last; break;
            case 7: value[0] = transition; break;
            case 8: value[0] = gl_add(a[0], b[0]); break;
            case 9: value[0] = gl_sub(a[0], b[0]); break;
            case 10: value[0] = gl_mul(a[0], b[0]); break;
            case 11: value[0] = gl_neg(a[0]); break;
            case 12: for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) value[j] = gl_add(a[j], b[j]); break;
            case 13: for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) value[j] = gl_sub(a[j], b[j]); break;
            case 14: fe_mul<QUOTIENT_DEGREE>(a, b, value); break;
            case 15: for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) value[j] = gl_neg(a[j]); break;
            case 16:
                for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
                    value[j] = gl_mul(a[0], weights[QUOTIENT_DEGREE * bb + j]);
                break;
            case 17:
                for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) b[j] = weights[QUOTIENT_DEGREE * bb + j];
                fe_mul<QUOTIENT_DEGREE>(a, b, value); break;
        }
        if (op >= 16) {
            for (u32 j = 0; j < QUOTIENT_DEGREE; ++j) accumulator[j] = gl_add(accumulator[j], value[j]);
        } else {
            // All operand reads precede a potentially reused destination slot.
            for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
                scratch[((u64)dst * QUOTIENT_DEGREE + j) * rows + row] = value[j];
        }
    }
#endif
    for (u32 j = 0; j < QUOTIENT_DEGREE; ++j)
        output[QUOTIENT_DEGREE * ((u64)output_first + row) + j] = gl_canon(gl_mul(accumulator[j], inverse_z));
}
#undef QUOTIENT_DEGREE
#undef QUOTIENT_ALPHA
#undef QUOTIENT_EVALUATE
#undef QUOTIENT_MUL
#undef QUOTIENT_SPECIALIZED
