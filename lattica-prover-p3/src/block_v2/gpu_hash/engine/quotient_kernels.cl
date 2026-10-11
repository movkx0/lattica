
// Alpha powers in global constraint emission order, matching the pinned
// verifier's Horner fold. One tiny device pass amortizes this across all rows.
__kernel void QUOTIENT_ALPHA(__global ulong *weights, uint count,
    ulong alpha0, ulong alpha1, ulong alpha2) {
    ulong a[QUOTIENT_DEGREE] = {alpha0, alpha1}, power[QUOTIENT_DEGREE] = {1}, next[QUOTIENT_DEGREE];
#if QUOTIENT_DEGREE == 3
    a[2] = alpha2;
#endif
    for (uint k = count; k > 0; --k) {
        for (uint j = 0; j < QUOTIENT_DEGREE; ++j) weights[QUOTIENT_DEGREE * (size_t)(k - 1) + j] = power[j];
        QUOTIENT_MUL(power, a, next);
        for (uint j = 0; j < QUOTIENT_DEGREE; ++j) power[j] = next[j];
    }
}
__kernel void QUOTIENT_EVALUATE(__global const ulong *code, uint instructions,
    __global const ulong *input, uint width, __global const ulong *parameters,
    __global const ulong *weights, __global ulong *scratch, __global ulong *output,
    uint rows, uint first_row, uint output_first, uint log_trace, ulong quotient_shift,
    ulong quotient_root, ulong trace_last) {
    uint row = (uint)get_global_id(0);
    if (row >= rows) return;
    ulong x = gl_mul(quotient_shift, gl_pow(quotient_root, (ulong)first_row + row));
    ulong z = x;
    for (uint j = 0; j < log_trace; ++j) z = gl_mul(z, z);
    z = gl_sub(z, 1UL);
    ulong transition = gl_sub(x, trace_last);
    if (gl_canon(z) == 0 || gl_canon(gl_sub(x, 1UL)) == 0 || gl_canon(transition) == 0) {
        // Noncanonical sentinel: the host adapter rejects before proof assembly.
        for (uint j = 0; j < QUOTIENT_DEGREE; ++j) output[QUOTIENT_DEGREE * ((size_t)output_first + row) + j] = 0xffffffff00000001UL;
        return;
    }
    ulong inverse_z = gl_pow(z, 0xfffffffeffffffffUL);
    ulong first = gl_mul(z, gl_pow(gl_sub(x, 1UL), 0xfffffffeffffffffUL));
    ulong last = gl_mul(z, gl_pow(transition, 0xfffffffeffffffffUL));
    ulong accumulator[QUOTIENT_DEGREE] = {0};
    for (uint pc = 0; pc < instructions; ++pc) {
        size_t at = 5 * (size_t)pc;
        uint op = (uint)code[at], dst = (uint)code[at + 1];
        ulong aa = code[at + 2], bb = code[at + 3], cc = code[at + 4];
        ulong a[QUOTIENT_DEGREE], b[QUOTIENT_DEGREE], r[QUOTIENT_DEGREE] = {0};
        if (op >= 8) {
            for (uint j = 0; j < QUOTIENT_DEGREE; ++j) a[j] = scratch[((size_t)aa * QUOTIENT_DEGREE + j) * rows + row];
            if (op == 8 || op == 9 || op == 10 || op == 12 || op == 13 || op == 14)
                for (uint j = 0; j < QUOTIENT_DEGREE; ++j) b[j] = scratch[((size_t)bb * QUOTIENT_DEGREE + j) * rows + row];
        }
        switch (op) {
            case 0: r[0] = aa; r[1] = bb;
#if QUOTIENT_DEGREE == 3
                r[2] = cc;
#endif
                break;
            case 1: r[0] = input[(size_t)row * width + aa]; break;
            case 2: for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = input[(size_t)row * width + aa + j]; break;
            case 3: r[0] = parameters[aa]; break;
            case 4: for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = parameters[aa + j]; break;
            case 5: r[0] = first; break;
            case 6: r[0] = last; break;
            case 7: r[0] = transition; break;
            case 8: r[0] = gl_add(a[0], b[0]); break;
            case 9: r[0] = gl_sub(a[0], b[0]); break;
            case 10: r[0] = gl_mul(a[0], b[0]); break;
            case 11: r[0] = gl_neg(a[0]); break;
            case 12: for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = gl_add(a[j], b[j]); break;
            case 13: for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = gl_sub(a[j], b[j]); break;
            case 14: QUOTIENT_MUL(a, b, r); break;
            case 15: for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = gl_neg(a[j]); break;
            case 16:
                for (uint j = 0; j < QUOTIENT_DEGREE; ++j) r[j] = gl_mul(a[0], weights[QUOTIENT_DEGREE * (size_t)bb + j]);
                break;
            case 17:
                for (uint j = 0; j < QUOTIENT_DEGREE; ++j) b[j] = weights[QUOTIENT_DEGREE * (size_t)bb + j];
                QUOTIENT_MUL(a, b, r); break;
        }
        if (op >= 16) {
            for (uint j = 0; j < QUOTIENT_DEGREE; ++j) accumulator[j] = gl_add(accumulator[j], r[j]);
        } else {
            // Sources were loaded before writing, so the destination may safely
            // reuse an operand's slot at its last consumer.
            for (uint j = 0; j < QUOTIENT_DEGREE; ++j) scratch[((size_t)dst * QUOTIENT_DEGREE + j) * rows + row] = r[j];
        }
    }
    for (uint j = 0; j < QUOTIENT_DEGREE; ++j) output[QUOTIENT_DEGREE * ((size_t)output_first + row) + j] = gl_canon(gl_mul(accumulator[j], inverse_z));
}

#undef QUOTIENT_DEGREE
#undef QUOTIENT_ALPHA
#undef QUOTIENT_EVALUATE
#undef QUOTIENT_MUL
