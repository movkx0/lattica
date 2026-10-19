// Public protocol hashes are distinct from both commitments and transcripts.
// Each chunk overwrites the upper four words and retains only the lower four.
extern "C" __global__ void public_hash(u64 *state, const u64 *input,
    u64 domain, u64 length, u32 first, u32 count, const u64 *constants) {
    u64 s[8] = {0};
    for (u32 i = 0; i < 4; ++i) s[i] = first ? 0 : state[i];
    if (first) { s[0] = domain; s[1] = length; }
    for (u32 offset = 0; offset < count; offset += 4) {
        for (u32 i = 0; i < 4; ++i)
            s[4 + i] = offset + i < count ? input[offset + i] : 0;
        poseidon_permute(s, constants);
    }
    for (u32 i = 0; i < 4; ++i) state[i] = gl_canon(s[i]);
}

extern "C" __global__ void public_summary(const u64 *words, u64 *status,
    u64 modes, u32 mode_index, u32 level_index, u32 count_index,
    u32 root_index, u32 depth) {
    for (u32 i = 0; i < 16; ++i) {
        if (words[i] > 0xffffffffULL) { status[0] = 1; return; }
    }
    const u64 mode = words[mode_index], level = words[level_index];
    if (mode == 0 || mode > modes || level > depth) { status[0] = 2; return; }
    if (words[count_index] > (1ULL << level)) { status[0] = 2; return; }
    for (u32 i = 0; i < 4; ++i) {
        if (words[root_index + i] >= GP) { status[0] = 3; return; }
    }
    status[0] = 0;
}

extern "C" __global__ void public_constants(u64 input, u64 *output,
    u32 operation, u32 count, u32 size, u64 exponent) {
    const u32 k = blockIdx.x * blockDim.x + threadIdx.x;
    if (k >= count) return;
    if (operation == 0) output[k] = gl_canon(gl_inverse_or_zero(input));
    else if (operation == 1) {
        u64 denominator = 1;
        for (u32 j = 0; j < count; ++j) {
            if (j != k)
                denominator = gl_mul(denominator, gl_sub(input + k, input + j));
        }
        output[k] = gl_canon(gl_inverse_or_zero(denominator));
    } else if (operation == 3) {
        if (k < size) {
            output[k] = gl_canon(gl_inverse_or_zero(gl_mul(7, gl_pow(input, k))));
        } else {
            const u32 i = (k - size) / size, j = (k - size) % size;
            if (i == j) { output[k] = 0; return; }
            const u64 a = gl_mul(7, gl_pow(input, i));
            const u64 b = gl_mul(7, gl_pow(input, j));
            const u64 denominator = gl_sub(gl_pow(gl_mul(a, gl_inverse_or_zero(b)), exponent), 1);
            output[k] = gl_canon(gl_inverse_or_zero(denominator));
        }
    }
}

// Fixed tiles bound both host staging and device scratch, independently of the
// public period. A later optimization may substitute a qualified inverse NTT.
extern "C" __global__ void public_periodic(const u64 *input, u64 *output,
    u64 root, u32 length, u32 input_start, u32 input_count,
    u32 coefficient_start, u32 count) {
    const u32 k = blockIdx.x * blockDim.x + threadIdx.x;
    if (k >= count) return;
    const u64 step = gl_pow(gl_inverse_or_zero(root), (u64)coefficient_start + k);
    u64 power = gl_pow(step, input_start);
    u64 sum = input_start == 0 ? 0 : output[k];
    for (u32 j = 0; j < input_count; ++j) {
        sum = gl_add(sum, gl_mul(power, input[j]));
        power = gl_mul(power, step);
    }
    if (input_start + input_count == length)
        sum = gl_mul(sum, gl_inverse_or_zero(length));
    output[k] = gl_canon(sum);
}

extern "C" __global__ void public_fold(const u64 *input, u64 *output,
    u32 operation) {
    const u64 a[3] = {input[0], input[1], input[2]};
    const u64 b[3] = {input[3], input[4], input[5]};
    u64 value[3] = {0}, invertible = 1;
    if (operation == 0) value[0] = gl_add(a[0], b[0]);
    else if (operation == 1) value[0] = gl_mul(a[0], b[0]);
    else if (operation == 2) {
        invertible = a[0] != 0;
        value[0] = gl_inverse_or_zero(a[0]);
    } else if (operation == 3) fe_mul<3>(a, b, value);
    else if (operation == 4) {
        invertible = (a[0] | a[1] | a[2]) != 0;
        fe_inverse_or_zero<3>(a, value);
    }
    for (u32 i = 0; i < 3; ++i) output[i] = gl_canon(value[i]);
    output[3] = invertible;
}
