// One 32-bit plane per limb. On 32-bank hardware, the 32-entry quotient
// table maps one entry to each bank: repeated indices broadcast, distinct
// indices never collide. Selector indices are consecutive (or reversed)
// within each warp, so its 64-entry planes also have no bank conflicts.
inline ulong compiler_table_word(__local const uint *low,
    __local const uint *high, uint index) {
    return ((ulong)high[index] << 32) | (ulong)low[index];
}

__attribute__((reqd_work_group_size(32, 1, 1)))
__kernel void device_compiler_constants(__global const ulong *input,
    __global ulong *output, uint operation, uint count, uint size, ulong log_root) {
    const uint k = get_global_id(0), lane = get_local_id(0);
    __local uint low[64], high[64];
    if (operation == 0) {
        if (k < count) output[k] = compiler_inverse_roots[log_root];
        return;
    }

    // Every lane participates, including padding beyond count. Inactive
    // lanes may return only after the workgroup's table is fully populated.
    const uint entries = operation == 1 ? 64u : 32u;
    for (uint i = lane; i < entries; i += 32u) {
        const ulong word = operation == 1 ? compiler_inverse_factorials[i]
            : compiler_reciprocal_differences[i];
        low[i] = (uint)word;
        high[i] = (uint)(word >> 32);
    }
    barrier(CLK_LOCAL_MEM_FENCE);
    if (k >= count) return;

    if (operation == 1) {
        // Product_{j != k}(k-j) = k! * (-1)^(count-1-k) * (count-1-k)!.
        // Translation by first cancels, including ranges next to the modulus.
        const uint opposite = count - 1u - k;
        ulong weight = gl_mul(compiler_table_word(low, high, k),
            compiler_table_word(low, high, opposite));
        output[k] = gl_canon((opposite & 1u) ? gl_sub(0UL, weight) : weight);
    } else if (operation == 3) {
        if (k < size) {
            output[k] = gl_canon(gl_mul(compiler_inverse_coset[0],
                gl_pow(compiler_inverse_roots[log_root], (ulong)k)));
        } else {
            const uint i = (k - size) / size, j = (k - size) % size;
            // (g^(i-j))^(2^height) is a size-th root of unity. Every
            // supported size divides 32, so one table covers every height.
            // Entry zero is the specified diagonal sentinel, not an inverse.
            const uint difference = (i + size - j) & (size - 1u);
            output[k] = compiler_table_word(low, high, difference * (32u / size));
        }
    }
}
