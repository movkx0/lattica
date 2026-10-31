// Exact inverse radix-2 DIF over Goldilocks. The input and twiddle buffers
// are private to one admitted compiler operation on the in-order queue.
__kernel void device_compiler_periodic_parameters(__global ulong *table,
    ulong root, uint length) {
    table[0] = compiler_inv((ulong)length);
    table[1] = compiler_inv(root);
}

__kernel void device_compiler_periodic_twiddles(__global ulong *table,
    uint count) {
    uint i = get_global_id(0);
    if (i < count) table[i + 2] = gl_canon(gl_pow(table[1], (ulong)i));
}

__kernel void device_compiler_periodic_dif(__global ulong *values,
    __global const ulong *table, uint length, uint width) {
    uint k = get_global_id(0);
    if (k >= length / 2) return;
uint half_width = width / 2;
uint j = k % half_width;
uint a = (k / half_width) * width + j;
uint b = a + half_width;
    ulong x = values[a], y = values[b];
    values[a] = gl_add(x, y);
    values[b] = gl_mul(gl_sub(x, y), table[2 + j * (length / width)]);
}

__kernel void device_compiler_periodic_normalize(__global ulong *values,
    __global const ulong *table, uint length, uint log_length) {
    uint i = get_global_id(0);
    if (i >= length) return;
    uint reversed = 0, bits = i;
    for (uint j = 0; j < log_length; ++j) {
        reversed = (reversed << 1) | (bits & 1);
        bits >>= 1;
    }
    // Each disjoint pair has one writer. Other work-items return before reading.
    if (i > reversed) return;
    ulong x = values[i], y = values[reversed];
    values[i] = gl_canon(gl_mul(y, table[0]));
    if (i != reversed) values[reversed] = gl_canon(gl_mul(x, table[0]));
}
