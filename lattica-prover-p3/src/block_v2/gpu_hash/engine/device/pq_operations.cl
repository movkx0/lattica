// Raw graph-node commitment only: no AIR rows are allocated or returned.
// Input is canonical residues, i64 bit patterns, or individually encoded bytes.
__kernel void pq_operation_commit_node(
    __global const ulong *raw, uint kind, ulong modulus, __global ulong *output,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    if (get_global_id(0)) return;
    for (uint i = 0; i < 5; ++i) output[i] = 0;
    uint count = kind == 2 ? 32 : 256;
    if (kind > 2 || (kind == 0 && modulus != 167770241UL && modulus != 3489661057UL)) {
        output[4] = 1; return;
    }
    for (uint i = 0; i < count; ++i) {
        long signed_value = as_long(raw[i]);
        if ((kind == 0 && raw[i] >= modulus)
            || (kind == 1 && (signed_value < -2147483647L || signed_value > 2147483647L))
            || (kind == 2 && raw[i] > 255)) {
            output[4] = 1; return;
        }
    }
    ulong state[8] = {0,0,0,0,0,0,0,0};
    state[0] = kind == 0 ? 0x504f4c595f505131UL
             : kind == 1 ? 0x5349474e50513031UL : 0x4259544550513332UL;
    state[1] = kind == 0 ? modulus : kind == 1 ? 0 : 32;
    state[2] = kind == 2 ? 0 : 256;
    uint rounds = kind == 2 ? 4 : 64;
    for (uint r = 0; r < rounds; ++r) {
        for (uint j = 0; j < 4; ++j) {
            if (kind == 2) {
                state[4+j] = raw[8*r+2*j] | (raw[8*r+2*j+1] << 8);
            } else if (kind == 1) {
                long value = as_long(raw[4*r+j]);
                // The range check above rules out signed-min overflow.
                state[4+j] = value < 0 ? gl_sub(0, (ulong)(-value)) : (ulong)value;
            } else {
                state[4+j] = raw[4*r+j];
            }
        }
        pq_poseidon_permute(state, rci, rcp, rcf, diag);
    }
    for (uint j = 0; j < 4; ++j) output[j] = gl_canon(state[j]);
}
