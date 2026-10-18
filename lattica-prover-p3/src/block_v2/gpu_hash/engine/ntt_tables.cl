// Public roots only. The host admits the entire table before either launch.
__kernel void ntt_fill_table(__global const ulong *roots, __global ulong *out,
                            uint stage, uint count, uint inner, uint words) {
    uint i=get_global_id(0);
    if(i>=words) return;
    if(i<inner) out[i]=gl_pow(roots[count-1u],(ulong)i);
    else {
        uint j=i-inner;
        out[i]=gl_pow(roots[stage+j%count],(ulong)(j/count));
    }
}
