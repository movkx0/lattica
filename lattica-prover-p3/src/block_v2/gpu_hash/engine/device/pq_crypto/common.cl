// Portable crypto trace primitives. Input bytes are scalar words, never fields
// containing a host-computed trace. Poseidon helpers are shared with other AIRs.
#define PQ_CONST __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag
#define PQ_PASS rci, rcp, rcf, diag
#define PQ_ARGS __global const ulong *input, __global const ulong *g, __global ulong *tmp, __global ulong *trace, __global ulong *public_values, PQ_CONST
#define PQ_AES_TABLE 16896UL
#define PQ_SHAKE_PREP 133UL
inline void pq_bits(__global ulong *row, uint offset, ulong x, uint count) {
    for (uint b=0;b<count;++b) row[offset+b]=(x>>b)&1UL;
}
inline void pq_byte_bits(__global ulong *row,uint offset,const uchar *bytes,uint count) {
    for(uint j=0;j<count;++j) pq_bits(row,offset+j*8,(ulong)bytes[j],8);
}
inline void pq_limbs(__global ulong *out,const ulong state[25]) {
    for(uint j=0;j<100;++j) out[j]=(state[j/4]>>(16*(j%4)))&65535UL;
}
inline void pq_crypto_absorb(ulong acc[4],const uchar bytes[8],uint count,ulong seed[8],PQ_CONST) {
    ulong s[8];
    for(uint j=0;j<8;++j) s[j]=j<4?acc[j]:0;
    for(uint j=0;j<count;++j) s[4+j/2]|=((ulong)bytes[j])<<(8*(j%2));
    for(uint j=0;j<8;++j) seed[j]=s[j];
    pq_poseidon_permute(s,PQ_PASS);
    for(uint j=0;j<4;++j) acc[j]=s[j];
}
inline void pq_crypto_hash_row(__global ulong *row,uint offset,ulong acc[4],
    const uchar bytes[8],uint count,uint advance,PQ_CONST) {
    ulong updated[4],seed[8];
    for(uint j=0;j<4;++j) updated[j]=acc[j];
    pq_crypto_absorb(updated,bytes,count,seed,PQ_PASS);
    for(uint j=0;j<8;++j) row[offset+j]=seed[j];
    if(advance) for(uint j=0;j<4;++j) acc[j]=updated[j];
}
inline ulong pq_crypto_public_offset(__global const ulong *g) {
    return g[0]<=1?PQ_AES_TABLE+(g[3]+g[4])*16+(g[4]+1)*8:g[4]*PQ_SHAKE_PREP;
}
__kernel void pq_crypto_poseidon_rows(__global ulong *trace,uint width,uint offset,
    uint count,ulong rows,PQ_CONST) {
    ulong i=get_global_id(0);
    if(i>=rows*count)return;
    pq_poseidon_trace_row(trace,width,offset+(uint)(i%count)*94,i/count,PQ_PASS);
}
__kernel void pq_crypto_public_values(__global const ulong *g,__global const ulong *tmp,
    __global ulong *public_values) {
    uint i=get_global_id(0);
    if(i<g[11])public_values[i]=gl_canon(tmp[pq_crypto_public_offset(g)+i]);
}
