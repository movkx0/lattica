// One bounded stream, no AIR trace allocation or readback. Canonical field
// validation is performed here even for the empty-stream identity operation.
__kernel void pq_operation_commit_fields(__global const ulong *raw,
    uint count, uint begin, __global const ulong *initial, __global ulong *output,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    ulong state[8];
    if(begin==0) {
        output[4]=0;
        for(uint j=0;j<4;++j) {output[j]=0;state[j]=initial[j];}
        for(uint j=0;j<4;++j) if(state[j]>=GP) {output[4]=1;return;}
    } else {
        if(output[4]!=0)return;
        for(uint j=0;j<4;++j)state[j]=output[j];
    }
    // The host launches consecutive aligned tiles on one queue. State remains
    // in device memory; no long unbounded single-work-item hash launch occurs.
    uint end=min(count,begin+4096u);
    for(uint j=begin;j<end;++j) if(raw[j]>=GP) {output[4]=2;return;}
    for(uint offset=begin;offset<end;offset+=4) {
        for(uint j=0;j<4;++j) state[4+j]=offset+j<end?raw[offset+j]:0;
        pq_poseidon_permute(state,rci,rcp,rcf,diag);
    }
    for(uint j=0;j<4;++j) output[j]=gl_canon(state[j]);
}
