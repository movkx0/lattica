//! Assemble the existing batch AIR from owned wallet traces and public values.
//! The AIR supplies the layout and ordered statement-chunk columns.
pub(crate) const KERNEL_SRC: &str = r#"
// g: height, batch width, wallet width, public width, fold base, root block,
// root column, root output row, tile count, chunk count, domain, chunk columns.
__kernel void device_wallet_batch_copy(__global const ulong *single,
    __global const ulong *public_values, __global const ulong *g,
    __global ulong *trace, uint tile) {
    ulong row=get_global_id(0); if(row>=g[0])return;
    ulong dst=((ulong)tile*g[0]+row)*g[1];
    for(ulong c=0;c<g[2];++c)trace[dst+c]=single[row*g[2]+c];
    for(ulong c=0;c<g[3];++c)trace[dst+g[2]+c]=public_values[c];
}
__kernel void device_wallet_batch_fold(__global const ulong *g,
    __global ulong *trace, __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    if(get_global_id(0)!=0)return;
    ulong root[4]={0,0,0,0};
    for(uint tile=0;tile<(uint)g[8];++tile) {
        ulong base=(ulong)tile*g[0]*g[1];
        uint block_base=tile*(uint)(g[0]/32);
        ulong state[8]={gl_canon(g[10]),0,0,0,0,0,0,0};
        for(uint chunk=0;chunk<(uint)g[9];++chunk) {
            for(uint j=0;j<4;++j) {
                ulong col=g[11+chunk*4+j];
                state[4+j]=(col==((ulong)-1))?0:trace[base+col];
            }
            js_permutation(trace,g,block_base+(uint)g[4]+chunk,state,rci,rcp,rcf,diag);
        }
        for(uint j=0;j<4;++j){state[4+j]=state[j];state[j]=root[j];}
        js_permutation(trace,g,block_base+(uint)g[5],state,rci,rcp,rcf,diag);
        for(ulong row=0;row<g[0];++row)
            for(uint j=0;j<4;++j)
                trace[base+row*g[1]+g[6]+j]=(row<=g[7])?root[j]:state[j];
        for(uint j=0;j<4;++j)root[j]=state[j];
    }
}
__kernel void device_wallet_batch_public(__global const ulong *trace,
    __global const ulong *g, __global ulong *public_values) {
    uint j=get_global_id(0); if(j>=4)return;
    public_values[j]=trace[((g[8]-1)*g[0]+g[7])*g[1]+j];
}

// Public statements from already-proven leaves. Geometry is the same AIR chunk
// table as the batch trace, expressed relative to the public statement columns.
__kernel void device_wallet_tree_root(__global const ulong *statements,
    __global const ulong *dummy, __global const ulong *g,
    uint count, uint padded, __global ulong *output,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    if(get_global_id(0)!=0)return;
    ulong root[4]={0,0,0,0};
    for(uint tile=0;tile<padded;++tile) {
        __global const ulong *pv=tile<count?statements+(ulong)tile*g[1]:dummy;
        ulong state[8]={g[2],0,0,0,0,0,0,0};
        for(uint chunk=0;chunk<(uint)g[0];++chunk) {
            for(uint j=0;j<4;++j) {
                ulong col=g[3+chunk*4+j];
                state[4+j]=col==((ulong)-1)?0:pv[col];
            }
            perm8(state,rci,rcp,rcf,diag);
        }
        for(uint j=0;j<4;++j){state[4+j]=state[j];state[j]=root[j];}
        perm8(state,rci,rcp,rcf,diag);
        for(uint j=0;j<4;++j)root[j]=state[j];
    }
    for(uint j=0;j<4;++j)output[j]=gl_canon(root[j]);
}
"#;
