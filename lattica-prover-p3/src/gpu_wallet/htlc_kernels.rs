//! HTLC span-end ownership, mode-independent nullifiers, timeout/range and
//! nonzero-hashlock witnesses. Poseidon row writing is shared with join-split.
pub(crate) const KERNEL_SRC: &str = r#"
#ifndef LATTICA_WALLET_FN
#define LATTICA_WALLET_FN
#endif
#define JS_AT(r,c) trace[(ulong)(r) * g[1] + (c)]
__kernel void device_htlc_regions(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global const ulong *rci,__global const ulong *rcp,
    __global const ulong *rcf,__global const ulong *diag) {
    uint item=get_global_id(0),inputs=g[2],outputs=g[3],depth=g[4];
    uint stride=24+5*depth,out_start=inputs*stride,global_start=out_start+11*outputs;
    ulong s[8];for(uint k=0;k<8;++k)s[k]=0;
    if(item<inputs) {
        __global const ulong *v=w+item*stride;uint base=item*g[7],hb=base+4+depth;
        ulong nk0=gl_canon(v[0]),nk1=gl_canon(v[1]),claim[4],owner[4],pos=0;
        s[0]=g[24];s[1]=nk0;s[2]=nk1;s[3]=v[2];
        js_permutation(trace,g,base,s,rci,rcp,rcf,diag);
        for(uint k=0;k<4;++k)claim[k]=s[k];
        for(uint k=0;k<8;++k)s[k]=0;s[0]=g[36];
        for(uint k=0;k<4;++k)s[4+k]=v[11+k];
        js_permutation(trace,g,hb,s,rci,rcp,rcf,diag);
        for(uint part=1;part<4;++part) {
            for(uint k=0;k<4;++k)s[4+k]=part<3?v[11+part*4+k]:(k==0?gl_canon(v[23]):0);
            js_permutation(trace,g,hb+part,s,rci,rcp,rcf,diag);
        }
        for(uint k=0;k<4;++k)owner[k]=v[9]==g[39]?s[k]:claim[k];
        s[0]=g[25];for(uint k=0;k<4;++k)s[1+k]=owner[k];s[5]=gl_canon(v[4]);s[6]=v[5];s[7]=v[6];
        js_permutation(trace,g,base+1,s,rci,rcp,rcf,diag);
        s[4]=v[7];s[5]=v[8];s[6]=v[3];s[7]=v[9];
        js_permutation(trace,g,base+2,s,rci,rcp,rcf,diag);
        for(uint d=0;d<depth;++d) {
            __global const ulong *path=v+24+5*d;ulong child[4];
            for(uint k=0;k<4;++k)child[k]=s[k];
            for(uint k=0;k<4;++k){s[k]=path[4]?path[k]:child[k];s[4+k]=path[4]?child[k]:path[k];}
            JS_AT((base+3+d)*32,g[13])=path[4];pos|=path[4]<<d;
            js_permutation(trace,g,base+3+d,s,rci,rcp,rcf,diag);
        }
        for(uint k=0;k<8;++k)s[k]=0;
        if(v[9]==g[39]) {
            s[0]=g[37];for(uint k=0;k<4;++k)s[1+k]=owner[k];s[5]=v[5];s[6]=v[6];s[7]=pos;
        } else {s[0]=g[26];s[1]=nk0;s[2]=nk1;s[3]=v[5];s[4]=v[6];s[5]=pos;}
        js_permutation(trace,g,base+3+depth,s,rci,rcp,rcf,diag);
        ulong height=w[global_start+6],diff=v[9]==g[39]?(v[10]==1?v[23]-height-1:height-v[23]):0;
        ulong acc=0;
        for(uint row=base*32;row<(base+g[7])*32;++row) {
            JS_AT(row,g[14])=nk0;JS_AT(row,g[15])=nk1;JS_AT(row,g[16])=v[5];JS_AT(row,g[17])=v[6];
            JS_AT(row,g[18])=gl_canon(v[4]);JS_AT(row,g[19])=acc;
            for(uint k=0;k<4;++k){JS_AT(row,g[28]+k)=owner[k];JS_AT(row,g[30]+k)=claim[k];}
            JS_AT(row,g[29])=v[9];JS_AT(row,g[31])=v[10];JS_AT(row,g[32])=gl_canon(v[23]);JS_AT(row,g[33])=gl_canon(diff);
            for(uint d=0;d<depth;++d)if(row==(base+2+d)*32+31)acc+=v[24+5*d+4]<<d;
        }
        js_range(trace,g,(base+1)*32,v[4]);js_range(trace,g,hb*32,v[23]);js_range(trace,g,(hb+2)*32,diff);
        ulong hashlock[4];for(uint k=0;k<4;++k)hashlock[k]=0;
        for(uint i=0;i<inputs;++i)if(w[i*stride+9]==g[39]&&w[i*stride+10]==1) {
            for(uint k=0;k<4;++k)hashlock[k]=w[i*stride+19+k];break;
        }
        uint inverse=4;for(uint k=0;k<4;++k)if(hashlock[k]!=0){inverse=k;break;}
        if(inverse<4)JS_AT((hb+2)*32,g[34]+inverse)=gl_pow(hashlock[inverse],0xfffffffeffffffffUL);
        else JS_AT((hb+2)*32,g[35])=1;
    } else if(item<inputs+outputs) {
        uint j=item-inputs,base=inputs*g[7]+j*g[8];__global const ulong *v=w+out_start+11*j;
        s[0]=g[25];for(uint k=0;k<4;++k)s[1+k]=v[k];s[5]=gl_canon(v[5]);s[6]=v[6];s[7]=v[7];
        js_permutation(trace,g,base,s,rci,rcp,rcf,diag);
        s[4]=v[8];s[5]=v[9];s[6]=v[4];s[7]=v[10];js_permutation(trace,g,base+1,s,rci,rcp,rcf,diag);
        for(uint row=base*32;row<(base+g[8])*32;++row)JS_AT(row,g[18])=gl_canon(v[5]);
        js_range(trace,g,base*32,v[5]);
    } else if(item<inputs+outputs+2) {
        uint part=item-inputs-outputs,base=inputs*g[7]+outputs*g[8]+(part?g[9]:0);
        uint blocks=part?g[10]:g[9];ulong value=w[global_start+part];
        for(uint block=0;block<blocks;++block){for(uint k=0;k<8;++k)s[k]=0;js_permutation(trace,g,base+block,s,rci,rcp,rcf,diag);}
        for(uint row=base*32;row<(base+blocks)*32;++row)JS_AT(row,g[18])=gl_canon(value);
        js_range(trace,g,base*32,value);
    } else {
        uint block=g[11]+item-inputs-outputs-2;if(block>=g[12])return;
        js_permutation(trace,g,block,s,rci,rcp,rcf,diag);
    }
}
__kernel void device_htlc_columns(__global const ulong *w,__global const ulong *g,__global ulong *trace) {
    uint row=get_global_id(0);if(row>=g[0])return;
    uint stride=24+5*g[4],out_start=g[2]*stride,global_start=out_start+11*g[3];ulong value=0;
    for(uint i=0;i<g[2];++i)if(row>(i*g[7]+1)*32)value=gl_add(value,w[i*stride+4]);
    for(uint j=0;j<g[3];++j)if(row>(g[2]*g[7]+j*g[8])*32)value=gl_sub(value,w[out_start+j*11+5]);
    uint fee=(g[2]*g[7]+g[3]*g[8])*32,mint=fee+g[9]*32;
    if(row>fee)value=gl_sub(value,w[global_start]);if(row>mint)value=gl_add(value,w[global_start+1]);
    JS_AT(row,g[20])=gl_canon(value);JS_AT(row,g[23])=w[3];
    if(row>=g[40]&&row<=g[40]+g[5]) {
        ulong rem=w[global_start+6]>>(row-g[40]);JS_AT(row,g[21])=gl_canon(rem);
        if(row<g[40]+g[5])JS_AT(row,g[22])=rem&1;
    }
}
__kernel void device_htlc_public(__global const ulong *w,__global const ulong *g,
    __global const ulong *trace,__global ulong *public_values,__global ulong *status) {
    uint stride=24+5*g[4],out_start=g[2]*stride,global_start=out_start+11*g[3];
    ulong in_lo=0,in_hi=0,out_lo=0,out_hi=0,code=0,bound=1UL<<g[5],height=w[global_start+6];
    uint root_row=(2+g[4])*32+31,tail=4+4*g[2]+4*g[3];ulong hashlock[4];
    for(uint k=0;k<4;++k){public_values[k]=JS_AT(root_row,k);hashlock[k]=0;}
    for(uint i=0;i<g[2];++i)if(w[i*stride+9]==g[39]&&w[i*stride+10]==1) {
        for(uint k=0;k<4;++k)hashlock[k]=w[i*stride+19+k];break;
    }
    for(uint i=0;i<g[2];++i) {
        __global const ulong *v=w+i*stride;uint base=i*g[7],root=(base+2+g[4])*32+31,nf=(base+3+g[4])*32+31;
        if(v[3]!=w[3])code|=1;if(v[4]>=bound||v[23]>=bound)code|=8;js_add_wide(v[4],&in_lo,&in_hi);
        if(v[9]>1||v[10]>1)code|=16;
        for(uint k=0;k<4;++k){if(JS_AT(root,k)!=public_values[k])code|=2;public_values[4+4*i+k]=JS_AT(nf,k);}
        if(v[9]==g[39]) {
            uint party=v[10]==1?11:15;
            for(uint k=0;k<4;++k)if(JS_AT(base*32+31,k)!=v[party+k])code|=32;
            if(v[10]==1) {
                if(height>=v[23])code|=64;
                ulong nonzero=0;for(uint k=0;k<4;++k){nonzero|=hashlock[k];if(v[19+k]!=hashlock[k])code|=128;}
                if(!nonzero)code|=128;
            } else if(height<v[23])code|=64;
        }
    }
    for(uint j=0;j<g[3];++j) {
        __global const ulong *v=w+out_start+11*j;uint row=(g[2]*g[7]+j*g[8]+1)*32+31;
        if(v[4]!=w[3])code|=1;if(v[5]>=bound)code|=8;js_add_wide(v[5],&out_lo,&out_hi);
        for(uint k=0;k<4;++k)public_values[4+4*g[2]+4*j+k]=JS_AT(row,k);
    }
    if(w[global_start]>=bound||height>=bound)code|=8;if(w[global_start+1]!=0)code|=256;
    js_add_wide(w[global_start+1],&in_lo,&in_hi);js_add_wide(w[global_start],&out_lo,&out_hi);
    if(in_lo!=out_lo||in_hi!=out_hi)code|=4;
    for(uint j=0;j<7;++j)public_values[tail+j]=gl_canon(w[global_start+j]);
    for(uint k=0;k<4;++k)public_values[tail+7+k]=hashlock[k];status[0]=code;
}
#undef JS_AT
"#;
