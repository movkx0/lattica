//! The existing join-split AIR layout, written from raw witness words on device.
pub(crate) const KERNEL_SRC: &str = r#"
#ifndef LATTICA_WALLET_FN
#define LATTICA_WALLET_FN
#endif
#define JS_AT(r,c) trace[(ulong)(r) * g[1] + (c)]
LATTICA_WALLET_FN void js_write_state(__global ulong *trace, __global const ulong *g, uint row, ulong s[8]) {
    for (uint j=0;j<8;++j) JS_AT(row,j)=gl_canon(s[j]);
}
LATTICA_WALLET_FN void js_permutation(__global ulong *trace, __global const ulong *g, uint block, ulong s[8],
    __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    uint row=block*32;
    js_write_state(trace,g,row++,s); extl(s); js_write_state(trace,g,row++,s);
    for(uint r=0;r<4;++r) {
        for(uint j=0;j<8;++j)s[j]=gl_pow7(gl_add(s[j],rci[r*8+j]));
        extl(s);js_write_state(trace,g,row++,s);
    }
    for(uint r=0;r<22;++r) {
        s[0]=gl_pow7(gl_add(s[0],rcp[r]));intl(s,diag);js_write_state(trace,g,row++,s);
    }
    for(uint r=0;r<4;++r) {
        for(uint j=0;j<8;++j)s[j]=gl_pow7(gl_add(s[j],rcf[r*8+j]));
        extl(s);js_write_state(trace,g,row++,s);
    }
}
LATTICA_WALLET_FN void js_range(__global ulong *trace,__global const ulong *g,uint row,ulong value) {
    for(uint k=0;k<=g[5];++k) {
        JS_AT(row+k,g[21])=gl_canon(value);
        if(k<g[5]){JS_AT(row+k,g[22])=value&1;value>>=1;}
    }
}
__kernel void device_joinsplit_regions(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global const ulong *rci,__global const ulong *rcp,
    __global const ulong *rcf,__global const ulong *diag) {
    uint item=get_global_id(0), inputs=g[2],outputs=g[3],depth=g[4];
    uint in_stride=9+5*depth,out_start=inputs*in_stride,global_start=out_start+10*outputs;
    ulong s[8];for(uint j=0;j<8;++j)s[j]=0;
    if(item<inputs) {
        __global const ulong *v=w+item*in_stride;
        uint base=item*g[7];ulong nk0=gl_canon(v[0]),nk1=gl_canon(v[1]),pos=0;
        s[0]=g[24];s[1]=nk0;s[2]=nk1;s[3]=v[2];
        js_permutation(trace,g,base,s,rci,rcp,rcf,diag);
        for(uint j=4;j>0;--j)s[j]=s[j-1];s[0]=g[25];s[5]=gl_canon(v[4]);s[6]=v[5];s[7]=v[6];
        js_permutation(trace,g,base+1,s,rci,rcp,rcf,diag);
        s[4]=v[7];s[5]=v[8];s[6]=v[3];s[7]=0;
        js_permutation(trace,g,base+2,s,rci,rcp,rcf,diag);
        for(uint d=0;d<depth;++d) {
            __global const ulong *path=v+9+5*d;ulong child[4];
            for(uint j=0;j<4;++j)child[j]=s[j];
            for(uint j=0;j<4;++j){s[j]=path[4]?path[j]:child[j];s[4+j]=path[4]?child[j]:path[j];}
            JS_AT((base+3+d)*32,g[13])=path[4];pos|=path[4]<<d;
            js_permutation(trace,g,base+3+d,s,rci,rcp,rcf,diag);
        }
        s[0]=g[26];s[1]=nk0;s[2]=nk1;s[3]=v[5];s[4]=v[6];s[5]=pos;s[6]=0;s[7]=0;
        js_permutation(trace,g,base+3+depth,s,rci,rcp,rcf,diag);
        ulong accumulator=0;
        for(uint row=base*32;row<(base+g[7])*32;++row) {
            JS_AT(row,g[14])=nk0;JS_AT(row,g[15])=nk1;JS_AT(row,g[16])=v[5];JS_AT(row,g[17])=v[6];
            JS_AT(row,g[18])=gl_canon(v[4]);JS_AT(row,g[19])=accumulator;
            for(uint d=0;d<depth;++d)if(row==(base+2+d)*32+31)accumulator+=v[9+5*d+4]<<d;
        }
        js_range(trace,g,(base+1)*32,v[4]);
    } else if(item<inputs+outputs) {
        uint j=item-inputs,base=inputs*g[7]+j*g[8];__global const ulong *v=w+out_start+10*j;
        s[0]=g[25];for(uint k=0;k<4;++k)s[1+k]=v[k];s[5]=gl_canon(v[5]);s[6]=v[6];s[7]=v[7];
        js_permutation(trace,g,base,s,rci,rcp,rcf,diag);
        s[4]=v[8];s[5]=v[9];s[6]=v[4];s[7]=0;js_permutation(trace,g,base+1,s,rci,rcp,rcf,diag);
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
__kernel void device_joinsplit_columns(__global const ulong *w,__global const ulong *g,__global ulong *trace) {
    uint row=get_global_id(0);if(row>=g[0])return;
    uint stride=9+5*g[4],out_start=g[2]*stride,global_start=out_start+10*g[3];ulong value=0;
    for(uint i=0;i<g[2];++i)if(row>(i*g[7]+1)*32)value=gl_add(value,w[i*stride+4]);
    for(uint j=0;j<g[3];++j)if(row>(g[2]*g[7]+j*g[8])*32)value=gl_sub(value,w[out_start+j*10+5]);
    uint fee=(g[2]*g[7]+g[3]*g[8])*32,mint=fee+g[9]*32;
    if(row>fee)value=gl_sub(value,w[global_start]);if(row>mint)value=gl_add(value,w[global_start+1]);
    JS_AT(row,g[20])=gl_canon(value);JS_AT(row,g[23])=w[3];
}
LATTICA_WALLET_FN void js_add_wide(ulong value,ulong *lo,ulong *hi){ulong old=*lo;*lo+=value;*hi+=*lo<old;}
__kernel void device_joinsplit_public(__global const ulong *w,__global const ulong *g,
    __global const ulong *trace,__global ulong *public_values,__global ulong *status) {
    uint stride=9+5*g[4],out_start=g[2]*stride,global_start=out_start+10*g[3];
    ulong in_lo=0,in_hi=0,out_lo=0,out_hi=0,code=0,bound=1UL<<g[5];
    uint root_row=(2+g[4])*32+31;
    for(uint k=0;k<4;++k)public_values[k]=JS_AT(root_row,k);
    for(uint i=0;i<g[2];++i) {
        __global const ulong *v=w+i*stride;uint base=i*g[7],root=(base+2+g[4])*32+31,nf=(base+3+g[4])*32+31;
        if(v[3]!=w[3])code|=1;if(v[4]>=bound)code|=8;js_add_wide(v[4],&in_lo,&in_hi);
        for(uint k=0;k<4;++k){if(JS_AT(root,k)!=public_values[k])code|=2;public_values[4+4*i+k]=JS_AT(nf,k);}
    }
    for(uint j=0;j<g[3];++j) {
        __global const ulong *v=w+out_start+10*j;uint row=(g[2]*g[7]+j*g[8]+1)*32+31;
        if(v[4]!=w[3])code|=1;if(v[5]>=bound)code|=8;js_add_wide(v[5],&out_lo,&out_hi);
        for(uint k=0;k<4;++k)public_values[4+4*g[2]+4*j+k]=JS_AT(row,k);
    }
    if(w[global_start]>=bound||w[global_start+1]>=bound)code|=8;
    js_add_wide(w[global_start+1],&in_lo,&in_hi);js_add_wide(w[global_start],&out_lo,&out_hi);
    if(in_lo!=out_lo||in_hi!=out_hi)code|=4;
    uint tail=4+4*g[2]+4*g[3];
    for(uint j=0;j<6;++j)public_values[tail+j]=gl_canon(w[global_start+j]);
    status[0]=code;
}
#undef JS_AT
"#;
