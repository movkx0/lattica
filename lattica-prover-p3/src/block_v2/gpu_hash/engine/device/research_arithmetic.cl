// Native MatRiCT arithmetic trace generation. Only raw inputs and immutable
// schedules are uploaded. Every trace/public commitment is computed here.
#define PQ_CONSTANTS __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag
#define PQ_ROUNDS rci,rcp,rcf,diag
#define PQ_G 32
inline ulong pq_abs(ulong word) { return (word >> 63) ? 0ul-word : word; }
inline ulong pq_signed(ulong word) { return (word >> 63) ? gl_canon(gl_sub(0,pq_abs(word))) : word; }
inline void pq_range(__global ulong *row,uint start,uint bits,ulong upper,ulong value) {
    row[start]=value;
    for(uint bit=0;bit<bits;++bit) row[start+1+bit]=(value>>bit)&1ul;
    uint equal=1;
    for(uint n=0;n<bits/4;++n) {
        uint shift=4*(bits/4-1-n);
        equal &= ((value>>shift)&15ul)==((upper>>shift)&15ul);
        row[start+1+bits+n]=equal;
    }
}
inline void pq_indices(__global ulong *row,uint bits,uint prefix,uint a,uint b) {
    for(uint j=0;j<8;++j) {row[bits+j]=(a>>j)&1u;row[bits+8+j]=(b>>j)&1u;}
    row[prefix+(a&15)]=1;row[prefix+16+(a>>4)]=1;
    row[prefix+32+(b&15)]=1;row[prefix+48+(b>>4)]=1;
}
inline void pq_initial(ulong acc[4],ulong domain,ulong q) {acc[0]=domain;acc[1]=q;acc[2]=256;acc[3]=0;}
inline void pq_pose_input(__global ulong *row,uint pose,ulong acc[4],ulong message[4]) {
    for(uint j=0;j<4;++j) {row[pose+j]=gl_canon(acc[j]);row[pose+4+j]=gl_canon(message[j]);}
}
inline void pq_absorb(ulong acc[4],ulong message[4],PQ_CONSTANTS) {
    ulong s[8];for(uint j=0;j<4;++j){s[j]=acc[j];s[4+j]=message[j];}
    pq_poseidon_permute(s,PQ_ROUNDS);for(uint j=0;j<4;++j)acc[j]=s[j];
}

__kernel void pq_arithmetic_affine(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    uint poly=get_global_id(0);if(poly>=g[4])return;
    uint width=g[2],pose=g[3],kind=g[11];ulong q=g[5];
    __global const ulong *a=w+(ulong)poly*256*(kind==3?1:2);__global const ulong *b=a+256;
    for(uint i=0;i<256;++i)if(kind==3?pq_abs(a[i])>g[12]:(a[i]>=q||b[i]>=q)){status[poly]=1;return;}
    ulong acc[3][4];for(uint k=0;k<3;++k)pq_initial(acc[k],k==0&&kind==3?g[17]:g[16],k==0&&kind==3?0:q);
    for(uint local_row=0;local_row<512;++local_row) {
        __global ulong *row=trace+((ulong)poly*512+local_row)*width;
        uint phase=local_row%4,chunk=local_row/4;ulong message[4]={0,0,0,0};
        for(uint lane=0;lane<4;++lane) {
            ulong canonical=0,mag=0;
            if(local_row<256) {
                uint i=4*chunk+lane;ulong sign=kind==3?(a[i]>>63):0;
                ulong av=kind==3?pq_signed(a[i]):a[i],bv=kind==3?0:b[i];
                ulong result=kind==1?(av+bv)%q:kind==2?(av+q-bv)%q:sign?(q-pq_abs(a[i]))%q:a[i];
                row[lane]=av;row[4+lane]=bv;row[8+lane]=sign;
                canonical=phase==2?result:kind!=3&&phase<2?(phase==0?av:bv):0;
                if(kind==3)mag=phase==0?pq_abs(a[i]):0;
                else if(phase==2)row[12+lane]=kind==1?(av+bv>=q):(av<bv);
                message[lane]=phase==0?av:phase==1?bv:result;
            }
            pq_range(row,g[7]+lane*g[8],g[6],q-1,canonical);
            if(kind==3)pq_range(row,g[14]+lane*g[15],g[13],g[12],mag);
        }
        for(uint k=0;k<3;++k)for(uint j=0;j<4;++j)row[16+4*k+j]=acc[k][j];
        if(local_row<256&&phase<3&&!(kind==3&&phase==1)) {
            pq_pose_input(row,pose,acc[phase],message);pq_absorb(acc[phase],message,PQ_ROUNDS);
        }
    }
    for(uint k=0;k<3;++k)for(uint j=0;j<4;++j)roots[(ulong)poly*12+4*k+j]=acc[k][j];
}
__kernel void pq_arithmetic_affine_bundle(__global const ulong *g,__global ulong *trace,__global ulong *roots,PQ_CONSTANTS) {
    ulong s[8]={g[18],g[11],g[5],g[4],g[12],256,0,0};pq_poseidon_permute(s,PQ_ROUNDS);
    ulong bundle[4];for(uint j=0;j<4;++j)bundle[j]=s[j];
    for(uint poly=0;poly<g[4];++poly)for(uint local_row=0;local_row<512;++local_row) {
        __global ulong *row=trace+((ulong)poly*512+local_row)*g[2];
        for(uint j=0;j<4;++j)row[28+j]=bundle[j];
        if(local_row>=256&&local_row<=258&&!(g[11]==3&&local_row==257)) {
            ulong message[4];for(uint j=0;j<4;++j)message[j]=roots[(ulong)poly*12+4*(local_row-256)+j];
            pq_pose_input(row,g[3],bundle,message);pq_absorb(bundle,message,PQ_ROUNDS);
        }
    }
    for(uint j=0;j<4;++j)roots[j]=bundle[j];
}

__kernel void pq_arithmetic_mul(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    uint poly=get_global_id(0);if(poly>=g[4])return;
    __global const ulong *a=w+(ulong)poly*512,*b=a+256;ulong q=g[5];
    for(uint i=0;i<256;++i)if(a[i]>=q||b[i]>=q){status[poly]=1;return;}
    ulong acc[3][4];for(uint k=0;k<3;++k)pq_initial(acc[k],g[16],q);
    for(uint block=0;block<64;++block) {
        ulong state[4]={0,0,0,0};
        for(uint local_row=0;local_row<19;++local_row) {
            __global ulong *row=trace+((ulong)poly*1216+block*19+local_row)*g[2];
            for(uint j=0;j<4;++j){row[j]=a[4*block+j];row[4+j]=b[4*block+j];row[8+j]=state[j];}
            ulong ranges[5]={0,0,0,0,0};uint which=local_row==0?0:local_row==1?1:local_row==18?2:3;
            if(which<3)for(uint j=0;j<4;++j)ranges[j]=which==0?a[4*block+j]:which==1?b[4*block+j]:state[j];
            else {
                uint term=local_row-2,i=term/4,j=term%4,target=(i+j)%4;ulong av=a[4*block+i],bv=b[4*block+j];
                ulong factor=g[PQ_G+2*(block*16+term)],negative=g[PQ_G+2*(block*16+term)+1];
                ulong first=av*bv;ranges[0]=first%q;ranges[1]=first/q;
                ulong second=ranges[0]*factor;ranges[2]=second%q;ranges[3]=second/q;
                ulong sum=negative?state[target]+q-ranges[2]:state[target]+ranges[2];ranges[4]=sum%q;
                row[g[10]]=sum/q;row[12]=av;row[13]=bv;row[14]=state[target];state[target]=ranges[4];
            }
            for(uint k=0;k<5;++k)pq_range(row,g[7]+k*g[8],g[6],q-1,ranges[k]);
            for(uint k=0;k<3;++k)for(uint j=0;j<4;++j)row[g[9]+4*k+j]=acc[k][j];
            if(which<3){ulong message[4];for(uint j=0;j<4;++j)message[j]=ranges[j];pq_pose_input(row,g[3],acc[which],message);pq_absorb(acc[which],message,PQ_ROUNDS);}
        }
    }
    for(uint k=0;k<3;++k)for(uint j=0;j<4;++j)roots[(ulong)poly*12+4*k+j]=acc[k][j];
}

__kernel void pq_arithmetic_permutation(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    ulong q=g[5];uint canonical=g[11]==1;
    for(uint i=0;i<256;++i)if(canonical?w[i]>=q:pq_abs(w[i])>1){status[0]=1;return;}
    ulong acc[2][4];for(uint k=0;k<2;++k)pq_initial(acc[k],canonical?g[16]:g[17],canonical?q:0);
    for(uint r=0;r<256;++r) {
        __global ulong *row=trace+(ulong)r*g[2];
        for(uint i=0;i<256;++i)row[i]=canonical?w[i]:pq_signed(w[i]);
        for(uint k=0;k<2;++k)for(uint j=0;j<4;++j)row[264+4*k+j]=acc[k][j];
        ulong message[4]={0,0,0,0};uint which=r/64;
        for(uint lane=0;lane<4;++lane) {
            ulong magnitude=0,negative=0,quotient=0;
            if(r<128) {
                uint target=4*(r%64)+lane,source=which==0?target:g[PQ_G+target];
                ulong value=canonical?w[source]:pq_signed(w[source]);row[256+lane]=value;
                ulong factor=which==0?1:g[PQ_G+256+target];
                if(canonical){ulong product=w[source]*factor;magnitude=product%q;quotient=which==1?product/q:0;message[lane]=magnitude;}
                else {message[lane]=gl_canon(gl_mul(value,factor));negative=message[lane]>1;magnitude=negative?GP-message[lane]:message[lane];}
                row[260+lane]=negative;
            }
            pq_range(row,g[7]+lane*g[8],g[6],q-1,magnitude);
            if(canonical)pq_range(row,g[14]+lane*g[8],g[6],q-1,quotient);
        }
        if(r<128){pq_pose_input(row,g[3],acc[which],message);pq_absorb(acc[which],message,PQ_ROUNDS);}
    }
    for(uint k=0;k<2;++k)for(uint j=0;j<4;++j)roots[4*k+j]=acc[k][j];
}

__kernel void pq_arithmetic_linear_map(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    uint inputs=g[20],stride=g[21],canonical=g[11]==1;ulong q=g[5];
    __global const ulong *kinds=g+PQ_G,*coeff=kinds+2*(inputs+1),*constant_words=coeff+256*inputs;
    for(uint input=0;input<inputs;++input)for(uint j=0;j<256;++j)
        if(canonical?w[input*256+j]>=q:pq_abs(w[input*256+j])>kinds[2*input+1]){status[0]=1;return;}
    ulong output[256],quotients[256];
    for(uint j=0;j<256;++j) {
        ulong positive=(constant_words[j]>>63)?0:constant_words[j],negative=(constant_words[j]>>63)?pq_abs(constant_words[j]):0;
        for(uint input=0;input<inputs;++input) {
            ulong c=coeff[256*input+j],v=w[256*input+j];uint sign=(c>>63)^(canonical?0:(v>>63));
            ulong product=pq_abs(c)*(canonical?v:pq_abs(v));if(sign)negative+=product;else positive+=product;
        }
        uint neg=negative>positive;ulong mag=neg?negative-positive:positive-negative;
        if(canonical) {
            ulong residue=mag%q;output[j]=neg&&residue?q-residue:residue;
            ulong quotient=mag/q+(neg&&residue?1:0);
            if(quotient>g[12]){status[0]=2;return;}
            quotients[j]=neg?g[12]-quotient:g[12]+quotient;
        } else {
            if(mag>kinds[2*inputs+1]){status[0]=2;return;}
            output[j]=neg?gl_canon(gl_sub(0,mag)):mag;quotients[j]=0;
        }
    }
    ulong acc[17][4];for(uint k=0;k<=inputs;++k)pq_initial(acc[k],canonical?g[16]:g[17],canonical?q:0);
    for(uint chunk=0;chunk<64;++chunk)for(uint phase=0;phase<stride;++phase) {
        __global ulong *row=trace+(ulong)(chunk*stride+phase)*g[2];ulong message[4]={0,0,0,0};
        for(uint input=0;input<inputs;++input)for(uint lane=0;lane<4;++lane)row[4*input+lane]=canonical?w[input*256+4*chunk+lane]:pq_signed(w[input*256+4*chunk+lane]);
        for(uint k=0;k<=inputs;++k)for(uint j=0;j<4;++j)row[g[9]+4*k+j]=acc[k][j];
        for(uint lane=0;lane<4;++lane) {
            uint j=4*chunk+lane;ulong current=phase<inputs?(canonical?w[phase*256+j]:pq_signed(w[phase*256+j])):phase==inputs?output[j]:0;
            ulong bound=phase<=inputs?kinds[2*phase+1]:0;
            ulong encoded=canonical?current:gl_canon(gl_add(current,bound));
            pq_range(row,g[7]+lane*g[8],g[6],canonical?q-1:2*bound,encoded);
            if(canonical)pq_range(row,g[14]+lane*g[15],g[13],2*g[12],phase==inputs?quotients[j]:0);
            message[lane]=current;
        }
        if(phase<=inputs){pq_pose_input(row,g[3],acc[phase],message);pq_absorb(acc[phase],message,PQ_ROUNDS);}
    }
    for(uint k=0;k<=inputs;++k)for(uint j=0;j<4;++j)roots[4*k+j]=acc[k][j];
}

__kernel void pq_arithmetic_ntt(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    uint poly=get_global_id(0);if(poly>=g[4])return;ulong q=g[5];
    ulong state[256];for(uint i=0;i<256;++i){state[i]=w[(ulong)poly*256+i];if(state[i]>=q){status[poly]=1;return;}}
    ulong acc[4];pq_initial(acc,g[16],q);
    for(uint local_row=0;local_row<896;++local_row) {
        __global ulong *row=trace+((ulong)poly*896+local_row)*g[2];
        for(uint i=0;i<256;++i)row[i]=state[i];
        ulong ranges[6]={0,0,0,0,0,0},reads[4]={0,0,0,0};uint a=0,b=0,hash=local_row<64||local_row>=832;
        if(hash) {
            uint group=local_row<64?local_row:g[PQ_G+768*4+local_row-832];a=4*group;
            for(uint j=0;j<4;++j){reads[j]=state[a+j];ranges[j]=reads[j];}
        } else {
            __global const ulong *step=g+PQ_G+4*(local_row-64);a=step[0];b=step[1];reads[0]=state[a];reads[1]=state[b];
            ulong u=reads[0]*step[2],v=reads[1]*step[3];ranges[0]=u%q;ranges[1]=v%q;ranges[2]=u/q;ranges[3]=v/q;
            ulong add=ranges[0]+ranges[1],sub=ranges[0]+q-ranges[1];ranges[4]=add%q;ranges[5]=sub%q;
            row[g[10]]=add/q;row[g[10]+1]=sub/q;state[a]=ranges[4];state[b]=ranges[5];
        }
        for(uint k=0;k<6;++k)pq_range(row,g[7]+k*g[8],g[6],q-1,ranges[k]);
        pq_indices(row,256,272,a,b);for(uint j=0;j<4;++j){row[336+j]=reads[j];row[g[9]+j]=acc[j];}
        ulong message[4];for(uint j=0;j<4;++j)message[j]=hash?reads[j]:0;
        pq_pose_input(row,g[3],acc,message);if(hash)pq_absorb(acc,message,PQ_ROUNDS);
        if(local_row==63){for(uint j=0;j<4;++j)roots[(ulong)poly*8+j]=acc[j];pq_initial(acc,g[16],q);}
    }
    for(uint j=0;j<4;++j)roots[(ulong)poly*8+4+j]=acc[j];
}

__kernel void pq_arithmetic_g_bound(__global const ulong *w,__global const ulong *g,
    __global ulong *trace,__global ulong *roots,__global ulong *status,PQ_CONSTANTS) {
    ulong left[256],right[256];
    for(uint i=0;i<256;++i){if(pq_abs(w[i])>g[12]||pq_abs(w[256+i])>1){status[0]=1;return;}
        left[i]=pq_signed(w[i]);right[i]=pq_signed(w[256+i]);}
    __global const ulong *schedule=g+PQ_G;ulong acc[4];pq_initial(acc,g[17],0);
    for(uint index=0;index<4096;++index) {
        uint phase=index/128,r=index%128,a=0,b=0;__global ulong *row=trace+(ulong)index*g[2];
        for(uint i=0;i<256;++i){row[i]=left[i];row[256+i]=right[i];}
        row[720+phase]=1;for(uint j=0;j<4;++j)row[752+j]=acc[j];
        if(phase==0)a=4*(r%64);
        else if(phase==1||phase==11||phase==21)a=r;
        else if(phase==2||phase==12||phase==22)a=r+128;
        else if(phase>=3&&phase<=10){a=schedule[(phase-3)*128+r];b=schedule[(8+phase-3)*128+r];}
        else if(phase>=13&&phase<=20){a=schedule[(20-phase)*128+r];b=schedule[(8+20-phase)*128+r];}
        else if(phase==23&&r<64)a=4*r;
        pq_indices(row,512,528,a,b);row[592]=left[a];row[593]=left[b];row[594]=right[a];row[595]=right[b];
        ulong values[4]={0,0,0,0},bound=0;
        if(phase==0){bound=r<64?g[12]:1;for(uint j=0;j<4;++j)values[j]=r<64?left[a+j]:right[a+j];}
        else if(phase==23&&r<64){bound=g[13];for(uint j=0;j<4;++j)values[j]=left[a+j];}
        for(uint j=0;j<4;++j){ulong encoded=gl_canon(gl_add(values[j],bound));
            if(encoded>2*bound||encoded>=(1ul<<24)){status[0]=2;return;}
            pq_range(row,596+j*31,24,2*bound,encoded);}
        ulong message[4];for(uint j=0;j<4;++j)message[j]=phase==0?values[j]:0;
        pq_pose_input(row,756,acc,message);
        if(phase==0){pq_absorb(acc,message,PQ_ROUNDS);if(r==63){for(uint j=0;j<4;++j)roots[j]=acc[j];pq_initial(acc,g[17],0);}if(r==127)for(uint j=0;j<4;++j)roots[4+j]=acc[j];}
        if(phase==1||phase==2){ulong factor=schedule[32*128+r];if(phase==2)factor=gl_mul(factor,g[20]);
            right[a]=gl_canon(gl_mul(gl_sub(right[a],left[a]),factor));left[a]=gl_canon(gl_mul(left[a],factor));}
        else if(phase>=3&&phase<=10){ulong factor=schedule[(16+phase-3)*128+r];ulong u=left[a],v=left[b];
            left[a]=gl_canon(gl_add(u,v));left[b]=gl_canon(gl_mul(gl_sub(u,v),factor));u=right[a];v=right[b];
            right[a]=gl_canon(gl_add(u,v));right[b]=gl_canon(gl_mul(gl_sub(u,v),factor));}
        else if(phase==11||phase==12)left[a]=gl_canon(gl_mul(left[a],right[a]));
        else if(phase>=13&&phase<=20){ulong factor=schedule[(24+20-phase)*128+r],u=left[a],v=gl_mul(left[b],factor);
            left[a]=gl_canon(gl_add(u,v));left[b]=gl_canon(gl_sub(u,v));}
        else if(phase==21||phase==22){ulong factor=schedule[33*128+r];if(phase==22)factor=gl_mul(factor,g[21]);left[a]=gl_canon(gl_mul(left[a],factor));}
    }
}

__kernel void pq_arithmetic_padding(__global const ulong *g,__global ulong *trace,__global const ulong *roots) {
    uint r=get_global_id(0),family=g[0],count=g[4];uint active=count*(family==2?896:1216);
    if((family!=2&&family!=3)||r<active||r>=g[1])return;__global ulong *row=trace+(ulong)r*g[2];
    uint ranges=family==2?6:5;for(uint k=0;k<ranges;++k)pq_range(row,g[7]+k*g[8],g[6],g[5]-1,0);
    if(family==2){pq_indices(row,256,272,0,0);for(uint j=0;j<4;++j){ulong value=roots[(ulong)(count-1)*8+4+j];row[g[9]+j]=value;row[g[3]+j]=value;}}
    else for(uint j=0;j<12;++j)row[g[9]+j]=roots[(ulong)(count-1)*12+j];
}
__kernel void pq_arithmetic_public(__global const ulong *roots,__global ulong *public_values,uint words) {
    uint i=get_global_id(0);if(i<words)public_values[i]=gl_canon(roots[i]);
}
#undef PQ_CONSTANTS
#undef PQ_ROUNDS
#undef PQ_G
