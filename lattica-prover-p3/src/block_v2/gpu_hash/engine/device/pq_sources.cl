// GPU witness traces for statement/private-proof/transcript AIRs. Geometry is
// validated by typed Rust entry points; input contains raw words, never a trace.
#define PQS_Q 167770241UL
#define PQS_QHAT 3489661057UL
#define PQS_POLY 0x504f4c595f505131UL
#define PQS_SIGNED 0x5349474e50513031UL
#define PQS_RC __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag
#define PQS_PASS rci,rcp,rcf,diag
inline ulong pqs_inv(ulong x) {
    if (!x) return 0;
    ulong result=1, power=x, exponent=0xfffffffeffffffffUL;
    while (exponent) { if (exponent&1) result=gl_mul(result,power); power=gl_mul(power,power); exponent>>=1; }
    return gl_canon(result);
}
// Montgomery batch inversion: one exponentiation per <=16 hints. Zero
// witnesses remain zero; all nonzero inverses are exactly the scalar result.
// Fixed local storage avoids event-count-dependent private allocation/spills.
inline void pqs_invert_columns(__global ulong *columns, uint count) {
    for(uint first=0;first<count;first+=16) {
        uint n=min((uint)16,count-first);ulong prefix[16],values[16],product=1;
        for(uint i=0;i<n;i++){values[i]=gl_canon(columns[first+i]);prefix[i]=product;if(values[i])product=gl_mul(product,values[i]);}
        ulong inverse=pqs_inv(product);
        for(uint left=n;left>0;left--){uint i=left-1;columns[first+i]=values[i]?gl_canon(gl_mul(inverse,prefix[i])):0;if(values[i])inverse=gl_mul(inverse,values[i]);}
    }
}
inline void pqs_copy(__global ulong *dst, ulong a[4]) { for(uint j=0;j<4;j++) dst[j]=a[j]; }
inline void pqs_absorb(__global ulong *dst, ulong state[4], ulong chunk[4], uint retain, PQS_RC) {
    ulong s[8];
    for(uint j=0;j<4;j++) { dst[j]=s[j]=state[j]; dst[4+j]=s[4+j]=chunk[j]; }
    if(retain) { pq_poseidon_permute(s,PQS_PASS); for(uint j=0;j<4;j++) state[j]=s[j]; }
}
inline void pqs_absorb_only(ulong state[4], ulong chunk[4], PQS_RC) {
    ulong s[8]; for(uint j=0;j<4;j++) {s[j]=state[j];s[4+j]=chunk[j];}
    pq_poseidon_permute(s,PQS_PASS);for(uint j=0;j<4;j++)state[j]=s[j];
}
inline uint pqs_class(uint p) {
    if(p<=6)return 0;if(p<=11)return 1;if(p==12)return 2;
    if(p<=61 || (p>=73 && p<=82))return 3;if(p<=72)return 4;return 5;
}
inline ulong pqs_offset(uint k) { return k==2?1:k==3?38346:k==4?565:k==5?6212586:0; }
inline ulong pqs_max(uint k) { return k==0?PQS_Q-1:k==1?PQS_QHAT-1:k==2?2:k==3?76692:k==4?1130:k==5?12425172:k==6?0xffffffffUL:0; }
inline void pqs_poly_init(ulong s[4],uint k) {s[0]=k<2?PQS_POLY:PQS_SIGNED;s[1]=k==0?PQS_Q:k==1?PQS_QHAT:0;s[2]=256;s[3]=0;}
inline void pqs_bits(__global ulong *d,uint bits,uint prefix,ulong value,ulong maximum,uint n) {
    for(uint b=0;b<n;b++) d[bits+b]=(value>>b)&1;
    uint equal=1;
    for(uint b=0;b<n/4;b++){uint shift=n-4-4*b;equal&=((value>>shift)&15)==((maximum>>shift)&15);d[prefix+b]=equal;}
}
// family 0: statement (fixed 202848-byte packet); 1: private proof; 2: transcript.
__kernel void pq_source_chain(__global const ulong *in,__global const ulong *g,
    __global ulong *trace,__global ulong *endpoints,__global ulong *status,PQS_RC) {
    if(get_global_id(0))return;
    uint family=g[0],width=g[1],rows=g[2];ulong zero[4]={0,0,0,0};status[0]=0;
    if(family==0) {
        const uint fields=50713,active=12679,lastpoly=12674;
        ulong acc[4]={0x4d52514353544d31UL,fields,0,0},poly[4]={PQS_POLY,PQS_Q,256,0};
        ulong bundle[4]={0x53544d54504f4c31UL,PQS_Q,256,198},prior[4]={0},older[4]={0},diffs=0;
        for(uint r=0;r<2;r++){ulong seed[4];for(uint j=0;j<4;j++)seed[j]=g[4+4*r+j];pqs_absorb_only(bundle,seed,PQS_PASS);}
        for(uint r=0;r<rows;r++) {
            __global ulong *d=trace+(ulong)r*width;ulong words[4],shifted[4];
            for(uint j=0;j<4;j++)words[j]=4*r+j<fields?in[4*r+j]:0;
            pqs_copy(d,words);pqs_copy(d+164,acc);pqs_copy(d+168,prior);pqs_copy(d+172,older);d[184]=diffs;
            pqs_copy(d+206,poly);pqs_copy(d+210,bundle);
            for(uint j=0;j<3;j++)shifted[j]=prior[j+1];shifted[3]=words[0];
            uint pa=r>=3 && r<=lastpoly,serial=r>lastpoly && r<active;
            ulong updated[4];for(uint j=0;j<4;j++)updated[j]=poly[j];
            if(pa && r%64==3){updated[0]=PQS_POLY;updated[1]=PQS_Q;updated[2]=256;updated[3]=0;}
            pqs_absorb(d+308,updated,shifted,pa,PQS_PASS);
            if(pa)for(uint j=0;j<4;j++)poly[j]=updated[j];
            uint end=pa && r%64==2;
            pqs_absorb(d+402,bundle,end?updated:serial?shifted:zero,end||serial,PQS_PASS);
            for(uint j=0;j<4;j++) if(4*r+j>=fields-8 && 4*r+j<fields && words[j]!=older[j])diffs++;
            d[185]=diffs; // inverse is produced by the row-parallel hints kernel.
            pqs_absorb(d+214,acc,words,r<active,PQS_PASS);
            for(uint j=0;j<4;j++){older[j]=prior[j];prior[j]=words[j];}
        }
        pqs_copy(endpoints,acc);pqs_copy(endpoints+4,bundle);
    } else if(family==1) {
        ulong poly[4];pqs_poly_init(poly,0);ulong bundle[4]={0x50524f4f46505131UL,91,8,1},norm=0;
        const uint starts[6]={13,22,31,40,51,83},ends[6]={22,31,40,51,62,91};
        for(uint r=0;r<rows;r++) {
            __global ulong *d=trace+(ulong)r*width;uint p=r/64,k=r<5824?pqs_class(p):r<5826?6:7;
            ulong words[4],coeff[4];for(uint j=0;j<4;j++){words[j]=r<5826?in[4*r+j]:0;coeff[j]=gl_sub(words[j],pqs_offset(k));}
            pqs_copy(d,words);pqs_copy(d+164,poly);pqs_copy(d+168,bundle);d[172]=gl_canon(norm);
            ulong updated[4];for(uint j=0;j<4;j++)updated[j]=poly[j];if(r<5824 && r%64==0)pqs_poly_init(updated,k);
            pqs_absorb(d+248,updated,coeff,r<5824,PQS_PASS);if(r<5824)for(uint j=0;j<4;j++)poly[j]=updated[j];
            uint end=r<5824 && r%64==63;
            pqs_absorb(d+342,bundle,end?updated:k==6?coeff:zero,end||k==6,PQS_PASS);
            uint active=0,reset=0,limit=3;
            for(uint n=0;n<6;n++){active|=p>=starts[n] && p<ends[n];reset|=p==starts[n];if(p+1==ends[n] && r%64==63)limit=n<3?0:n<5?1:2;}
            if(reset && r%64==0)norm=0;
            if(active)for(uint j=0;j<4;j++){long v=(long)words[j]-(long)pqs_offset(k);ulong mag=v<0?(ulong)(-v):(ulong)v;ulong sq=mag*mag;if(norm>~0UL-sq)status[0]=1;norm+=sq;}
            d[173]=limit<3?norm:0; // unexpanded norm hint, consumed by row-parallel kernel.
        }
        pqs_copy(endpoints,bundle);
    } else {
        uint parts=g[4],events=g[5],class_col=85+2*events,source_col=class_col+4,byte_col=source_col+4,bundle_col=byte_col+4,pose=bundle_col+4;
        uint kind0=g[8];ulong source[4]={kind0==0?0x4259544550513332UL:PQS_POLY,kind0==0?32:kind0==1?PQS_Q:PQS_QHAT,kind0==0?0:256,0};
        ulong bytes[4]={0x5348414b455f494eUL,g[6],0,0},bundle[4]={0x5452414e53505131UL,parts,g[6],1},buffer[2]={0};
        for(uint r=0;r<rows;r++) {
            uint p=r/128,l=r%128,k=p<parts?g[8+p]:3,active=k<3 && (k!=0 || l<4);
            __global ulong *d=trace+(ulong)r*width;ulong pair[2];for(uint j=0;j<2;j++)pair[j]=active?in[256*p+2*l+j]:0;
            d[0]=pair[0];d[1]=pair[1];d[82]=buffer[0];d[83]=buffer[1];
            pqs_copy(d+source_col,source);pqs_copy(d+byte_col,bytes);pqs_copy(d+bundle_col,bundle);
            ulong limbs[4]={pair[0]&65535,pair[0]>>16,pair[1]&65535,pair[1]>>16};
            if(l==0){source[0]=k==0?0x4259544550513332UL:k<3?PQS_POLY:0;source[1]=k==0?32:k==1?PQS_Q:k==2?PQS_QHAT:0;source[2]=k==1||k==2?256:0;source[3]=0;}
            uint hash=k<3 && (k==0?l<4:l%2==1);
            ulong chunk[4]={buffer[0],buffer[1],pair[0],pair[1]};
            pqs_absorb(d+pose,source,k==0 && l<4?limbs:hash?chunk:zero,hash,PQS_PASS);
            pqs_absorb(d+pose+94,bytes,active?limbs:zero,active,PQS_PASS);
            ulong metadata[4]={k+1,k==0?32:1024,p,0};
            pqs_absorb(d+pose+188,bundle,l==0 && k<3?metadata:l==127 && k<3?source:zero,k<3 && (l==0||l==127),PQS_PASS);
            buffer[0]=l%2==0?pair[0]:0;buffer[1]=l%2==0?pair[1]:0;
        }
        pqs_copy(endpoints,bundle);pqs_copy(endpoints+4,bytes);
    }
}
__kernel void pq_source_hints(__global const ulong *g,__global ulong *trace) {
    uint r=get_global_id(0),family=g[0],width=g[1];if(r>=g[2])return;__global ulong *d=trace+(ulong)r*width;
    if(family==0) {
        const uint selected[8]={0,1,2,12673,12674,12676,12677,12678};
        d[186]=r;for(uint i=0;i<8;i++){d[187+i]=r==selected[i];d[195+i]=gl_sub(r,selected[i]);}
        d[203]=r<12679;d[204]=r>=3 && r<=12673;d[205]=r>12674 && r<12679;
        for(uint j=0;j<4;j++){pqs_bits(d,4+32*j,132+8*j,d[j],PQS_Q-1,32);ulong delta=gl_canon(gl_sub(d[j],d[172+j]));d[176+j]=delta==0;d[180+j]=delta;}
        pqs_invert_columns(d+195,8);pqs_invert_columns(d+180,4);d[185]=pqs_inv(d[185]);
    } else if(family==1) {
        uint p=r/64,k=r<5824?pqs_class(p):r<5826?6:7;const uint ev[12]={6,11,12,21,30,39,50,61,72,82,90,91};
        d[436]=p;for(uint i=0;i<12;i++){d[437+i]=p==ev[i];d[449+i]=gl_sub(p,ev[i]);}pqs_invert_columns(d+449,12);if(k<6)d[461+k]=1;
        const uint starts[6]={13,22,31,40,51,83},ends[6]={22,31,40,51,62,91};uint active=0,reset=0,limit=3;
        for(uint n=0;n<6;n++){active|=p>=starts[n] && p<ends[n];reset|=p==starts[n];if(p+1==ends[n] && r%64==63)limit=n<3?0:n<5?1:2;}
        d[467]=active;d[468]=reset;for(uint j=0;j<4;j++)pqs_bits(d,4+32*j,132+8*j,d[j],pqs_max(k),32);
        const ulong limits[3]={135519727172UL,165635222099UL,3161803581581766UL};ulong check=d[173];
        pqs_bits(d,173,233,check,limit<3?limits[limit]:0,60);if(limit==3)for(uint i=0;i<15;i++)d[233+i]=0;
    } else {
        uint p=r/128,l=r%128,events=g[5],k=p<g[4]?g[8+p]:3;d[84]=p;d[85+2*events+k]=1;
        for(uint i=0;i<events;i++){ulong at=g[8+g[4]+i];d[85+i]=p==at;d[85+events+i]=gl_sub(p,at);}
        pqs_invert_columns(d+85+events,events);
        ulong maximum=k==0 && l<4?0xffffffffUL:k==1?PQS_Q-1:k==2?PQS_QHAT-1:0;
        for(uint j=0;j<2;j++)pqs_bits(d,2+32*j,66+8*j,d[j],maximum,32);
    }
}
__kernel void pq_source_poseidon(__global const ulong *g,__global ulong *trace,PQS_RC) {
    uint r=get_global_id(0);if(r>=g[2])return;uint f=g[0],offset=f==0?214:f==1?248:101+2*g[5],count=f==1?2:3;
    for(uint i=0;i<count;i++)pq_poseidon_trace_row(trace,(uint)g[1],offset+94*i,r,PQS_PASS);
}
__kernel void pq_source_public(__global const ulong *g,__global const ulong *endpoints,__global ulong *public_values) {
    uint i=get_global_id(0);if(i<g[3])public_values[i]=endpoints[i];
}
