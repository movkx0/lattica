// Exact UniformAir and SparseAir state transitions; public static layout only.
// pq_poseidon.cl provides the unchanged 94-column Poseidon2 AIR layout.
#define PQ_SAMPLE_Q ((ulong)167770241)
#define PQ_SAMPLE_LIMIT ((ulong)4194256025)
#define PQ_SAMPLE_POLY ((ulong)0x504f4c595f505131UL)
#define PQ_SAMPLE_SIGNED ((ulong)0x5349474e50513031UL)
#define PQ_SAMPLE_AES ((ulong)0x4145535f4354524fUL)
#define PQ_SAMPLE_SHAKE ((ulong)0x5348414b455f4f55UL)
#define PQ_SAMPLE_BUNDLE ((ulong)0x554e494651503031UL)

inline void pq_sample_bits(__global ulong *row, uint at, uint count, ulong value) {
    for (uint i=0;i<count;++i) row[at+i]=(value>>i)&1UL;
}
inline void pq_sample_input(__global ulong *row, uint at, ulong state[4], ulong words[4]) {
    for (uint i=0;i<4;++i) { row[at+i]=state[i]; row[at+4+i]=words[i]; }
}
inline void pq_sample_absorb(ulong state[4], ulong words[4],
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    ulong s[8]; for(uint i=0;i<4;++i){s[i]=state[i];s[4+i]=words[i];}
    pq_poseidon_permute(s,rci,rcp,rcf,diag);
    for(uint i=0;i<4;++i)state[i]=s[i];
}

__kernel void pq_uniform_chain(__global const ulong *bytes, uint kind,
    __global ulong *trace, __global ulong *endpoints, __global ulong *status,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    if(get_global_id(0)!=0)return;
    uint draws=kind==0?1197:643, polynomials=kind==0?4:2, rows=kind==0?2048:1024;
    uint count=0; ulong previous[2]={0,0}, buffer[4]={0,0,0,0};
    ulong byte_acc[4]={PQ_SAMPLE_AES,4*(ulong)draws,0,0};
    ulong poly_acc[4]={PQ_SAMPLE_POLY,PQ_SAMPLE_Q,256,0};
    ulong bundle_acc[4]={PQ_SAMPLE_BUNDLE,PQ_SAMPLE_Q,draws,polynomials};
    for(uint r=0;r<rows;++r){
        __global ulong *row=trace+(ulong)r*445;
        ulong raw=0;if(r<draws)for(uint i=0;i<4;++i)raw|=bytes[4*r+i]<<(8*i);
        uint accept=raw<PQ_SAMPLE_LIMIT;
        ulong remainder=raw%PQ_SAMPLE_Q;
        row[0]=raw;row[33]=accept;row[66]=remainder;
        uint take=r<draws&&accept&&count<polynomials*256;
        uint end_four=take&&(count%4==3),end_poly=take&&(count%256==255);
        row[128]=count;
        for(uint i=0;i<4;++i){row[147+i]=buffer[i];row[151+i]=byte_acc[i];row[155+i]=poly_acc[i];row[159+i]=bundle_acc[i];}
        ulong current[2]={raw&65535UL,raw>>16};
        ulong byte_words[4]={previous[0],previous[1],current[0],current[1]};
        pq_sample_input(row,163,byte_acc,byte_words);
        if((r&1)&&r<((draws+1)/2)*2)pq_sample_absorb(byte_acc,byte_words,rci,rcp,rcf,diag);
        previous[0]=current[0];previous[1]=current[1];
        if(take)buffer[count%4]=remainder;
        pq_sample_input(row,257,poly_acc,buffer);
        // The second parallel trace pass fills the four next-poly words.
        for(uint i=0;i<4;++i)row[351+i]=bundle_acc[i];
        if(end_four){
            pq_sample_absorb(poly_acc,buffer,rci,rcp,rcf,diag);
            for(uint i=0;i<4;++i)buffer[i]=0;
        }
        if(end_poly){
            pq_sample_absorb(bundle_acc,poly_acc,rci,rcp,rcf,diag);
            poly_acc[0]=PQ_SAMPLE_POLY;poly_acc[1]=PQ_SAMPLE_Q;poly_acc[2]=256;poly_acc[3]=0;
        }
        if(take)++count;
    }
    for(uint i=0;i<4;++i){endpoints[i]=byte_acc[i];endpoints[4+i]=bundle_acc[i];}
    status[0]=(count!=polynomials*256);
}

__kernel void pq_sparse_chain(__global const ulong *bytes, uint kind,
    __global ulong *trace, __global ulong *endpoints, __global ulong *status,
    __global ulong *history,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    if(get_global_id(0)!=0)return;
    uint challenge=kind==3,input_len=challenge?137:127,sign_bytes=challenge?6:5,weight=challenge?44:39;
    // history[0..256] is activation row + 1 (zero means never accepted);
    // history[256..512] is the final signed value. Every index is accepted at
    // most once. The parallel snapshot pass reconstructs exact old row states.
    ulong buffer[8];for(uint i=0;i<8;++i)buffer[i]=0;
    uint count=0;ulong byte_acc[4]={challenge?PQ_SAMPLE_SHAKE:PQ_SAMPLE_AES,input_len,0,0};
    ulong poly_acc[4]={PQ_SAMPLE_SIGNED,0,256,0};
    for(uint r=0;r<256;++r){
        __global ulong *row=trace+(ulong)r*506;ulong raw=r<input_len?bytes[r]:0;
        row[320]=raw;pq_sample_bits(row,321,8,raw);row[329+(raw&15)]=1;row[345+(raw>>4)]=1;
        row[361]=count;pq_sample_bits(row,362,6,count);row[368+(count&15)]=1;row[384+(count>>4)]=1;
        uint has_group=challenge&&count<44,group=count<4?count:(count-4)/10;
        if(has_group)row[388+group]=1;
        uint remaining=count<weight,index=challenge?4*(raw&63)+(has_group?group:0):raw;
        ulong read=challenge&&!has_group?0:history[256+index];
        ulong sign=(count/8<sign_bytes&&r>count/8)?((bytes[count/8]>>(count%8))&1UL):0;
        row[392]=remaining;row[393]=read;row[394]=sign;
        uint take=r>=sign_bytes&&r<input_len&&remaining&&read==0;row[395]=take;
        for(uint i=0;i<8;++i)row[396+i]=buffer[i];
        for(uint i=0;i<4;++i){row[404+i]=byte_acc[i];row[408+i]=poly_acc[i];}
        buffer[r%8]=raw;
        if(r<((input_len+7)/8)*8&&(r%8)==7){
            ulong words[4];for(uint i=0;i<4;++i)words[i]=buffer[2*i]|(buffer[2*i+1]<<8);
            pq_sample_input(row,412,byte_acc,words);pq_sample_absorb(byte_acc,words,rci,rcp,rcf,diag);
            for(uint i=0;i<8;++i)buffer[i]=0;
        }else if(r>=192){
            ulong words[4];for(uint i=0;i<4;++i)words[i]=history[256+4*(r-192)+i];
            pq_sample_input(row,412,poly_acc,words);pq_sample_absorb(poly_acc,words,rci,rcp,rcf,diag);
        }
        if(take){history[index]=r+1;history[256+index]=sign?gl_sub(0UL,1UL):1UL;++count;}
    }
    for(uint i=0;i<4;++i){endpoints[i]=byte_acc[i];endpoints[4+i]=poly_acc[i];}
    status[0]=(count!=weight);
}

// Independent bit/flag columns do not belong in the serial sponge recurrence.
// Immutable raw/accept/remainder/count cells were produced by the chain kernel.
__kernel void pq_uniform_hints(uint kind,uint rows,__global ulong *trace){
    uint item=get_global_id(0),row_index=item/147,column=item%147;
    if(row_index>=rows||column==0||column==33||column==66||column==128)return;
    __global ulong *row=trace+(ulong)row_index*445;
    ulong raw=row[0],accept=row[33],remainder=row[66],count=row[128],value=0;
    uint draws=kind==0?1197:643,polynomials=kind==0?4:2;
    uint take=row_index<draws&&accept&&count<polynomials*256;
    if(column<33)value=(raw>>(column-1))&1UL;
    else if(column<66){ulong compare=PQ_SAMPLE_LIMIT-1+((ulong)(!accept)<<32)-raw;value=(compare>>(column-34))&1UL;}
    else if(column<95)value=(remainder>>(column-67))&1UL;
    else if(column<123)value=((PQ_SAMPLE_Q-1-remainder)>>(column-95))&1UL;
    else if(column<128)value=((raw/PQ_SAMPLE_Q)>>(column-123))&1UL;
    else if(column<140)value=(count>>(column-129))&1UL;
    else if(column==140)value=take;
    else if(column==141)value=take&&(count%4==3);
    else if(column==142)value=(count&15)==15;
    else if(column==143)value=((count>>4)&15)==15;
    else if(column==144)value=take&&(count%256==255);
    else {ulong previous=row_index?trace[(ulong)(row_index-1)*445]:0;value=(previous>>(16*(column-145)))&65535UL;}
    row[column]=value;
}

__kernel void pq_sparse_snapshots(__global const ulong *bytes,uint kind,
    __global const ulong *history,__global ulong *trace){
    uint item=get_global_id(0),row=item/320,column=item%320;
    if(row>=256)return;ulong value=0;
    if(column<256){ulong active=history[column];if(active!=0&&row>=active)value=history[256+column];}
    else {uint bit=column-256,byte=bit/8,sign_bytes=kind==3?6:5;if(byte<sign_bytes&&row>byte)value=(bytes[byte]>>(bit%8))&1UL;}
    trace[(ulong)row*506+column]=value;
}

__kernel void pq_sampling_poseidon(uint kind,uint rows,__global ulong *trace,
    __global const ulong *rci,__global const ulong *rcp,
    __global const ulong *rcf,__global const ulong *diag){
    uint item=get_global_id(0),uniform=kind<2;
    uint row=uniform?item/2:item,at=uniform?(item%2==0?163:257):412;
    if(row<rows)pq_poseidon_trace_row(trace,uniform?445:506,at,row,rci,rcp,rcf,diag);
}
__kernel void pq_uniform_bundle_columns(uint rows,__global ulong *trace,
    __global const ulong *rci,__global const ulong *rcp,
    __global const ulong *rcf,__global const ulong *diag){
    uint row=get_global_id(0);if(row>=rows)return;
    for(uint i=0;i<4;++i)trace[(ulong)row*445+355+i]=trace[(ulong)row*445+257+86+i];
    pq_poseidon_trace_row(trace,445,351,row,rci,rcp,rcf,diag);
}
__kernel void pq_sampling_public(__global const ulong *endpoints,__global ulong *public_values){
    uint i=get_global_id(0);if(i<8)public_values[i]=endpoints[i];
}
