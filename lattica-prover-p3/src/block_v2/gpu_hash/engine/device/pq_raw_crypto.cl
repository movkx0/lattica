// Reuses the exact AES and Keccak primitives of pq_crypto/*.cl, included first.
// Geometry: kind, input bytes, output words, AES domain, AES starting counter.
#define PQ_RAW_ARGS __global const ulong *input, __global const ulong *g, __global ulong *scratch, __global ulong *output
__kernel void pq_raw_aes_sboxes(PQ_RAW_ARGS) {
    uint x=get_global_id(0);if(x>=256)return;
    // Raw encryption needs only S-box output bits, not AIR inverse witnesses.
    uchar inverse=pq_aes_pow((uchar)x,254);
    for(uint bit=0;bit<8;++bit){
        uint value=(0x63>>bit)&1;
        for(uint k=0;k<5;++k){uint shift=k?k+3:0;value^=(inverse>>((bit+shift)%8))&1;}
        scratch[x*66+42+bit]=value;
    }
}
__kernel void pq_raw_aes(PQ_RAW_ARGS) {
    ulong block=get_global_id(0);if(block*16>=g[2])return;
    uchar state[16];pq_aes_encrypt_block(input,g[3],(uint)g[4]+(uint)block,scratch,state);
    for(uint j=0;j<16&&block*16+j<g[2];++j)output[block*16+j]=state[j];
}
__kernel void pq_raw_shake(PQ_RAW_ARGS) {
    if(get_global_id(0))return;
    ulong state[25]={0},rotated[25],absorb=g[1]/136+1;
    for(ulong permutation=0;permutation<absorb;++permutation){
        ulong offset=permutation*136;
        uint raw=(uint)min((ulong)136,g[1]-offset);
        for(uint j=0;j<raw;++j)state[j/8]^=input[offset+j]<<(8*(j%8));
        if(permutation+1==absorb){state[raw/8]^=0x1fUL<<(8*(raw%8));state[16]^=0x8000000000000000UL;}
        for(uint round=0;round<24;++round)pq_keccak_round(state,rotated,round);
    }
    for(ulong offset=0;offset<g[2];offset+=136){
        uint take=(uint)min((ulong)136,g[2]-offset);
        for(uint j=0;j<take;++j)output[offset+j]=(state[j/8]>>(8*(j%8)))&255UL;
        if(offset+take<g[2])for(uint round=0;round<24;++round)pq_keccak_round(state,rotated,round);
    }
}
__kernel void pq_raw_uniform(PQ_RAW_ARGS) {
    if(get_global_id(0))return;
    uint width=g[0]==2?4:5;
    ulong bound=g[0]==2?4194256025UL:1099243232955UL;
    ulong modulus=g[0]==2?167770241UL:3489661057UL;
    ulong cursor=0,count=0;
    while(count<g[2]){
        if(cursor+width>g[1]){output[g[2]]=1;return;}
        ulong x=0;for(uint j=0;j<width;++j)x|=input[cursor+j]<<(8*j);cursor+=width;
        if(x<bound)output[count++]=x%modulus;
    }
}
__kernel void pq_raw_sparse(PQ_RAW_ARGS) {
    if(get_global_id(0))return;
    uint alpha=g[0]==4,sign_bytes=alpha?5:6;
    ulong signs=0,cursor=sign_bytes;uchar used[256]={0};
    for(uint j=0;j<sign_bytes;++j)signs|=input[j]<<(8*j);
    if(alpha){
        for(uint count=0;count<39;++count){
            uint index;
            do{if(cursor>=g[1]){output[256]=1;return;}index=(uint)input[cursor++];}while(used[index]);
            used[index]=1;output[index]=((signs>>count)&1)?2:1;
        }
    }else{
        for(uint group=0;group<4;++group){
            if(cursor>=g[1]){output[256]=1;return;}
            uint index=((uint)input[cursor++]&63)*4+group;
            used[index]=1;output[index]=((signs>>group)&1)?2:1;
        }
        uint count=4;
        for(uint group=0;group<4;++group)for(uint item=1;item<11;++item){
            uint index;
            do{if(cursor>=g[1]){output[256]=1;return;}index=((uint)input[cursor++]&63)*4+group;}while(used[index]);
            used[index]=1;output[index]=((signs>>count)&1)?2:1;++count;
        }
    }
}
