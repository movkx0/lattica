__constant uint pq_keccak_rot[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
__constant ulong pq_keccak_rc[24]={
  0x0000000000000001UL,0x0000000000008082UL,0x800000000000808aUL,0x8000000080008000UL,
  0x000000000000808bUL,0x0000000080000001UL,0x8000000080008081UL,0x8000000000008009UL,
  0x000000000000008aUL,0x0000000000000088UL,0x0000000080008009UL,0x000000008000000aUL,
  0x000000008000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,
  0x8000000000008002UL,0x8000000000000080UL,0x000000000000800aUL,0x800000008000000aUL,
  0x8000000080008081UL,0x8000000000008080UL,0x0000000080000001UL,0x8000000080008008UL};
inline ulong pq_rot(ulong x,uint r){return r?((x<<r)|(x>>(64-r))):x;}
inline void pq_keccak_round(ulong state[25],ulong rotated[25],uint round){
    ulong c[5];for(uint x=0;x<5;++x)c[x]=state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20];
    for(uint y=0;y<5;++y)for(uint x=0;x<5;++x){uint i=x+5*y;ulong a=state[i]^c[(x+4)%5]^pq_rot(c[(x+1)%5],1);rotated[y+5*((2*x+3*y)%5)]=pq_rot(a,pq_keccak_rot[i]);}
    for(uint y=0;y<5;++y)for(uint x=0;x<5;++x)state[x+5*y]=rotated[x+5*y]^((~rotated[(x+1)%5+5*y])&rotated[(x+2)%5+5*y]);
    state[0]^=pq_keccak_rc[round];
}
inline uint pq_shake_raw(__global const ulong *g,ulong permutation){
    ulong offset=permutation*136;return offset<g[1]?(uint)min((ulong)136,g[1]-offset):0;
}
inline uint pq_shake_take(__global const ulong *g,ulong permutation){
    ulong last=g[1]/136;if(permutation<last)return 0;ulong offset=(permutation-last)*136;
    return offset<g[2]?(uint)min((ulong)136,g[2]-offset):0;
}
__kernel void pq_crypto_shake_prepare(PQ_ARGS){
    if(get_global_id(0))return;
    ulong state[25]={0},rotated[25],ia[4]={0x5348414b455f494eUL,g[1],0,0},oa[4]={0x5348414b455f4f55UL,g[2],0,0};
    for(ulong permutation=0;permutation<g[3]+g[4];++permutation){
        uint raw=pq_shake_raw(g,permutation),take=pq_shake_take(g,permutation);uchar message[136]={0},chunk[8];ulong seed[8];
        for(uint j=0;j<raw;++j)message[j]=(uchar)input[permutation*136+j];
        if(permutation==g[1]/136){message[raw]^=0x1f;message[135]^=0x80;}
        __global ulong *data=tmp+(permutation>=g[3]?(permutation-g[3])*PQ_SHAKE_PREP:0);
        if(permutation>=g[3]){
            for(uint j=0;j<25;++j)data[j]=state[j];
            for(uint j=0;j<4;++j){data[92+j]=ia[j];data[96+j]=oa[j];}
        }
        for(uint j=0;j<136;++j)state[j/8]^=((ulong)message[j])<<(8*(j%8));
        if(permutation>=g[3]){
            for(uint j=0;j<25;++j)data[25+j]=state[j];
            for(uint j=0;j<17;++j){ulong word=0;for(uint b=0;b<8;++b)word|=((ulong)message[j*8+b])<<(8*b);data[75+j]=word;}
        }
        for(uint round=0;round<24;++round)pq_keccak_round(state,rotated,round);
        for(uint start=0;start<raw;start+=8){uint count=min((uint)8,raw-start);for(uint j=0;j<count;++j)chunk[j]=message[start+j];pq_crypto_absorb(ia,chunk,count,seed,PQ_PASS);}
        for(uint start=0;start<take;start+=8){uint count=min((uint)8,take-start);for(uint j=0;j<count;++j)chunk[j]=(uchar)(state[(start+j)/8]>>(8*((start+j)%8)));pq_crypto_absorb(oa,chunk,count,seed,PQ_PASS);}
        if(permutation>=g[3]){
            for(uint j=0;j<25;++j){data[50+j]=state[j];data[108+j]=rotated[j];}
            for(uint j=0;j<4;++j){data[100+j]=ia[j];data[104+j]=oa[j];}
        }
    }
    __global ulong *pub=tmp+pq_crypto_public_offset(g),*last=tmp+(g[4]-1)*PQ_SHAKE_PREP;
    for(uint j=0;j<100;++j){pub[j]=(tmp[j/4]>>(16*(j%4)))&65535UL;pub[100+j]=(last[50+j/4]>>(16*(j%4)))&65535UL;}
    for(uint j=0;j<4;++j){pub[200+j]=tmp[92+j];pub[204+j]=last[100+j];pub[208+j]=tmp[96+j];pub[212+j]=last[104+j];}
}
inline void pq_shake_lane(PQ_ARGS){
    ulong unit=get_global_id(0);if(unit>=g[4])return;
    ulong permutation=g[3]+unit;__global ulong *data=tmp+unit*PQ_SHAKE_PREP;
    ulong state[25],scratch[25],ia[4],oa[4];
    for(uint j=0;j<25;++j){state[j]=data[j];scratch[j]=g[0]==3&&unit?tmp[(unit-1)*PQ_SHAKE_PREP+108+j]:0;}
    for(uint j=0;j<4;++j){ia[j]=data[92+j];oa[j]=data[96+j];}
    uint raw=pq_shake_raw(g,permutation),take=pq_shake_take(g,permutation);uchar rc[15]={1};
    for(uint index=0;index<4096;++index){
        uint block=index/128,step=index%128,prelude=block==0,rounds=block>=1&&block<=24,final_round=block==24;
        __global ulong *row=trace+(unit*4096+index)*g[6];
        for(uint j=0;j<7;++j)rc[j+8]=rc[j+6]^rc[j+5]^rc[j+4]^rc[j];
        pq_limbs(row,state);pq_limbs(row+100,scratch);
        for(uint j=0;j<4;++j){row[392+j]=ia[j];row[396+j]=oa[j];}
        pq_bits(row,400,block,5);row[405]=prelude;row[406]=rounds;row[407]=final_round;
        for(uint j=0;j<15;++j)row[408+j]=rc[j];if(g[0]==3)row[517]=permutation;
        ulong slots[3]={0};
        if(rounds){
            if(step<25){uint x=step/5,y=step%5;slots[0]=state[y*5+x];slots[1]=scratch[x];scratch[x]=y?slots[0]^slots[1]:slots[0];}
            else if(step<50){uint lane=step-25,x=lane%5;slots[0]=state[lane];slots[1]=scratch[(x+4)%5];slots[2]=scratch[(x+1)%5];state[lane]=slots[0]^slots[1]^pq_rot(slots[2],1);}
            else if(step<75){uint lane=step-50,x=lane%5,y=lane/5;slots[0]=state[lane];scratch[((2*x+3*y)%5)*5+y]=pq_rot(state[lane],pq_keccak_rot[lane]);}
            else if(step<100){uint lane=step-75,x=lane%5,y=lane/5;slots[0]=scratch[lane];slots[1]=scratch[y*5+(x+1)%5];slots[2]=scratch[y*5+(x+2)%5];state[lane]=slots[0]^((~slots[1])&slots[2]);}
            else if(step==100){slots[0]=state[0];ulong rc_word=0;for(uint j=0;j<7;++j)rc_word|=((ulong)rc[j])<<((1U<<j)-1);state[0]^=rc_word;for(uint j=0;j<8;++j)rc[j]=rc[j+7];}
        }
        if(step>=101&&step<=117){
            uint lane=step-101;
            if(prelude&&permutation<=g[1]/136){
                slots[0]=state[lane];slots[1]=data[75+lane];state[lane]^=slots[1];
                uint start=lane*8;if(start<raw){uint count=min((uint)8,raw-start);uchar bytes[8];for(uint j=0;j<count;++j)bytes[j]=(uchar)(data[75+lane]>>(8*j));pq_crypto_hash_row(row,423,ia,bytes,count,1,PQ_PASS);}
            }
            if(final_round){
                slots[0]=state[lane];uint start=lane*8;if(start<take){uint count=min((uint)8,take-start);uchar bytes[8];for(uint j=0;j<count;++j)bytes[j]=(uchar)(state[lane]>>(8*j));pq_crypto_hash_row(row,423,oa,bytes,count,1,PQ_PASS);}
            }
        }
        for(uint j=0;j<3;++j)pq_bits(row,200+j*64,slots[j],64);
    }
}
inline void pq_shake_wide(PQ_ARGS){
    ulong unit=get_global_id(0);if(unit*24>=g[5])return;
    uint active=unit<g[4];ulong state[25]={0},initial[25]={0},output[25]={0},rotated[25],ia[4],oa[4];
    __global ulong *data=tmp+(active?unit:g[4]-1)*PQ_SHAKE_PREP;
    for(uint j=0;j<25;++j){if(active){initial[j]=state[j]=data[25+j];output[j]=data[50+j];}}
    if(!active)for(uint round=0;round<24;++round)pq_keccak_round(output,rotated,round);
    for(uint j=0;j<4;++j){ia[j]=data[(active?92:100)+j];oa[j]=data[(active?96:104)+j];}
    uint raw=active?pq_shake_raw(g,g[3]+unit):0,take=active?pq_shake_take(g,g[3]+unit):0;
    for(uint round=0;round<24&&unit*24+round<g[5];++round){
        __global ulong *row=trace+(unit*24+round)*4033;
        row[round]=1;pq_limbs(row+25,initial);pq_limbs(row+125,state);
        ulong c[5],cp[5];
        for(uint x=0;x<5;++x){c[x]=state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20];pq_bits(row,225+x*64,c[x],64);}
        for(uint x=0;x<5;++x){cp[x]=c[x]^c[(x+4)%5]^pq_rot(c[(x+1)%5],1);pq_bits(row,545+x*64,cp[x],64);}
        for(uint y=0;y<5;++y)for(uint x=0;x<5;++x){uint lane=x+5*y;state[lane]^=c[x]^cp[x];pq_bits(row,865+lane*64,state[lane],64);rotated[y+5*((2*x+3*y)%5)]=pq_rot(state[lane],pq_keccak_rot[lane]);}
        for(uint y=0;y<5;++y)for(uint x=0;x<5;++x)state[x+5*y]=rotated[x+5*y]^((~rotated[(x+1)%5+5*y])&rotated[(x+2)%5+5*y]);
        pq_limbs(row+2465,state);pq_bits(row,2565,state[0],64);state[0]^=pq_keccak_rc[round];
        for(uint j=0;j<4;++j)row[2629+j]=(state[0]>>(16*j))&65535UL;
        // Keccak column count is 2633: 24+1+100+100+320+320+1600+100+64+4.
        for(uint bit=0;bit<1088;++bit)row[2633+bit]=active?((data[75+bit/64]>>(bit%64))&1UL):0;
        pq_limbs(row+3721,output);
        uint odd=(g[2]%136)%2?(uint)((g[2]%136)/2):0;ulong limb=(output[odd/4]>>(16*(odd%4)))&65535UL;pq_bits(row,3821,limb,16);
        for(uint j=0;j<4;++j){row[3837+j]=ia[j];row[3841+j]=oa[j];}
        uint start=round*8,ni=start<raw?min((uint)8,raw-start):0,no=start<take?min((uint)8,take-start):0;
        uchar inbytes[8]={0},outbytes[8]={0};for(uint j=0;j<ni;++j)inbytes[j]=(uchar)(data[75+(start+j)/8]>>(8*((start+j)%8)));for(uint j=0;j<no;++j)outbytes[j]=(uchar)(output[(start+j)/8]>>(8*((start+j)%8)));
        pq_crypto_hash_row(row,3845,ia,inbytes,ni,ni!=0,PQ_PASS);pq_crypto_hash_row(row,3939,oa,outbytes,no,no!=0,PQ_PASS);
    }
}
__kernel void pq_crypto_shake_trace(PQ_ARGS){
    if(g[0]==4)pq_shake_wide(input,g,tmp,trace,public_values,PQ_PASS);
    else pq_shake_lane(input,g,tmp,trace,public_values,PQ_PASS);
}
