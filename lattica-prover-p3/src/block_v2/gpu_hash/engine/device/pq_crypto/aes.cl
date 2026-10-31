inline uchar pq_aes_mul(uchar a,uchar b) {
    uchar z=0;for(uint j=0;j<8;++j){if(b&1)z^=a;uchar high=a>>7;a<<=1;if(high)a^=0x1b;b>>=1;}return z;
}
inline uchar pq_aes_pow(uchar x,uint power) {
    uchar y=1;while(power){if(power&1)y=pq_aes_mul(y,x);x=pq_aes_mul(x,x);power>>=1;}return y;
}
inline uint pq_aes_shift(uint i){return 4*((i/4+i%4)%4)+i%4;}
inline uchar pq_aes_sbox_value(__global const ulong *table,uchar x){
    uchar y=0;for(uint b=0;b<8;++b)y|=(uchar)(table[(uint)x*66+42+b]<<b);return y;
}
inline uchar pq_aes_sbox_copy(__global ulong *row,uint start,__global const ulong *table,uchar x){
    for(uint j=0;j<66;++j)row[start+j]=table[(uint)x*66+j];return pq_aes_sbox_value(table,x);
}
inline void pq_aes_header(__global const ulong *input,__global const ulong *g,uchar bytes[52]){
    for(uint j=0;j<32;++j)bytes[j]=(uchar)input[j];
    for(uint j=0;j<8;++j){bytes[32+j]=(uchar)(g[7]>>(8*j));bytes[44+j]=(uchar)(g[2]>>(8*j));}
    for(uint j=0;j<4;++j)bytes[40+j]=(uchar)(g[8]>>(8*j));
}
inline void pq_aes_sbox_witness(__global ulong *tmp,uint x){
    __global ulong *row=tmp+x*66;uchar inverse=pq_aes_pow((uchar)x,254);
    pq_bits(row,0,(ulong)inverse,8);row[40]=x==0;row[41]=x?gl_canon(gl_pow((ulong)x,0xfffffffeffffffffUL)):0;
    uchar out=0;
    for(uint bit=0;bit<8;++bit){
        uint sum=0;
        for(uint i=0;i<8;++i)for(uint j=0;j<8;++j)
            if(pq_aes_mul((uchar)(1<<i),(uchar)(1<<j))&(1<<bit))sum+=((x>>i)&1)*((inverse>>j)&1);
        uint expected=x!=0&&bit==0;pq_bits(row,8+4*bit,(sum-expected)/2,4);
        uint affine=(0x63>>bit)&1;
        for(uint k=0;k<5;++k){uint shift=k? k+3:0;affine+=(inverse>>((bit+shift)%8))&1;}
        out|=(uchar)((affine&1)<<bit);pq_bits(row,50+2*bit,affine/2,2);
    }
    pq_bits(row,42,(ulong)out,8);
}
__kernel void pq_crypto_aes_sboxes(PQ_ARGS){
    uint x=get_global_id(0);if(x<256)pq_aes_sbox_witness(tmp,x);
}
// Serial-lane checkpoints append to the existing scrubbed scratch matrix.
// Public reservation and all historical offsets remain unchanged. Packed byte
// words are storage, never field elements: unpack before writing trace columns.
#define PQ_AES_LANE_STATE_WORDS 118UL
#define PQ_AES_LANE_HEADER_WORDS 28UL
inline ulong pq_aes_lane_header_offset(__global const ulong *g) {
    return pq_crypto_public_offset(g)+64;
}
inline ulong pq_aes_lane_half_offset(__global const ulong *g) {
    return pq_aes_lane_header_offset(g)+PQ_AES_LANE_HEADER_WORDS;
}
inline ulong pq_aes_lane_state_offset(__global const ulong *g) {
    return pq_aes_lane_half_offset(g)+g[4]*4;
}
inline ulong pq_aes_lane_inverse_offset(__global const ulong *g) {
    return pq_aes_lane_state_offset(g)+g[4]*PQ_AES_LANE_STATE_WORDS;
}
inline ulong pq_aes_pack8(const uchar *bytes) {
    ulong packed=0;
    for(uint j=0;j<8;++j)packed|=((ulong)bytes[j])<<(j*8);
    return packed;
}
inline uchar pq_aes_checkpoint_byte(__global const ulong *checkpoint,ulong offset,uint byte) {
    return (uchar)(checkpoint[offset+byte/8]>>(8*(byte%8)));
}
inline void pq_aes_store_checkpoint(__global ulong *checkpoint,uint round,
    const uchar rolling[32],const uchar state[16]) {
    // Fifteen key/state boundaries, followed by fourteen S-box byte vectors.
    for(uint j=0;j<4;++j)checkpoint[round*4+j]=pq_aes_pack8(rolling+j*8);
    for(uint j=0;j<2;++j)checkpoint[60+round*2+j]=pq_aes_pack8(state+j*8);
}
inline void pq_aes_seed_row(__global ulong *row,const ulong acc[4],
    const uchar bytes[8],uint count) {
    // Accumulators were advanced once by aes_prepare. Row seeds alone are
    // expanded into the unchanged Poseidon trace by pq_crypto_poseidon_rows.
    for(uint j=0;j<8;++j)row[323+j]=j<4?acc[j]:0;
    for(uint j=0;j<count;++j)row[327+j/2]|=((ulong)bytes[j])<<(8*(j%2));
}
inline void pq_aes_encrypt_block_checkpoint(__global const ulong *input,ulong domain,uint counter,
    __global const ulong *table,uchar state[16],
    __global ulong *checkpoint,uint capture){
    uchar rolling[32],next[16],sub[16],nextkey[16];
    for(uint j=0;j<32;++j)rolling[j]=(uchar)input[j];
    for(uint j=0;j<16;++j){uchar p=j<4?(uchar)(counter>>(8*j)):j<8?0:(uchar)(domain>>(8*(j-8)));state[j]=p^rolling[j];}
    for(uint round=0;round<14;++round){
        if(capture)pq_aes_store_checkpoint(checkpoint,round,rolling,state);
        for(uint j=0;j<16;++j)sub[j]=pq_aes_sbox_value(table,state[j]);
        if(capture)for(uint j=0;j<2;++j)checkpoint[90+round*2+j]=pq_aes_pack8(sub+j*8);
        for(uint j=0;j<16;++j){
            uchar v=rolling[16+j];
            if(round==13)v^=sub[pq_aes_shift(j)];
            else for(uint source=0;source<4;++source){uint k=(source+4-j%4)%4;uchar c=k==0?2:k==1?3:1;v^=pq_aes_mul(c,sub[pq_aes_shift(4*(j/4)+source)]);}
            next[j]=v;
            uchar t=j<4?pq_aes_sbox_value(table,rolling[28+(round%2?j:(j+1)%4)]):nextkey[j-4];
            nextkey[j]=rolling[j]^t^((j==0&&round%2==0)?pq_aes_pow(2,round/2):0);
        }
        for(uint j=0;j<16;++j){state[j]=next[j];rolling[j]=rolling[16+j];rolling[16+j]=nextkey[j];}
    }
    if(capture)pq_aes_store_checkpoint(checkpoint,14,rolling,state);
}
// Preserve the shared raw-byte helper API and its scratch-free behavior.
inline void pq_aes_encrypt_block(__global const ulong *input,ulong domain,uint counter,
    __global const ulong *table,uchar state[16]){
    pq_aes_encrypt_block_checkpoint(input,domain,counter,table,state,(__global ulong *)0,0);
}
__kernel void pq_crypto_aes_encrypt(PQ_ARGS){
    ulong block=get_global_id(0);
    // Metadata indices are padded lane-unit indices, independent of the AES
    // ciphertext block index below. Initialize them before the ciphertext bound.
    if(g[0]==0 && block<g[5]/1024){
        ulong position=min(block,g[4]),at=g[3]+position,remaining=g[4]-position;
        ulong last=(g[2]+15)/16-1;
        __global ulong *inverse=tmp+pq_aes_lane_inverse_offset(g)+block*3;
        inverse[0]=remaining?gl_canon(gl_pow(remaining,0xfffffffeffffffffUL)):0;
        inverse[1]=at==g[3]?0:gl_canon(gl_pow(gl_sub(at,g[3]),0xfffffffeffffffffUL));
        inverse[2]=at==last?0:gl_canon(gl_pow(gl_sub(at,last),0xfffffffeffffffffUL));
    }
    if(block>=g[3]+g[4])return;
    uint capture=g[0]==0 && block>=g[3];
    __global ulong *checkpoint=tmp;
    if(capture)checkpoint=tmp+pq_aes_lane_state_offset(g)+(block-g[3])*PQ_AES_LANE_STATE_WORDS;
    uchar state[16];
    pq_aes_encrypt_block_checkpoint(input,g[7],(uint)g[8]+(uint)block,tmp,state,checkpoint,capture);
    for(uint j=0;j<16;++j)tmp[PQ_AES_TABLE+block*16+j]=state[j];
}
__kernel void pq_crypto_aes_prepare(PQ_ARGS){
    if(get_global_id(0))return;
    uchar header[52],chunk[8];pq_aes_header(input,g,header);
    ulong ia[4]={0x4145535f43545249UL,52,0,0},oa[4]={0x4145535f4354524fUL,g[2],0,0},seed[8];
    for(uint start=0;start<52;start+=8){
        if(g[0]==0)for(uint j=0;j<4;++j)tmp[pq_aes_lane_header_offset(g)+(start/8)*4+j]=ia[j];
        uint count=min((uint)8,52-start);
        for(uint j=0;j<count;++j)chunk[j]=header[start+j];
        pq_crypto_absorb(ia,chunk,count,seed,PQ_PASS);
    }
    ulong boundary=PQ_AES_TABLE+(g[3]+g[4])*16;
    for(ulong block=0;block<=g[3]+g[4];++block){
        if(block>=g[3])for(uint j=0;j<4;++j){tmp[boundary+(block-g[3])*8+j]=ia[j];tmp[boundary+(block-g[3])*8+4+j]=oa[j];}
        if(block==g[3]+g[4])break;
        for(uint start=0;start<16;start+=8){
            ulong at=block*16+start;if(at>=g[2])break;
            uint count=(uint)min((ulong)8,g[2]-at);
            for(uint j=0;j<count;++j)chunk[j]=(uchar)tmp[PQ_AES_TABLE+at+j];
            pq_crypto_absorb(oa,chunk,count,seed,PQ_PASS);
            if(g[0]==0 && block>=g[3] && start==0)
                for(uint j=0;j<4;++j)tmp[pq_aes_lane_half_offset(g)+(block-g[3])*4+j]=oa[j];
        }
    }
    __global ulong *pub=tmp+pq_crypto_public_offset(g);
    for(uint j=0;j<4;++j){pub[j]=ia[j];if(g[0]==0){pub[4+j]=tmp[boundary+4+j];pub[8+j]=oa[j];}else pub[4+j]=oa[j];}
}
inline void pq_aes_lane(PQ_ARGS){
    // One independent work item materializes each row from GPU checkpoints.
    // All fields describe state BEFORE that row's transition, including partial
    // byte updates and the final pre-reset row. Padding never reads checkpoints.
    ulong index=get_global_id(0);if(index>=g[5])return;
    ulong unit=index/1024,position=min(unit,g[4]);
    uint local_step=(uint)(index%1024),phase=local_step/64,active=unit<g[4];
    ulong block=g[3]+position,remaining=g[4]-position,last=(g[2]+15)/16-1;
    uint counter=(uint)g[8]+(uint)block;
    uchar rolling[32],state[16]={0},scratch[16]={0};
    for(uint j=0;j<32;++j)rolling[j]=(uchar)input[j];
    if(active){
        __global const ulong *checkpoint=tmp+pq_aes_lane_state_offset(g)+unit*PQ_AES_LANE_STATE_WORDS;
        if(phase==0){
            for(uint j=0;j<16;++j)if(local_step>16+j)
                state[j]=pq_aes_checkpoint_byte(checkpoint,60,j);
        }else if(phase<15){
            uint round=phase-1,step=local_step%64;
            uint key_round=round+(step>=48);
            for(uint j=0;j<32;++j)rolling[j]=pq_aes_checkpoint_byte(checkpoint,key_round*4,j);
            for(uint j=0;j<16;++j){
                uint state_round=round+(step>=32 || (step>=16 && j<step-16));
                state[j]=pq_aes_checkpoint_byte(checkpoint,60+state_round*2,j);
                if(step<16){
                    scratch[j]=j<step?pq_aes_checkpoint_byte(checkpoint,90+round*2,j)
                        :round?pq_aes_checkpoint_byte(checkpoint,round*4,16+j):0;
                }else if(step<32){
                    scratch[j]=pq_aes_checkpoint_byte(checkpoint,90+round*2,j);
                }else if(step<48){
                    scratch[j]=j<step-32?pq_aes_checkpoint_byte(checkpoint,(round+1)*4,16+j)
                        :pq_aes_checkpoint_byte(checkpoint,90+round*2,j);
                }else{
                    scratch[j]=pq_aes_checkpoint_byte(checkpoint,(round+1)*4,16+j);
                }
            }
        }else{
            for(uint j=0;j<32;++j)rolling[j]=pq_aes_checkpoint_byte(checkpoint,14*4,j);
            for(uint j=0;j<16;++j){
                state[j]=pq_aes_checkpoint_byte(checkpoint,60+14*2,j);
                scratch[j]=rolling[16+j];
            }
        }
    }
    ulong boundary=PQ_AES_TABLE+(g[3]+g[4])*16,ia[4],oa[4];
    for(uint j=0;j<4;++j){
        ia[j]=unit==0 && local_step<7
            ?tmp[pq_aes_lane_header_offset(g)+local_step*4+j]
            :tmp[boundary+position*8+j];
        oa[j]=tmp[boundary+position*8+4+j];
        if(active && local_step==961)oa[j]=tmp[pq_aes_lane_half_offset(g)+unit*4+j];
        if(active && local_step>=962)oa[j]=tmp[boundary+(position+1)*8+4+j];
    }
    __global const ulong *inverse=tmp+pq_aes_lane_inverse_offset(g)+unit*3;
    __global ulong *row=trace+index*417;
    for(uint j=0;j<32;++j){row[j]=(uchar)input[j];row[32+j]=rolling[j];}
    for(uint j=0;j<16;++j){row[64+j]=state[j];row[80+j]=scratch[j];}
    pq_bits(row,258,counter,32);row[291]=block;row[292]=remaining;row[293]=active;
    row[294]=inverse[0];row[295]=block==g[3];row[296]=inverse[1];row[297]=block==last;row[298]=inverse[2];
    for(uint j=0;j<4;++j){row[299+j]=ia[j];row[303+j]=oa[j];}
    pq_bits(row,307,phase,4);row[311]=phase==0;row[312]=phase>=1&&phase<15;row[313]=phase==14;row[314]=phase==15;
    pq_bits(row,315,pq_aes_pow(2,(phase?phase-1:0)/2),8);
    uchar read[8]={0},result=0;uint parity[8]={0};
    if(active){
        if(local_step<7 && unit==0){
            uchar header[52];pq_aes_header(input,g,header);
            uint count=min((uint)8,52-local_step*8);
            for(uint j=0;j<count;++j)read[j]=header[local_step*8+j];
            pq_aes_seed_row(row,ia,read,count);
        }else if(local_step>=16 && local_step<32){
            uint i=local_step-16;
            read[0]=i<4?(uchar)(counter>>(8*i)):i<8?0:(uchar)(g[7]>>(8*(i-8)));read[1]=(uchar)input[i];
            for(uint b=0;b<8;++b)parity[b]=((read[0]>>b)&1)+((read[1]>>b)&1);
            result=read[0]^read[1];
        }else if(local_step>=64 && local_step<960){
            uint round=(local_step-64)/64,step=(local_step-64)%64,i=step%16;
            if(step<16){read[0]=state[i];result=pq_aes_sbox_copy(row,160,tmp,read[0]);}
            else if(step<32){
                for(uint k=0;k<4;++k)read[k]=scratch[pq_aes_shift(4*(i/4)+k)];read[4]=rolling[16+i];
                for(uint b=0;b<8;++b){uint sum=(read[4]>>b)&1;
                    if(round==13)sum+=(read[i%4]>>b)&1;
                    else for(uint k=0;k<4;++k){uint cidx=(k+4-i%4)%4;uchar c=cidx==0?2:cidx==1?3:1;for(uint sb=0;sb<8;++sb)if(pq_aes_mul(c,(uchar)(1<<sb))&(1<<b))sum+=(read[k]>>sb)&1;}
                    parity[b]=sum;result|=(uchar)((sum&1)<<b);
                }
            }else if(step<48){
                uchar rc=round%2==0&&i==0?pq_aes_pow(2,round/2):0,t;
                if(i<4){read[0]=rolling[28+(round%2?i:(i+1)%4)];read[1]=rolling[i];t=pq_aes_sbox_copy(row,160,tmp,read[0]);}
                else {read[0]=rolling[i];read[1]=scratch[i-4];t=read[0];}
                for(uint b=0;b<8;++b)parity[b]=((t>>b)&1)+((read[1]>>b)&1)+((rc>>b)&1);
                result=t^read[1]^rc;
            }
        }else if(local_step==960 || local_step==961){
            ulong start=block*16+(local_step-960)*8;
            if(start<g[2]){
                uint count=(uint)min((ulong)8,g[2]-start);
                for(uint j=0;j<count;++j)read[j]=(uchar)tmp[PQ_AES_TABLE+start+j];
                pq_aes_seed_row(row,oa,read,count);
            }
        }else if(local_step==1023){row[290]=counter==0xffffffffU;}
    }
    pq_byte_bits(row,96,read,8);pq_bits(row,226,result,8);
    for(uint b=0;b<8;++b)pq_bits(row,234+3*b,parity[b]/2,3);
}
inline void pq_aes_wide(PQ_ARGS){
    ulong block=get_global_id(0);if(block>=g[4])return;
    uchar key[32],rolling[32],state[16],cipher[16],header[52];
    uint counter=(uint)g[8]+(uint)block;
    for(uint j=0;j<32;++j)key[j]=rolling[j]=(uchar)input[j];pq_aes_header(input,g,header);
    for(uint j=0;j<16;++j){uchar p=j<4?(uchar)(counter>>(8*j)):j<8?0:(uchar)(g[7]>>(8*(j-8)));state[j]=p^key[j];cipher[j]=(uchar)tmp[PQ_AES_TABLE+block*16+j];}
    ulong boundary=PQ_AES_TABLE+g[4]*16,ia[4],oa[4];
    for(uint j=0;j<4;++j){ia[j]=block?tmp[boundary+block*8+j]:(j==0?0x4145535f43545249UL:j==1?52:0);oa[j]=tmp[boundary+block*8+4+j];}
    for(uint round=0;round<14;++round){
        __global ulong *row=trace+(block*14+round)*3084;
        pq_bits(row,2856,counter,32);pq_byte_bits(row,0,key,32);pq_byte_bits(row,256,rolling,32);pq_byte_bits(row,512,state,16);pq_byte_bits(row,640,cipher,16);
        uchar sub[16],keysub[4],nextkey[16],nextstate[16]={0};
        for(uint j=0;j<16;++j)sub[j]=pq_aes_sbox_copy(row,768+j*66,tmp,state[j]);
        for(uint j=0;j<4;++j)keysub[j]=pq_aes_sbox_copy(row,1824+j*66,tmp,rolling[28+(round%2?j:(j+1)%4)]);
        uchar rcon=round%2==0?pq_aes_pow(2,round/2):0;
        for(uint j=0;j<16;++j){uchar t=j<4?keysub[j]:nextkey[j-4],rc=j==0?rcon:0;nextkey[j]=rolling[j]^t^rc;
            for(uint b=0;b<8;++b)pq_bits(row,2216+j*8+b,(((rolling[j]>>b)&1)+((t>>b)&1)+((rc>>b)&1))/2,1);
            for(uint b=0;b<8;++b){uint sum=(rolling[16+j]>>b)&1;
                if(round==13)sum+=(sub[pq_aes_shift(j)]>>b)&1;
                else for(uint k=0;k<4;++k){uint cidx=(k+4-j%4)%4;uchar c=cidx==0?2:cidx==1?3:1;for(uint sb=0;sb<8;++sb)if(pq_aes_mul(c,(uchar)(1<<sb))&(1<<b))sum+=(sub[pq_aes_shift(4*(j/4)+k)]>>sb)&1;}
                nextstate[j]|=(uchar)((sum&1)<<b);pq_bits(row,2472+(j*8+b)*3,sum/2,3);
            }
        }
        pq_byte_bits(row,2088,nextkey,16);pq_byte_bits(row,2344,nextstate,16);
        for(uint j=0;j<16;++j){state[j]=nextstate[j];rolling[j]=rolling[16+j];rolling[16+j]=nextkey[j];}
        for(uint j=0;j<4;++j){row[2888+j]=ia[j];row[2892+j]=oa[j];}
        uchar inbytes[8]={0},outbytes[8]={0};uint ni=block==0&&round<7?min((uint)8,52-round*8):0;
        uint take=(uint)min((ulong)16,g[2]-block*16),no=round<2&&round*8<take?min((uint)8,take-round*8):0;
        for(uint j=0;j<ni;++j)inbytes[j]=header[round*8+j];for(uint j=0;j<no;++j)outbytes[j]=cipher[round*8+j];
        pq_crypto_hash_row(row,2896,ia,inbytes,ni,ni!=0,PQ_PASS);pq_crypto_hash_row(row,2990,oa,outbytes,no,no!=0,PQ_PASS);
    }
    // Only the final block fills the tail; row ownership remains disjoint.
    if(block+1==g[4])for(ulong rowidx=g[4]*14;rowidx<g[5];++rowidx){
        __global ulong *row=trace+rowidx*3084;uchar empty[8]={0};
        for(uint j=0;j<4;++j){row[2888+j]=ia[j];row[2892+j]=oa[j];}
        pq_crypto_hash_row(row,2896,ia,empty,0,0,PQ_PASS);pq_crypto_hash_row(row,2990,oa,empty,0,0,PQ_PASS);
    }
}
__kernel void pq_crypto_aes_trace(PQ_ARGS){
    if(g[0]==0)pq_aes_lane(input,g,tmp,trace,public_values,PQ_PASS);
    else pq_aes_wide(input,g,tmp,trace,public_values,PQ_PASS);
}
