// Raw graph-witness arithmetic, deliberately independent of dense AIR layouts.
// Signed values are carried as original two's-complement ulong words. All signed
// overflow checks use defined unsigned arithmetic, including the i64::MIN edge.
#define PQ_OP_HEADER 4
inline ulong pq_op_residue(ulong word, ulong q) {
    ulong magnitude = (word >> 63) ? 0ul - word : word;
    ulong remainder = magnitude % q;
    return (word >> 63) && remainder != 0 ? q - remainder : remainder;
}
inline ulong pq_op_montgomery(ulong a, ulong b, ulong q) {
    // Both supported moduli are <2^32, so every product fits ulong.
    ulong factor = q == 167770241ul ? 2887272321ul : 1071660929ul;
    ulong product = a * b;
    ulong correction = ((product & 0xfffffffful) * factor) & 0xfffffffful;
    ulong hi = product >> 32, correction_hi = (correction * q) >> 32;
    return (hi + q - correction_hi) % q;
}

__kernel void pq_graph_arithmetic(__global const ulong *input,
    __global const ulong *metadata, __global ulong *output, __global ulong *status) {
    uint id = get_global_id(0), opcode = metadata[0], count = metadata[2];
    ulong q = metadata[1];
    if(opcode <= 6) {
        if(id >= count) return;
        ulong a = input[id], b = (opcode <= 3 || opcode == 6) ? input[count + id] : 0;
        if(opcode <= 3) {
            if(a >= q || b >= q) {status[id] = 1; return;}
            output[id] = opcode == 1 ? (a+b)%q : opcode == 2 ? (a+q-b)%q : pq_op_montgomery(a,b,q);
        } else if(opcode == 4) {
            output[id] = pq_op_residue(a,q);
        } else if(opcode == 5) {
            if(a == 0x8000000000000000ul) {status[id] = 2; return;}
            output[id] = 0ul-a;
        } else {
            ulong result = a-b;
            if(((a^b)&(a^result)) >> 63) {status[id] = 2; return;}
            output[id] = result;
        }
    } else if(opcode == 7) {
        if(id >= count) return;
        ulong state[256];
        for(uint i=0;i<256;++i) state[i]=pq_op_residue(input[(ulong)id*256+i],q);
        for(uint i=0;i<768;++i) {
            __global const ulong *step = metadata+PQ_OP_HEADER+4*i;
            uint a=step[0],b=step[1];
            ulong u=(state[a]*step[2])%q,v=(state[b]*step[3])%q;
            state[a]=(u+v)%q;state[b]=(u+q-v)%q;
        }
        for(uint block=0;block<64;++block) {
            uint source=metadata[PQ_OP_HEADER+768*4+block];
            for(uint j=0;j<4;++j) output[(ulong)id*256+block*4+j]=state[source*4+j];
        }
    } else if(opcode == 8) {
        if(id >= count*64) return;
        uint poly=id/64,block=id%64;
        __global const ulong *a=input+(ulong)poly*512+4*block,*b=a+256;
        for(uint j=0;j<4;++j) if(a[j]>=q||b[j]>=q) {status[id]=1;return;}
        ulong state[4]={0,0,0,0};
        for(uint i=0;i<4;++i) for(uint j=0;j<4;++j) {
            uint term=block*16+4*i+j,target=(i+j)%4;
            ulong factor=metadata[PQ_OP_HEADER+2*term],negative=metadata[PQ_OP_HEADER+2*term+1];
            ulong value=(((a[i]*b[j])%q)*factor)%q;
            state[target]=(negative?state[target]+q-value:state[target]+value)%q;
        }
        for(uint j=0;j<4;++j) output[(ulong)poly*256+4*block+j]=state[j];
    } else if(opcode == 9 || opcode == 10) {
        if(id>=256) return;
        uint source=metadata[PQ_OP_HEADER+id];
        ulong value=input[source],factor=metadata[PQ_OP_HEADER+256+id];
        if(opcode==9) {
            if(value>=q) {status[id]=1;return;}
            output[id]=(value*factor)%q;
        } else {
            if(factor && value==0x8000000000000000ul) {status[id]=2;return;}
            output[id]=factor?0ul-value:value;
        }
    }
}
