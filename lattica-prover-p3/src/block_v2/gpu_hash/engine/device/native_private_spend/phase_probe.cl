/* FEATURE native-spend-oracle ONLY. Appended after the actual production bundle.
 * This kernel is observational: all production arena/RNG/status arguments are
 * const. It writes only the separately admitted private record/control buffers.
 */
#define PQ_PHASE_RECORD_WORDS 7ul
#define PQ_PHASE_MAX_RECORDS 131074ul

inline void pq_phase_record(__global const uchar *src,ulong bytes,
    uint phase,uint component,ulong blocks,__global ulong *records,
    ulong capacity,__global ulong *control) {
    if(control[1])return;
    ulong index=control[0];
    if(index>=capacity){control[1]=1ul;return;}
    __global ulong *record=records+index*PQ_PHASE_RECORD_WORDS;
    record[0]=((ulong)component<<32)|(ulong)phase;
    record[1]=bytes;
    pq_spend_shake(src,bytes,(__global uchar*)(record+2),32ul);
    record[6]=blocks;
    control[0]=index+1;
}

__kernel void pq_phase_capture(__global const ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,
    __global const pq_private_rng_state *rng,__global const uint *status,
    __global ulong *records,ulong record_words,ulong capacity,
    __global ulong *control,ulong control_words,uint step) {
    if(get_global_id(0)!=0)return;
    if(control_words!=4ul)return; /* host binds the fixed four-word allocation */
    if(control[1])return;
    if(!capacity || capacity>PQ_PHASE_MAX_RECORDS ||
       record_words!=capacity*PQ_PHASE_RECORD_WORDS ||
       slot_count!=PQ_SPEND_SLOT_COUNT || status[0] || status[1]>1u ||
       rng[0].status || rng[0].next_counter>0x100000000ul) {
        control[1]=1ul;return;
    }
    for(uint i=3;i<16;++i)if(status[i]){control[1]=1ul;return;}
    for(uint i=0;i<PQ_SPEND_SLOT_COUNT;++i) {
        if(offsets[i]>arena_words || pq_spend_slot_words[i]>arena_words-offsets[i]) {
            control[1]=1ul;return;
        }
        for(uint j=0;j<i;++j)if(offsets[i]<offsets[j]+pq_spend_slot_words[j] &&
            offsets[j]<offsets[i]+pq_spend_slot_words[i]) {control[1]=1ul;return;}
    }
    uint phase=0,count=0;
    if(step==5u){phase=30u;count=2u;}
    else if(step==6u){phase=35u;count=1u;}
    else if(step==14u){phase=40u;count=4u;}
    else if(step==18u){phase=50u;count=4u;}
    else if(step==20u){phase=60u;count=2u;}
    else if(step==22u){phase=70u;count=2u;}
    else if(step==24u){phase=80u;count=1u;}
    else {control[1]=1ul;return;}
    if(status[2]!=phase || ((step==5u || step==6u || step==18u) && status[1]) ||
       control[0]>capacity || (ulong)count>capacity-control[0] ||
       (step==5u && control[0]!=0ul)) {control[1]=1ul;return;}
    __global const pq_spend_proof *proof=(__global const pq_spend_proof*)
        (arena+offsets[PQ_SPEND_SLOT_OUT]);
    ulong blocks=rng[0].next_counter;
    /* Native rej is uint64_t with values0/1. Challenge expansion uses its own
     * stream; after-step40 data and private_blocks equal all four C checkpoints.
     */
    control[2]=(ulong)status[1];
    if(step==5u) {
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_CN_OUT]),20480ul,
            30u,1u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_CK_OUT]),36864ul,
            30u,2u,blocks,records,capacity,control);
    } else if(step==6u) {
        pq_phase_record((__global const uchar*)(control+2),8ul,35u,0u,blocks,records,capacity,control);
    } else if(step==14u) {
        pq_phase_record(proof->alpha,32ul,40u,1u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_A]),24576ul,
            40u,2u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_RHO]),22528ul,
            40u,3u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(control+2),8ul,40u,4u,blocks,records,capacity,control);
    } else if(step==18u) {
        pq_phase_record((__global const uchar*)&proof->x,2048ul,50u,1u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_RB]),20480ul,
            50u,2u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_RA]),20480ul,
            50u,3u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(arena+offsets[PQ_SPEND_SLOT_Y]),16384ul,
            50u,4u,blocks,records,capacity,control);
    } else if(step==20u) {
        pq_phase_record((__global const uchar*)proof->f1,22528ul,60u,1u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(control+2),8ul,60u,2u,blocks,records,capacity,control);
    } else if(step==22u) {
        pq_phase_record((__global const uchar*)proof->z,16384ul,70u,1u,blocks,records,capacity,control);
        pq_phase_record((__global const uchar*)(control+2),8ul,70u,2u,blocks,records,capacity,control);
    } else {
        pq_phase_record((__global const uchar*)(control+2),8ul,80u,1u,blocks,records,capacity,control);
    }
    ((__global volatile ulong*)control)[2]=0;
    control[3]=(ulong)step;
}
