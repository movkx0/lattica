// One bounded stream, no AIR trace allocation or readback. Canonical field
// validation is performed here even for the empty-stream identity operation.
__kernel void pq_operation_commit_fields(__global const ulong *raw,
    uint count, uint begin, __global const ulong *initial, __global ulong *output,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    ulong state[8];
    if(begin==0) {
        output[4]=0;
        for(uint j=0;j<4;++j) {output[j]=0;state[j]=initial[j];}
        for(uint j=0;j<4;++j) if(state[j]>=GP) {output[4]=1;return;}
    } else {
        if(output[4]!=0)return;
        for(uint j=0;j<4;++j)state[j]=output[j];
    }
    // The host launches consecutive aligned tiles on one queue. State remains
    // in device memory; no long unbounded single-work-item hash launch occurs.
    uint end=min(count,begin+4096u);
    for(uint j=begin;j<end;++j) if(raw[j]>=GP) {output[4]=2;return;}
    for(uint offset=begin;offset<end;offset+=4) {
        for(uint j=0;j<4;++j) state[4+j]=offset+j<end?raw[offset+j]:0;
        pq_poseidon_permute(state,rci,rcp,rcf,diag);
    }
    for(uint j=0;j<4;++j) output[j]=gl_canon(state[j]);
}

// Each descriptor is offset,count,initial[4]. A stream's recurrence remains
// serial and tile ordered; different streams have disjoint roots and status.
__kernel void pq_operation_commit_fields_batch(__global const ulong *raw,
    __global const ulong *descriptors, uint streams, uint begin,
    __global ulong *roots, __global ulong *status,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    uint stream = get_global_id(0);
    if (stream >= streams) return;
    ulong offset = descriptors[6*stream], count = descriptors[6*stream+1];
    ulong state[8];
    if (begin == 0) {
        status[stream] = 0;
        if (streams > 64 || offset > 131072UL || count > 131072UL-offset) {
            status[stream] = 1; return;
        }
        for (uint j=0;j<4;++j) {
            state[j] = descriptors[6*stream+2+j];
            if (state[j] >= GP) { status[stream] = 2; return; }
            roots[4*stream+j] = state[j];
        }
    } else {
        if (status[stream] != 0 || begin >= count) return;
        for (uint j=0;j<4;++j) state[j] = roots[4*stream+j];
    }
    uint end = (uint)min(count,(ulong)begin+4096UL);
    for (uint j=begin;j<end;++j) if (raw[offset+j] >= GP) {
        status[stream] = 3; return;
    }
    for (uint at=begin;at<end;at+=4) {
        for (uint j=0;j<4;++j) state[4+j] = at+j<end ? raw[offset+at+j] : 0;
        pq_poseidon_permute(state,rci,rcp,rcf,diag);
    }
    for (uint j=0;j<4;++j) roots[4*stream+j] = gl_canon(state[j]);
}

// Every lane participates in validation and every permutation exchange. The
// eight-item workgroup matches public_hash_exchange's NVIDIA member mask.
inline uint pq_fields_invalid(uint invalid, uint lane, __local ulong *words) {
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
    invalid |= (uint)public_hash_exchange((ulong)invalid, lane ^ 1u);
    invalid |= (uint)public_hash_exchange((ulong)invalid, lane ^ 2u);
    invalid |= (uint)public_hash_exchange((ulong)invalid, lane ^ 4u);
#else
    words[lane] = invalid;
    barrier(CLK_LOCAL_MEM_FENCE);
    invalid = 0;
    for (uint i=0; i<8; ++i) invalid |= (uint)words[i];
    barrier(CLK_LOCAL_MEM_FENCE);
#endif
    return invalid;
}
inline ulong pq_fields_permute(ulong value, uint lane, ulong diagonal,
    __local ulong *words, __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf) {
    value = public_hash_external(value, lane, words);
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
    for (uint r=0; r<4; ++r) {
        value = gl_pow7(gl_add(value, rci[8*r+lane]));
        value = public_hash_external(value, lane, words);
    }
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
    for (uint r=0; r<22; ++r) {
        if (lane == 0) value = gl_pow7(gl_add(value, rcp[r]));
        value = public_hash_internal(value, lane, diagonal, words);
    }
#if defined(LATTICA_PUBLIC_HASH_NVIDIA_SHUFFLE)
#pragma unroll
#endif
    for (uint r=0; r<4; ++r) {
        value = gl_pow7(gl_add(value, rcf[8*r+lane]));
        value = public_hash_external(value, lane, words);
    }
    // pq_poseidon_permute canonicalizes after EVERY rate-four absorption.
    return gl_canon(value);
}
__attribute__((reqd_work_group_size(8, 1, 1)))
__kernel void pq_operation_commit_fields_cooperative(__global const ulong *raw,
    uint count, uint begin, __global const ulong *initial, __global ulong *output,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    const uint lane = get_local_id(0);
    __local ulong words[8];
    if (begin != 0 && output[4] != 0) return; // uniform across the group
    ulong value = lane < 4 ? (begin == 0 ? initial[lane] : output[lane]) : 0;
    const uint end = min(count, begin + 4096u);
    uint invalid = begin == 0 && value >= GP ? 1u : 0u;
    for (uint i=begin+lane; i<end; i+=8) if (raw[i] >= GP) invalid |= 2u;
    invalid = pq_fields_invalid(invalid, lane, words);
    if (lane == 0) output[4] = (invalid & 1u) ? 1u : (invalid ? 2u : 0u);
    if (invalid) return; // reduction makes all error exits collective
    const ulong diagonal = diag[lane];
    for (uint at=begin; at<end; at+=4) {
        if (lane >= 4) value = at+lane-4 < end ? raw[at+lane-4] : 0;
        value = pq_fields_permute(value, lane, diagonal, words, rci, rcp, rcf);
    }
    if (lane < 4) output[lane] = value;
}
__attribute__((reqd_work_group_size(8, 1, 1)))
__kernel void pq_operation_commit_fields_batch_cooperative(__global const ulong *raw,
    __global const ulong *descriptors, uint streams, uint begin,
    __global ulong *roots, __global ulong *status,
    __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    const uint stream = get_group_id(0), lane = get_local_id(0);
    __local ulong words[8];
    if (stream >= streams) return;
    const ulong offset = descriptors[6*stream], count = descriptors[6*stream+1];
    if (streams > 64 || offset > 131072UL || count > 131072UL-offset) {
        if (lane == 0) status[stream] = 1;
        return;
    }
    if (begin != 0 && (status[stream] != 0 || begin >= count)) return;
    ulong value = lane < 4 ? (begin == 0 ? descriptors[6*stream+2+lane] : roots[4*stream+lane]) : 0;
    const uint end = (uint)min(count, (ulong)begin+4096UL);
    uint invalid = begin == 0 && value >= GP ? 1u : 0u;
    for (uint i=begin+lane; i<end; i+=8) if (raw[offset+i] >= GP) invalid |= 2u;
    invalid = pq_fields_invalid(invalid, lane, words);
    if (lane == 0) status[stream] = (invalid & 1u) ? 2u : (invalid ? 3u : 0u);
    if (invalid) return;
    const ulong diagonal = diag[lane];
    for (uint at=begin; at<end; at+=4) {
        if (lane >= 4) value = at+lane-4 < end ? raw[offset+at+lane-4] : 0;
        value = pq_fields_permute(value, lane, diagonal, words, rci, rcp, rcf);
    }
    if (lane < 4) roots[4*stream+lane] = value;
}
