//! SSA execution waves and the unchanged recursive AIR row layouts.
pub(crate) const KERNEL_SRC: &str = r#"
__kernel void device_witness_public(__global const ulong *input, __global ulong *wires, uint count) {
    uint i = get_global_id(0); if (i < count) wires[i] = input[i];
}
inline void device_witness_instruction(__global const ulong *program, uint instruction,
    __global const ulong *input, __global ulong *wires, __global uint *status,
    __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    __global const ulong *c = program + program[16] + (size_t)instruction*18;
    ulong a[3], b[3], result[3], s[8], value = 0;
    uint index = 0;
    switch ((uint)c[0]) {
    case 0: wires[c[1]] = input[program[14]+c[2]]; break;
    case 1: wires[c[1]] = c[2]; break;
    case 2: wires[c[1]] = gl_canon(gl_add(wires[c[2]],wires[c[3]])); break;
    case 3: wires[c[1]] = gl_canon(gl_mul(wires[c[2]],wires[c[3]])); break;
    case 4: if (wires[c[1]] != wires[c[2]]) atomic_or(status,1U); break;
    case 5: value = wires[c[1]]; if (value != 0 && value != 1) atomic_or(status,1U); break;
    case 6:
        value = wires[c[2]]; if (value == 0) atomic_or(status,1U);
        wires[c[1]] = gl_canon(gl_inverse(value)); break;
    case 7:
        value = wires[c[2]]; if (value != 0 && value != 1) atomic_or(status,1U);
        wires[c[1]] = value == 1 ? wires[c[4]] : wires[c[3]]; break;
    case 8:
        for (uint j=0;j<8;++j) s[j] = wires[c[1+j]];
        perm8(s,rci,rcp,rcf,diag);
        for (uint j=0;j<8;++j) wires[c[9+j]] = gl_canon(s[j]); break;
    case 9:
        for (uint j=0;j<3;++j) { a[j] = wires[c[4+j]]; b[j] = wires[c[7+j]]; }
        opening_cubic_mul(a,b,result);
        for (uint j=0;j<3;++j) wires[c[1+j]] = gl_canon(result[j]); break;
    case 10:
        for (uint j=0;j<3;++j) a[j] = wires[c[4+j]];
        if (a[0]==0 && a[1]==0 && a[2]==0) atomic_or(status,1U);
        lookup_cubic_inverse(a,result);
        for (uint j=0;j<3;++j) wires[c[1+j]] = gl_canon(result[j]); break;
    case 11: wires[c[1]] = (wires[c[2]] >> c[3]) & 1UL; break;
    case 12:
        for (uint j=0;j<c[3];++j) {
            value = wires[program[c[2]+j]];
            if (value != 0 && value != 1) atomic_or(status,1U);
            index |= (uint)(value == 1) << j;
        }
        wires[c[1]] = wires[program[c[2]+c[3]+index]]; break;
    }
}
__kernel void device_witness_wave(__global const ulong *program, uint first, uint count,
    __global const ulong *input, __global ulong *wires, __global uint *status,
    __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    uint i = get_global_id(0); if (i >= count) return;
    device_witness_instruction(program, first+i, input, wires, status, rci, rcp, rcf, diag);
}

// Exactly one workgroup executes at most 64 dependency levels. Global-memory
// barriers publish SSA wire writes before the next level reads them. Bounds are
// uniform across the group, including malformed-marker rejection paths.
__kernel __attribute__((reqd_work_group_size(128, 1, 1)))
void device_witness_fused(__global const ulong *program, uint first, uint end,
    __global const ulong *input, __global ulong *wires, __global uint *status,
    __global const ulong *rci, __global const ulong *rcp, __global const ulong *rcf, __global const ulong *diag) {
    uint lane = get_local_id(0);
    for (uint wave = 0; wave < 64 && first < end; ++wave) {
        ulong count = program[program[16] + (size_t)first*18 + 17];
        if (count == 0 || count > 128 || count > (ulong)(end-first)) {
            if (lane == 0) atomic_or(status, 1U);
            return;
        }
        if (lane < count)
            device_witness_instruction(program, first+lane, input, wires, status, rci, rcp, rcf, diag);
        barrier(CLK_GLOBAL_MEM_FENCE);
        first += (uint)count;
    }
    if (first != end && lane == 0) atomic_or(status, 1U);
}

inline uint witness_port(uint port, uint lane, uint lanes) {
    return lane < 8 ? port*8+lane : 32+port*(lanes-8)+lane-8;
}
inline uint witness_hash_column(uint column) {
    return column < 8 ? 8+column : column < 16 ? 24+column-8 : 32+column-16;
}
__kernel void device_witness_rows(__global const ulong *program, __global const ulong *wires,
    __global ulong *trace, __global const ulong *rci, __global const ulong *rcp,
    __global const ulong *rcf, __global const ulong *diag) {
    uint row = get_global_id(0); if (row >= program[0]) return;
    __global ulong *t = trace+(size_t)row*program[2];
    for (uint j=0;j<program[2];++j) t[j]=0;
    if (row >= program[1]) return;
    __global const ulong *r = program+program[18]+(size_t)row*4;
    if (r[0] == 4) return;
    __global const ulong *ports = program+program[19]+r[1]*7;
    if (r[0] != 3) {
        for (uint lane=0;lane<r[2];++lane) {
            __global const ulong *p=ports+(size_t)lane*7;
            for (uint k=0;k<4;++k) if (p[1+k]) t[witness_port(k,lane,(uint)program[4])]=wires[p[1+k]-1];
        }
        return;
    }
    ulong s[8]; for (uint j=0;j<8;++j) { s[j]=wires[ports[j*7+1]-1]; t[j]=s[j]; }
    uint column=0; extl(s);
    for (uint r=0;r<4;++r) {
        for (uint j=0;j<8;++j) s[j]=gl_pow7(gl_add(s[j],rci[r*8+j])); extl(s);
        for (uint j=0;j<8;++j) t[witness_hash_column(column++)]=gl_canon(s[j]);
    }
    for (uint r=0;r<22;++r) {
        s[0]=gl_pow7(gl_add(s[0],rcp[r])); t[witness_hash_column(column++)]=gl_canon(s[0]); intl(s,diag);
    }
    for (uint r=0;r<4;++r) {
        for (uint j=0;j<8;++j) s[j]=gl_pow7(gl_add(s[j],rcf[r*8+j])); extl(s);
        for (uint j=0;j<8;++j) t[r==3 ? 16+j : witness_hash_column(column++)]=gl_canon(s[j]);
    }
}
__kernel void device_preprocessing_rows(__global const ulong *program, __global ulong *output) {
    uint row=get_global_id(0); if (row>=program[0]) return;
    __global ulong *t=output+(size_t)row*program[3];
    for (uint j=0;j<program[3];++j) t[j]=0;
    for (uint lane=0;lane<program[4];++lane) t[lane*3]=1;
    if (row>=program[1]) return;
    __global const ulong *r=program+program[18]+(size_t)row*4;
    if (r[0]==4) {
        t[program[13]]=r[3]+1;
        for (uint lane=0;lane<program[4];++lane) t[lane*3]=0;
        for (uint j=0;j<32;++j) if (r[3]*32+j<program[14]) t[program[5]+j]=program[program[20]+r[3]*32+j];
        return;
    }
    if (r[0]==3) {
        t[program[10]]=1;
        for (uint lane=0;lane<program[4];++lane) t[lane*3]=0;
    }
    __global const ulong *ports=program+program[19]+r[1]*7;
    for (uint lane=0;lane<r[2];++lane) {
        __global const ulong *p=ports+(size_t)lane*7;
        uint op=(uint)p[0], code=op<8 ? op : 0;
        for (uint bit=0;bit<3;++bit) t[lane*3+bit]=(code>>bit)&1U;
        for (uint k=0;k<4;++k) t[program[5+k]+lane]=p[1+k];
        t[program[9]+lane]=p[5];
        if (op==1) t[program[6]+lane]=p[6];
        if (op==9 || op==10) t[program[op==9 ? 11 : 12]+lane/3]=1;
    }
}
"#;
