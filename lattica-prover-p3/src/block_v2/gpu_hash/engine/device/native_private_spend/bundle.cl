#pragma OPENCL FP_CONTRACT OFF
// begin private_rng.clh
#ifndef PQ_MATRICT_PRIVATE_RNG_CLH
#define PQ_MATRICT_PRIVATE_RNG_CLH
// ISOLATED UNCOMPILED CANDIDATE. No claim of constant-time generated ISA.
// All coefficient words are two's-complement signed values represented as ulong.
typedef struct { ulong poly[256]; } pq_private_poly;
typedef struct {
    uchar roundkeys[240];
    ulong next_counter;       // 0..2^32 inclusive; 2^32 means exhausted.
    ulong status;             // Sticky fatal code; not normal proof rejection.
    ulong random_calls;
    ulong random_call_limit;
    ulong proposals;
    ulong proposal_limit;
} pq_private_rng_state;       // Proposed ABI: 288 bytes, alignment 8.
typedef char pq_private_rng_abi_size[(sizeof(pq_private_rng_state)==288)?1:-1];
#define PQ_PRIVATE_OK 0u
#define PQ_PRIVATE_BAD_INPUT 1u
#define PQ_PRIVATE_COUNTER_EXHAUSTED 16u
#define PQ_PRIVATE_UNIFORM_EXHAUSTED 32u
#define PQ_PRIVATE_BUDGET_EXHAUSTED 32u
#define PQ_PRIVATE_NUMERIC_CONTRACT 128u
#define PQ_PRIVATE_COUNTER_END 0x100000000UL
inline uint pq_private_error_code(ulong state_status) {
    // Preserve known ABI bits and fail closed if an opaque state is corrupted.
    return (uint)(state_status & 255UL)
        | ((state_status & ~255UL) ? PQ_PRIVATE_NUMERIC_CONTRACT : 0u);
}

inline void pq_private_poison(__private pq_private_rng_state *rng, uint code) {
    rng->status |= code;
}
inline void pq_private_publish(__global uint *status, uint job, uint code) {
    if (code != 0) atomic_or((volatile __global uint *)(status + 16UL * job), code);
}
inline uchar pq_private_gf_mul(uchar a, uchar b) {
    uchar product = 0;
    for (uint i = 0; i < 8; ++i) {
        product ^= a & (uchar)(0u - (uint)(b & 1));
        uchar high = a >> 7;
        a = (uchar)((a << 1) ^ (0x1bu & (0u - (uint)high)));
        b >>= 1;
    }
    return product;
}
inline uchar pq_private_rotl_byte(uchar x, uint n) {
    return (uchar)((x << n) | (x >> (8u - n)));
}
inline uchar pq_private_aes_sbox(uchar x) {
    // x^254 in GF(2^8), including 0 -> 0. Fixed operations, no lookup table.
    uchar a2 = pq_private_gf_mul(x, x);
    uchar a4 = pq_private_gf_mul(a2, a2);
    uchar a8 = pq_private_gf_mul(a4, a4);
    uchar a16 = pq_private_gf_mul(a8, a8);
    uchar a32 = pq_private_gf_mul(a16, a16);
    uchar a64 = pq_private_gf_mul(a32, a32);
    uchar a128 = pq_private_gf_mul(a64, a64);
    uchar inverse = pq_private_gf_mul(a2, a4);
    inverse = pq_private_gf_mul(inverse, a8);
    inverse = pq_private_gf_mul(inverse, a16);
    inverse = pq_private_gf_mul(inverse, a32);
    inverse = pq_private_gf_mul(inverse, a64);
    inverse = pq_private_gf_mul(inverse, a128);
    return inverse ^ pq_private_rotl_byte(inverse, 1) ^ pq_private_rotl_byte(inverse, 2)
        ^ pq_private_rotl_byte(inverse, 3) ^ pq_private_rotl_byte(inverse, 4) ^ (uchar)0x63;
}
inline void pq_private_expand_loaded_key(__private pq_private_rng_state *rng) {
    uchar rcon = 1;
    for (uint word = 8; word < 60; ++word) {
        uchar t[4];
        for (uint j = 0; j < 4; ++j) t[j] = rng->roundkeys[4 * (word - 1) + j];
        if ((word & 7u) == 0) {
            uchar first = t[0];
            t[0] = pq_private_aes_sbox(t[1]) ^ rcon;
            t[1] = pq_private_aes_sbox(t[2]);
            t[2] = pq_private_aes_sbox(t[3]);
            t[3] = pq_private_aes_sbox(first);
            rcon = pq_private_gf_mul(rcon, 2);
        } else if ((word & 7u) == 4) {
            for (uint j = 0; j < 4; ++j) t[j] = pq_private_aes_sbox(t[j]);
        }
        for (uint j = 0; j < 4; ++j)
            rng->roundkeys[4 * word + j] = rng->roundkeys[4 * (word - 8) + j] ^ t[j];
        volatile __private uchar *wipe_t = t;
        for (uint j = 0; j < 4; ++j) wipe_t[j] = 0;
    }
}
inline void pq_private_expand_key(__private pq_private_rng_state *rng, __global const uchar *key) {
    for(uint i=0;i<32;++i) rng->roundkeys[i]=key[i];
    pq_private_expand_loaded_key(rng);
}
inline int pq_private_expand_key_words(__private pq_private_rng_state *rng, __global const ulong *key) {
    ulong invalid=0;
    for(uint i=0;i<32;++i) { invalid |= key[i]>>8; rng->roundkeys[i]=(uchar)key[i]; }
    if(invalid) { pq_private_poison(rng,PQ_PRIVATE_BAD_INPUT); return 0; }
    pq_private_expand_loaded_key(rng);
    return 1;
}
inline void pq_private_aes_encrypt16(__private const pq_private_rng_state *rng,
                                     __private const uchar input[16], __private uchar out[16]) {
    uchar state[16], shift[16];
    for (uint i = 0; i < 16; ++i)
        state[i] = rng->roundkeys[i] ^ input[i];
    for (uint round = 1; round <= 14; ++round) {
        for (uint column = 0; column < 4; ++column)
            for (uint row = 0; row < 4; ++row)
                shift[4 * column + row] = pq_private_aes_sbox(state[4 * ((column + row) & 3u) + row]);
        for (uint column = 0; column < 4; ++column) {
            uint at = 4 * column;
            uchar a = shift[at], b = shift[at + 1], c = shift[at + 2], d = shift[at + 3];
            if (round != 14) {
                uchar all = a ^ b ^ c ^ d;
                state[at] = a ^ all ^ pq_private_gf_mul(a ^ b, 2);
                state[at + 1] = b ^ all ^ pq_private_gf_mul(b ^ c, 2);
                state[at + 2] = c ^ all ^ pq_private_gf_mul(c ^ d, 2);
                state[at + 3] = d ^ all ^ pq_private_gf_mul(d ^ a, 2);
            } else {
                state[at] = a; state[at + 1] = b; state[at + 2] = c; state[at + 3] = d;
            }
        }
        for (uint i = 0; i < 16; ++i) state[i] ^= rng->roundkeys[16 * round + i];
    }
    for (uint i = 0; i < 16; ++i) out[i] = state[i];
    volatile __private uchar *wipe_state = state, *wipe_shift = shift;
    for (uint i = 0; i < 16; ++i) { wipe_state[i] = 0; wipe_shift[i] = 0; }
}
inline void pq_private_aes_block_domain(__private const pq_private_rng_state *rng,
                                        uint counter, ulong domain, __private uchar out[16]) {
    uchar input[16];
    for (uint i = 0; i < 16; ++i) input[i] = 0;
    for (uint i = 0; i < 4; ++i) input[i] = (uchar)(counter >> (8 * i));
    for (uint i = 0; i < 8; ++i) input[8 + i] = (uchar)(domain >> (8 * i));
    pq_private_aes_encrypt16(rng, input, out);
}
inline int pq_private_random_bytes_domain(__private pq_private_rng_state *rng,
                                          __private uchar *out, ulong count, ulong domain) {
    if (rng->status) return 0;
    if (count > 0xfffffffffffffff0UL) { pq_private_poison(rng, PQ_PRIVATE_BAD_INPUT); return 0; }
    ulong blocks = (count + 15UL) >> 4;
    if (rng->next_counter > PQ_PRIVATE_COUNTER_END || blocks > PQ_PRIVATE_COUNTER_END - rng->next_counter) {
        pq_private_poison(rng, PQ_PRIVATE_COUNTER_EXHAUSTED); return 0;
    }
    if (rng->random_calls >= rng->random_call_limit) {
        pq_private_poison(rng, PQ_PRIVATE_BUDGET_EXHAUSTED); return 0;
    }
    ++rng->random_calls;
    uchar block[16];
    for (ulong b = 0; b < blocks; ++b) {
        pq_private_aes_block_domain(rng, (uint)rng->next_counter, domain, block);
        ++rng->next_counter;
        for (uint j = 0; j < 16; ++j) if (16 * b + j < count) out[16 * b + j] = block[j];
    }
    // Unused suffix of final block is discarded, exactly as reference calls.
    volatile __private uchar *wipe = block;
    for (uint i = 0; i < 16; ++i) wipe[i] = 0;
    return 1;
}
inline int pq_private_random_bytes(__private pq_private_rng_state *rng,
                                   __private uchar *out, ulong count) {
    return pq_private_random_bytes_domain(rng, out, count, 0UL);
}
inline void pq_private_wipe_local(__private void *pointer, uint bytes) {
    volatile __private uchar *wipe=(volatile __private uchar *)pointer;
    for(uint i=0;i<bytes;++i) wipe[i]=0;
}
inline void pq_private_clear_rng(__private pq_private_rng_state *rng) {
    volatile __private uchar *wipe = (volatile __private uchar *)rng;
    for (uint i = 0; i < sizeof(pq_private_rng_state); ++i) wipe[i] = 0;
}
#endif

// end private_rng.clh
// begin private_sampling.clh
#ifndef PQ_MATRICT_PRIVATE_SAMPLING_CLH
#define PQ_MATRICT_PRIVATE_SAMPLING_CLH
// begin reference_gaussian.clh
// GENERATED isolated candidate: reference arithmetic port, uncompiled/unqualified.
#ifndef PQ_MATRICT_REFERENCE_GAUSSIAN_CLH
#define PQ_MATRICT_REFERENCE_GAUSSIAN_CLH

// begin reference_intrinsics.clh
#ifndef PQ_MATRICT_REFERENCE_INTRINSICS_CLH
#define PQ_MATRICT_REFERENCE_INTRINSICS_CLH
#ifndef cl_khr_fp64
#error Native MatRiCT Gaussian candidate requires cl_khr_fp64
#endif
#pragma OPENCL EXTENSION cl_khr_fp64 : enable
#pragma OPENCL FP_CONTRACT OFF
// Source-level SSE/AVX semantics. No exp/native_exp/fast relaxed math.
typedef uchar uint8_t;
typedef uint uint32_t;
typedef ulong uint64_t;
typedef long int64_t;
typedef ulong4 pq_i4;
typedef double4 pq_d4;
typedef ulong2 pq_i2;
typedef double2 pq_d2;
#define PQ_REF_UINT64_C(x) x##UL
inline pq_i4 pq_mm256_setzero_si256(void) { return (pq_i4)(0); }
inline pq_i4 pq_mm256_add_epi64(pq_i4 a,pq_i4 b) { return a+b; }
inline pq_i4 pq_mm256_sub_epi64(pq_i4 a,pq_i4 b) { return a-b; }
inline pq_i4 pq_mm256_and_si256(pq_i4 a,pq_i4 b) { return a&b; }
inline pq_i4 pq_mm256_or_si256(pq_i4 a,pq_i4 b) { return a|b; }
inline pq_i4 pq_mm256_cmpeq_epi64(pq_i4 a,pq_i4 b) { return as_ulong4(a==b); }
inline pq_i4 pq_mm256_mul_epu32(pq_i4 a,pq_i4 b) { return (a&0xffffffffUL)*(b&0xffffffffUL); }
inline pq_i4 pq_mm256_slli_epi64(pq_i4 a,uint n) { return n<64?a<<n:(pq_i4)(0); }
inline pq_i4 pq_mm256_srli_epi64(pq_i4 a,uint n) { return n<64?a>>n:(pq_i4)(0); }
inline pq_i4 pq_mm256_sllv_epi64(pq_i4 a,pq_i4 n) {
    return select(a<<(n&63UL),(pq_i4)(0),as_ulong4(n>=(pq_i4)(64)));
}
inline pq_i4 pq_mm256_set_epi64x(ulong d,ulong c,ulong b,ulong a) { return (pq_i4)(a,b,c,d); }
inline pq_i4 pq_mm256_load_si256(__private const ulong *p) { return vload4(0,p); }
inline pq_i4 pq_mm256_loadu_si256(__private const uchar *bytes) {
    ulong words[4] = {0,0,0,0};
    for (uint i=0;i<4;++i) for (uint j=0;j<8;++j) words[i] |= (ulong)bytes[8*i+j]<<(8*j);
    return (pq_i4)(words[0],words[1],words[2],words[3]);
}
inline void pq_mm256_store_si256(__private ulong *p,pq_i4 v) { vstore4(v,0,p); }
inline pq_d4 pq_mm256_castsi256_pd(pq_i4 a) { return as_double4(a); }
inline pq_i4 pq_mm256_castpd_si256(pq_d4 a) { return as_ulong4(a); }
inline pq_d4 pq_mm256_add_pd(pq_d4 a,pq_d4 b) { return a+b; }
inline pq_d4 pq_mm256_sub_pd(pq_d4 a,pq_d4 b) { return a-b; }
inline pq_d4 pq_mm256_mul_pd(pq_d4 a,pq_d4 b) { return a*b; }
inline pq_d4 pq_mm256_floor_pd(pq_d4 a) { return floor(a); }
inline pq_d4 pq_mm256_fmadd_pd(pq_d4 a,pq_d4 b,pq_d4 c) { return fma(a,b,c); }
inline pq_d2 pq_mm_setzero_pd(void) { return (pq_d2)(0.0); }
inline pq_i2 pq_mm_add_epi64(pq_i2 a,pq_i2 b) { return a+b; }
inline pq_i2 pq_mm_slli_epi64(pq_i2 a,uint n) { return n<64?a<<n:(pq_i2)(0); }
inline pq_d2 pq_mm_castsi128_pd(pq_i2 a) { return as_double2(a); }
inline pq_i2 pq_mm_castpd_si128(pq_d2 a) { return as_ulong2(a); }
inline pq_i2 pq_mm_cvtsi64x_si128(ulong a) { return (pq_i2)(a,0); }
inline pq_d2 pq_mm_cvtsi64_sd(pq_d2 a,ulong bits) { return (pq_d2)(convert_double_rte(as_long(bits)),a.s1); }
inline pq_d2 pq_mm_add_sd(pq_d2 a,pq_d2 b) { return (pq_d2)(a.s0+b.s0,a.s1); }
inline pq_d2 pq_mm_sub_sd(pq_d2 a,pq_d2 b) { return (pq_d2)(a.s0-b.s0,a.s1); }
inline pq_d2 pq_mm_mul_sd(pq_d2 a,pq_d2 b) { return (pq_d2)(a.s0*b.s0,a.s1); }
inline pq_d2 pq_mm_floor_pd(pq_d2 a) { return floor(a); }
inline uint pq_sse_i32_bits(double x) {
    double rounded=rint(x);
    if (!isfinite(rounded) || rounded < -2147483648.0 || rounded > 2147483647.0) return 0x80000000u;
    return as_uint(convert_int_rte(rounded));
}
inline pq_i2 pq_mm_cvtpd_epi32(pq_d2 a) {
    return (pq_i2)((ulong)pq_sse_i32_bits(a.s0)|((ulong)pq_sse_i32_bits(a.s1)<<32),0);
}
inline void pq_mm_storel_epi64(__private ulong *p,pq_i2 a) { *p=a.s0; }
inline ulong pq_ref_ct_lt(ulong x,ulong y) { return (x-y)>>63; }
inline ulong pq_ref_ct_eq(ulong x,ulong y) { return 1^(((x-y)|(y-x))>>63); }
inline ulong pq_ref_load_64(__private const uchar *p) {
    ulong result=0; for(uint i=0;i<8;++i) result|=(ulong)p[i]<<(8*i); return result;
}
inline ulong pq_ref_load_24(__private const uchar *p) { return (ulong)p[0]|((ulong)p[1]<<8)|((ulong)p[2]<<16); }
inline ulong pq_ref_load_32(__private const uchar *p) { return pq_ref_load_24(p)|((ulong)p[3]<<24); }
inline ulong pq_ref_load_40(__private const uchar *p) { return pq_ref_load_32(p)|((ulong)p[4]<<32); }
#endif

// end reference_intrinsics.clh

#define PQ_MS_CRYPTO_BYTES 32L
#define PQ_MS_M 2L
#define PQ_MS_S 2L
#define PQ_MS_N_SPENT 10L
#define PQ_MS_W 44L
#define PQ_MS_WA 39L
#define PQ_MS_N 4L
#define PQ_MS_K 4L
#define PQ_MS_N_BAR 4L
#define PQ_MS_N_HAT 5L
#define PQ_MS_K_HAT 5L
#define PQ_MS_B_K 7525L
#define PQ_MS_BA_10_K 111L
#define PQ_MS_BETA 40L
#define PQ_MS_BRS_13_K 1219127L
#define PQ_MS_BG_0 6825771L
#define PQ_MS_BG_1 1137628L
#define PQ_MS_B_6 38346L
#define PQ_MS_BA_10_6 565L
#define PQ_MS_BRS_13_6 6212586L
#define PQ_MS_D 256L


#define PQ_MS_CDT_ENTRY_SIZE 16
#define PQ_MS_CDT_LOW_MASK 0x7fffffffffffffff
#define PQ_MS_CDT_LENGTH 9 /* [0..tau*sigma]=[0..9] */

#define PQ_MS_BERNOULLI_ENTRY_SIZE 9 /* 72bit randomness */

/* -1/k^2 */
#define PQ_MS_BINARY_SAMPLER_B_K_2_INV (-0x1.2f64d69a1162ap-26)
#define PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV (-0x1.546b4b9161626p-14)
#define PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV (-0x1.7ac44c0d0bbc6p-41)

#define PQ_MS_EXP_MANTISSA_PRECISION 52
#define PQ_MS_EXP_MANTISSA_MASK ((1L << PQ_MS_EXP_MANTISSA_PRECISION) - 1)
#define PQ_MS_R_MANTISSA_PRECISION (PQ_MS_EXP_MANTISSA_PRECISION + 1)
#define PQ_MS_R_MANTISSA_MASK ((1L << PQ_MS_R_MANTISSA_PRECISION) - 1)
#define PQ_MS_R_EXPONENT_L (8 * PQ_MS_BERNOULLI_ENTRY_SIZE - PQ_MS_R_MANTISSA_PRECISION)

#define PQ_MS_DOUBLE_ONE (1023L << 52)

#define PQ_MS_UNIFORM_SIZE_B_K 4
#define PQ_MS_UNIFORM_REJ_B_K 23
#define PQ_MS_BARRETT_BITSHIFT_B_K (PQ_MS_UNIFORM_SIZE_B_K * 8)
#define PQ_MS_BARRETT_FACTOR_B_K ((1L << PQ_MS_BARRETT_BITSHIFT_B_K) / PQ_MS_B_K)
#define PQ_MS_UNIFORM_Q_B_K (PQ_MS_B_K * PQ_MS_BARRETT_FACTOR_B_K)

#define PQ_MS_UNIFORM_SIZE_BA_10_K 3
#define PQ_MS_UNIFORM_REJ_BA_10_K 22
#define PQ_MS_BARRETT_BITSHIFT_BA_10_K (PQ_MS_UNIFORM_SIZE_BA_10_K * 8)
#define PQ_MS_BARRETT_FACTOR_BA_10_K ((1L << PQ_MS_BARRETT_BITSHIFT_BA_10_K) / PQ_MS_BA_10_K)
#define PQ_MS_UNIFORM_Q_BA_10_K (PQ_MS_BA_10_K * PQ_MS_BARRETT_FACTOR_BA_10_K)

#define PQ_MS_UNIFORM_SIZE_BRS_13_K 5
#define PQ_MS_UNIFORM_REJ_BRS_13_K 22
#define PQ_MS_BARRETT_BITSHIFT_BRS_13_K (PQ_MS_UNIFORM_SIZE_BRS_13_K * 8)
#define PQ_MS_BARRETT_FACTOR_BRS_13_K ((1L << PQ_MS_BARRETT_BITSHIFT_BRS_13_K) / PQ_MS_BRS_13_K)
#define PQ_MS_UNIFORM_Q_BRS_13_K (PQ_MS_BRS_13_K * PQ_MS_BARRETT_FACTOR_BRS_13_K)

// OpenCL long/ulong are the intended 64-bit C-reference arithmetic types.
// Some device compilers treat LL literals as signed 128-bit integers, which
// promotes ulong subtraction and makes valid uniform candidates reject.
typedef char pq_private_u64_literal_contract[
    (sizeof(long) == 8 && sizeof(ulong) == 8
     && sizeof(1L) == 8 && sizeof(1UL) == 8) ? 1 : -1];
typedef char pq_private_uniform_b_k_u64_contract[
    (sizeof(0UL - PQ_MS_UNIFORM_Q_B_K) == 8
     && ((0UL - PQ_MS_UNIFORM_Q_B_K) >> 63) == 1UL) ? 1 : -1];
typedef char pq_private_uniform_ba_10_k_u64_contract[
    (sizeof(0UL - PQ_MS_UNIFORM_Q_BA_10_K) == 8
     && ((0UL - PQ_MS_UNIFORM_Q_BA_10_K) >> 63) == 1UL) ? 1 : -1];
typedef char pq_private_uniform_brs_13_k_u64_contract[
    (sizeof(0UL - PQ_MS_UNIFORM_Q_BRS_13_K) == 8
     && ((0UL - PQ_MS_UNIFORM_Q_BRS_13_K) >> 63) == 1UL) ? 1 : -1];

#define PQ_MS_UNIFORM_R_SIZE_MAX 110

#define PQ_MS_BASE_TABLE_SIZE (4 * PQ_MS_CDT_ENTRY_SIZE)
#define PQ_MS_BERNOULLI_TABLE_SIZE (4 * PQ_MS_BERNOULLI_ENTRY_SIZE)

/* CDT table */
__constant pq_i4 PQ_MS_V_CDT[][2]  = {
    {(pq_i4)(2200310400551559144, 2200310400551559144, 2200310400551559144,
      2200310400551559144),
     (pq_i4)(3327841033070651387, 3327841033070651387, 3327841033070651387,
      3327841033070651387)},
    {(pq_i4)(7912151619254726620, 7912151619254726620, 7912151619254726620,
      7912151619254726620),
     (pq_i4)(380075531178589176, 380075531178589176, 380075531178589176,
      380075531178589176)},
    {(pq_i4)(5167367257772081627, 5167367257772081627, 5167367257772081627,
      5167367257772081627),
     (pq_i4)(11604843442081400, 11604843442081400, 11604843442081400,
      11604843442081400)},
    {(pq_i4)(5081592746475748971, 5081592746475748971, 5081592746475748971,
      5081592746475748971),
     (pq_i4)(90134450315532, 90134450315532, 90134450315532, 90134450315532)},
    {(pq_i4)(6522074513864805092, 6522074513864805092, 6522074513864805092,
      6522074513864805092),
     (pq_i4)(175786317361, 175786317361, 175786317361, 175786317361)},
    {(pq_i4)(2579734681240182346, 2579734681240182346, 2579734681240182346,
      2579734681240182346),
     (pq_i4)(85801740, 85801740, 85801740, 85801740)},
    {(pq_i4)(8175784047440310133, 8175784047440310133, 8175784047440310133,
      8175784047440310133),
     (pq_i4)(10472, 10472, 10472, 10472)},
    {(pq_i4)(2947787991558061753, 2947787991558061753, 2947787991558061753,
      2947787991558061753),
     (pq_i4)(0, 0, 0, 0)},
    {(pq_i4)(22489665999543, 22489665999543, 22489665999543, 22489665999543),
     (pq_i4)(0, 0, 0, 0)}};

__constant pq_i4 PQ_MS_V_CDT_LOW_MASK  = (pq_i4)(PQ_MS_CDT_LOW_MASK, PQ_MS_CDT_LOW_MASK, PQ_MS_CDT_LOW_MASK,
                                       PQ_MS_CDT_LOW_MASK);

__constant pq_i4 PQ_MS_V_B_K  = (pq_i4)(PQ_MS_B_K, PQ_MS_B_K, PQ_MS_B_K, PQ_MS_B_K);
__constant pq_i4 PQ_MS_V_BA_10_K  = (pq_i4)(PQ_MS_BA_10_K, PQ_MS_BA_10_K, PQ_MS_BA_10_K, PQ_MS_BA_10_K);
__constant pq_i4 PQ_MS_V_BRS_13_K  = (pq_i4)(PQ_MS_BRS_13_K, PQ_MS_BRS_13_K, PQ_MS_BRS_13_K, PQ_MS_BRS_13_K);

/* coefficients of the exp evaluation polynomial */
__constant pq_i4 PQ_MS_EXP_COFF[]  = {(pq_i4)(0x3e833b70ffa2c5d4, 0x3e833b70ffa2c5d4,
                                    0x3e833b70ffa2c5d4, 0x3e833b70ffa2c5d4),
                                   (pq_i4)(0x3eb4a480fda7e6e1, 0x3eb4a480fda7e6e1,
                                    0x3eb4a480fda7e6e1, 0x3eb4a480fda7e6e1),
                                   (pq_i4)(0x3ef01b254493363f, 0x3ef01b254493363f,
                                    0x3ef01b254493363f, 0x3ef01b254493363f),
                                   (pq_i4)(0x3f242e0e0aa273cc, 0x3f242e0e0aa273cc,
                                    0x3f242e0e0aa273cc, 0x3f242e0e0aa273cc),
                                   (pq_i4)(0x3f55d8a2334ed31b, 0x3f55d8a2334ed31b,
                                    0x3f55d8a2334ed31b, 0x3f55d8a2334ed31b),
                                   (pq_i4)(0x3f83b2aa56db0f1a, 0x3f83b2aa56db0f1a,
                                    0x3f83b2aa56db0f1a, 0x3f83b2aa56db0f1a),
                                   (pq_i4)(0x3fac6b08e11fc57e, 0x3fac6b08e11fc57e,
                                    0x3fac6b08e11fc57e, 0x3fac6b08e11fc57e),
                                   (pq_i4)(0x3fcebfbdff556072, 0x3fcebfbdff556072,
                                    0x3fcebfbdff556072, 0x3fcebfbdff556072),
                                   (pq_i4)(0x3fe62e42fefa7fe6, 0x3fe62e42fefa7fe6,
                                    0x3fe62e42fefa7fe6, 0x3fe62e42fefa7fe6),
                                   (pq_i4)(0x3ff0000000000000, 0x3ff0000000000000,
                                    0x3ff0000000000000, 0x3ff0000000000000)};

__constant pq_d4 PQ_MS_V_INT64_DOUBLE  = (pq_d4)(0x0010000000000000, 0x0010000000000000,
                                       0x0010000000000000, 0x0010000000000000);
__constant pq_d4 PQ_MS_V_DOUBLE_INT64  = (pq_d4)(0x0018000000000000, 0x0018000000000000,
                                       0x0018000000000000, 0x0018000000000000);

__constant pq_i4 PQ_MS_V_EXP_MANTISSA_MASK  = (pq_i4)(
    PQ_MS_EXP_MANTISSA_MASK, PQ_MS_EXP_MANTISSA_MASK, PQ_MS_EXP_MANTISSA_MASK, PQ_MS_EXP_MANTISSA_MASK);
__constant pq_i4 PQ_MS_V_RES_MANTISSA  = (pq_i4)(
    1L << PQ_MS_EXP_MANTISSA_PRECISION, 1L << PQ_MS_EXP_MANTISSA_PRECISION,
    1L << PQ_MS_EXP_MANTISSA_PRECISION, 1L << PQ_MS_EXP_MANTISSA_PRECISION);
__constant pq_i4 PQ_MS_V_RES_EXPONENT  = (pq_i4)(
    PQ_MS_R_EXPONENT_L - 1023 + 1, PQ_MS_R_EXPONENT_L - 1023 + 1, PQ_MS_R_EXPONENT_L - 1023 + 1,
    PQ_MS_R_EXPONENT_L - 1023 + 1);
__constant pq_i4 PQ_MS_V_R_MANTISSA_MASK  = (pq_i4)(PQ_MS_R_MANTISSA_MASK, PQ_MS_R_MANTISSA_MASK,
                                          PQ_MS_R_MANTISSA_MASK, PQ_MS_R_MANTISSA_MASK);
__constant pq_i4 PQ_MS_V_1  = (pq_i4)(1, 1, 1, 1);
__constant pq_i4 PQ_MS_V_DOUBLE_ONE  = (pq_i4)(PQ_MS_DOUBLE_ONE, PQ_MS_DOUBLE_ONE, PQ_MS_DOUBLE_ONE,
                                     PQ_MS_DOUBLE_ONE);

__constant pq_d4 PQ_MS_V_B_K_2_INV  = (pq_d4)(
    PQ_MS_BINARY_SAMPLER_B_K_2_INV, PQ_MS_BINARY_SAMPLER_B_K_2_INV,
    PQ_MS_BINARY_SAMPLER_B_K_2_INV, PQ_MS_BINARY_SAMPLER_B_K_2_INV);
__constant pq_d4 PQ_MS_V_BA_10_K_2_INV  = (pq_d4)(
    PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV, PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV,
    PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV, PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV);
__constant pq_d4 PQ_MS_V_BRS_13_K_2_INV  = (pq_d4)(
    PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV, PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV,
    PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV, PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV);

__constant pq_d2 PQ_MS_REJ_V_B_K_2_INV  = (pq_d2)(-PQ_MS_BINARY_SAMPLER_B_K_2_INV, 0);
__constant pq_d2 PQ_MS_REJ_V_BA_10_K_2_INV  = (pq_d2)(-PQ_MS_BINARY_SAMPLER_BA_10_K_2_INV, 0);
__constant pq_d2 PQ_MS_REJ_V_BRS_13_K_2_INV  = (pq_d2)(-PQ_MS_BINARY_SAMPLER_BRS_13_K_2_INV, 0);

#define PQ_MS_REJ_BERNOULLI_ENTRY_SIZE 9 /* 64bit randomness */
#define PQ_MS_REJ_R_EXPONENT_L (8 * PQ_MS_REJ_BERNOULLI_ENTRY_SIZE - PQ_MS_R_MANTISSA_PRECISION)

#define PQ_MS_PHI_A 10
#define PQ_MS_PHI_RS 13
#define PQ_MS_PHI_B 1
#define PQ_MS_MU_A (0x1.bd0ae59e8e95dp+0)
#define PQ_MS_MU_RS (0x1.56033b954fad2p+0)
#define PQ_MS_MU_B (0x1.71547652b82fep-1)

__constant pq_d2 PQ_MS_V_MU_A  = (pq_d2)(PQ_MS_MU_A, 0);
__constant pq_d2 PQ_MS_V_MU_RS  = (pq_d2)(PQ_MS_MU_RS, 0);
__constant pq_d2 PQ_MS_V_MU_B  = (pq_d2)(PQ_MS_MU_B, 0);


inline pq_i4 pq_ref_cdt_sampler(const unsigned char *r) {
  pq_i4 x = pq_mm256_setzero_si256();
  pq_i4 r1, r2;
  pq_i4 r1_lt_cdt0, r2_lt_cdt1;
  pq_i4 r2_eq_cdt1;
  pq_i4 b;

  uint32_t i;

  r1 = pq_mm256_loadu_si256((__private const uchar *)r);
  r2 = pq_mm256_loadu_si256((__private const uchar *)(r + 32));

  r1 = pq_mm256_and_si256(r1, PQ_MS_V_CDT_LOW_MASK);
  r2 = pq_mm256_and_si256(r2, PQ_MS_V_CDT_LOW_MASK);

  for (i = 0; i < PQ_MS_CDT_LENGTH; i++) {
    r1_lt_cdt0 = pq_mm256_sub_epi64(r1, PQ_MS_V_CDT[i][0]);

    r2_lt_cdt1 = pq_mm256_sub_epi64(r2, PQ_MS_V_CDT[i][1]);
    r2_eq_cdt1 = pq_mm256_cmpeq_epi64(r2, PQ_MS_V_CDT[i][1]);

    b = pq_mm256_and_si256(r1_lt_cdt0, r2_eq_cdt1);
    b = pq_mm256_or_si256(b, r2_lt_cdt1);
    b = pq_mm256_srli_epi64(b, 63);

    x = pq_mm256_add_epi64(x, b);
  }

  return x;
}

inline void pq_ref_bernoulli_sampler(uint64_t *b, pq_i4 x,
                                     const unsigned char *r,
                                     const pq_d4 v_k_2_inv) {
  pq_d4 vx, vx_1, vx_2, vsum;
  pq_i4 vt, k, vres, vres_mantissa, vres_exponent, vr_mantissa, vr_exponent,
      vr_exponent2, vres_eq_1, vr_lt_vres_mantissa, vr_lt_vres_exponent;

  /* 2^x=2^(floor(x)+a)=2^(floor(x))*2^a, where a is in [0,1]
   * we only evaluate 2^a by using a polynomial */
  x = pq_mm256_or_si256(x, pq_mm256_castpd_si256(PQ_MS_V_INT64_DOUBLE));
  vx = pq_mm256_sub_pd(pq_mm256_castsi256_pd(x), PQ_MS_V_INT64_DOUBLE);
  vx = pq_mm256_mul_pd(vx, v_k_2_inv);

  vx_1 = pq_mm256_floor_pd(vx);
  vx_2 = pq_mm256_add_pd(vx_1, PQ_MS_V_DOUBLE_INT64);
  vt = pq_mm256_sub_epi64(pq_mm256_castpd_si256(vx_2),
                        pq_mm256_castpd_si256(PQ_MS_V_DOUBLE_INT64));
  vt = pq_mm256_slli_epi64(vt, 52);

  /* evaluate 2^a */
  vx_2 = pq_mm256_sub_pd(vx, vx_1);
  vsum = pq_mm256_fmadd_pd(pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[0]), vx_2,
                         pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[1]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[2]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[3]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[4]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[5]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[6]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[7]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[8]));
  vsum = pq_mm256_fmadd_pd(vsum, vx_2, pq_mm256_castsi256_pd(PQ_MS_EXP_COFF[9]));

  /* combine to compute 2^x */
  vres = pq_mm256_add_epi64(vt, pq_mm256_castpd_si256(vsum));

  /* compute the Bernoulli value */
  vres_mantissa = pq_mm256_and_si256(vres, PQ_MS_V_EXP_MANTISSA_MASK);
  vres_mantissa = pq_mm256_or_si256(vres_mantissa, PQ_MS_V_RES_MANTISSA);

  vres_exponent = pq_mm256_srli_epi64(vres, PQ_MS_EXP_MANTISSA_PRECISION);
  vres_exponent = pq_mm256_add_epi64(vres_exponent, PQ_MS_V_RES_EXPONENT);
  vres_exponent = pq_mm256_sllv_epi64(PQ_MS_V_1, vres_exponent);

  vr_mantissa = pq_mm256_loadu_si256((__private const uchar *)r);
  vr_exponent = pq_mm256_srli_epi64(vr_mantissa, PQ_MS_R_MANTISSA_PRECISION);
  vr_mantissa = pq_mm256_and_si256(vr_mantissa, PQ_MS_V_R_MANTISSA_MASK);
  vr_exponent2 = pq_mm256_set_epi64x(r[35], r[34], r[33], r[32]);
  vr_exponent2 = pq_mm256_slli_epi64(vr_exponent2, 64 - PQ_MS_R_MANTISSA_PRECISION);
  vr_exponent = pq_mm256_or_si256(vr_exponent, vr_exponent2);

  /* (res == 1.0) || ((r_mantissa < res_mantissa) && (r_exponent < (1 <<
   * res_exponent))) */
  vres_eq_1 = pq_mm256_cmpeq_epi64(vres, PQ_MS_V_DOUBLE_ONE);
  vr_lt_vres_mantissa = pq_mm256_sub_epi64(vr_mantissa, vres_mantissa);
  vr_lt_vres_exponent = pq_mm256_sub_epi64(vr_exponent, vres_exponent);

  k = pq_mm256_and_si256(vr_lt_vres_mantissa, vr_lt_vres_exponent);
  k = pq_mm256_or_si256(k, vres_eq_1);

  pq_mm256_store_si256((__private ulong *)(b), k);
}

inline void pq_ref_uniform_sampler_b_k(__private pq_private_rng_state *rng, const unsigned char *r, pq_i4 *y1,
                                pq_i4 *y2) {
  uint64_t sample[8] ;
  uint32_t i = 0, j = 0;
  uint64_t x;

  while (j < 8) {
    do { /* we ignore the low probability of rerunning the PRG
          * change the loading size i.e. uint16_t according to your UNIFORM_SIZE
          */
      if (i >= PQ_MS_UNIFORM_REJ_B_K) { pq_private_poison(rng, PQ_PRIVATE_UNIFORM_EXHAUSTED); { pq_private_wipe_local(sample, sizeof sample); return; } }
      x = pq_ref_load_32(r + PQ_MS_UNIFORM_SIZE_B_K * (i++));
    } while (1 ^ ((x - PQ_MS_UNIFORM_Q_B_K) >> 63));

    x = x - ((((x * PQ_MS_BARRETT_FACTOR_B_K) >> PQ_MS_BARRETT_BITSHIFT_B_K) + 1) * PQ_MS_B_K);
    x = x + (x >> 63) * PQ_MS_B_K;

    sample[j++] = x;
  }

  *y1 = pq_mm256_load_si256((__private const ulong *)(sample));
  *y2 = pq_mm256_load_si256((__private const ulong *)(sample + 4));

  pq_private_wipe_local(sample, sizeof sample);
}

inline void pq_ref_uniform_sampler_ba_10_k(__private pq_private_rng_state *rng, const unsigned char *r, pq_i4 *y1,
                                    pq_i4 *y2) {
  uint64_t sample[8] ;
  uint32_t i = 0, j = 0;
  uint64_t x;

  while (j < 8) {
    do { /* we ignore the low probability of rerunning the PRG
          * change the loading size i.e. uint16_t according to your UNIFORM_SIZE
          */
      if (i >= PQ_MS_UNIFORM_REJ_BA_10_K) { pq_private_poison(rng, PQ_PRIVATE_UNIFORM_EXHAUSTED); { pq_private_wipe_local(sample, sizeof sample); return; } }
      x = pq_ref_load_24(r + PQ_MS_UNIFORM_SIZE_BA_10_K * (i++));
    } while (1 ^ ((x - PQ_MS_UNIFORM_Q_BA_10_K) >> 63));

    x = x - ((((x * PQ_MS_BARRETT_FACTOR_BA_10_K) >> PQ_MS_BARRETT_BITSHIFT_BA_10_K) + 1) *
             PQ_MS_BA_10_K);
    x = x + (x >> 63) * PQ_MS_BA_10_K;

    sample[j++] = x;
  }

  *y1 = pq_mm256_load_si256((__private const ulong *)(sample));
  *y2 = pq_mm256_load_si256((__private const ulong *)(sample + 4));

  pq_private_wipe_local(sample, sizeof sample);
}

inline void pq_ref_uniform_sampler_brs_13_k(__private pq_private_rng_state *rng, const unsigned char *r, pq_i4 *y1,
                                     pq_i4 *y2) {
  uint64_t sample[8] ;
  uint32_t i = 0, j = 0;
  uint64_t x;

  while (j < 8) {
    do { /* we ignore the low probability of rerunning the PRG
          * change the loading size i.e. uint16_t according to your UNIFORM_SIZE
          */
      if (i >= PQ_MS_UNIFORM_REJ_BRS_13_K) { pq_private_poison(rng, PQ_PRIVATE_UNIFORM_EXHAUSTED); { pq_private_wipe_local(sample, sizeof sample); return; } }
      x = pq_ref_load_40(r + PQ_MS_UNIFORM_SIZE_BRS_13_K * (i++));
    } while (1 ^ ((x - PQ_MS_UNIFORM_Q_BRS_13_K) >> 63));

    x = x -
        ((((x * PQ_MS_BARRETT_FACTOR_BRS_13_K) >> PQ_MS_BARRETT_BITSHIFT_BRS_13_K) + 1) *
         PQ_MS_BRS_13_K);
    x = x + (x >> 63) * PQ_MS_BRS_13_K;

    sample[j++] = x;
  }

  *y1 = pq_mm256_load_si256((__private const ulong *)(sample));
  *y2 = pq_mm256_load_si256((__private const ulong *)(sample + 4));

  pq_private_wipe_local(sample, sizeof sample);
}

inline void pq_ref_uniform_dispatch(__private pq_private_rng_state *rng, uint profile,
    __private const uchar *r, __private pq_i4 *a, __private pq_i4 *b) {
    if(profile==0) pq_ref_uniform_sampler_b_k(rng,r,a,b);
    else if(profile==1) pq_ref_uniform_sampler_ba_10_k(rng,r,a,b);
    else if(profile==2) pq_ref_uniform_sampler_brs_13_k(rng,r,a,b);
    else pq_private_poison(rng,PQ_PRIVATE_BAD_INPUT);
}

inline void pq_ref_gaussian_sampler(__private pq_private_rng_state *rng, 
    __global uint64_t *sample, const uint32_t slen, const pq_i4 v_k,
    const pq_d4 v_k_2_inv, const uint64_t uniform_r_size,
    const uint profile) {
  pq_i4 v_x, v_y1, v_y2, v_z, v_b_in;
  uint64_t z[8] ;
  uint64_t b[8] ;

  unsigned char r[2 * (PQ_MS_BASE_TABLE_SIZE + PQ_MS_BERNOULLI_TABLE_SIZE) +
                  PQ_MS_UNIFORM_R_SIZE_MAX + 1] ;
  unsigned char *r1;

  uint32_t i = 8, j = 0;
  uint64_t k;

  while (j < slen) {
    do {
      if (i == 8) {
        if (rng->proposals > rng->proposal_limit || rng->proposal_limit-rng->proposals < 8) { pq_private_poison(rng, PQ_PRIVATE_BUDGET_EXHAUSTED); { pq_private_wipe_local(r, sizeof r); pq_private_wipe_local(z, sizeof z); pq_private_wipe_local(b, sizeof b); return; } }
        rng->proposals += 8;
        /* x<--D_sigma_0, y<--U([0,k-1]), z=kx+y */
        if (!pq_private_random_bytes(rng, r, 2 * (PQ_MS_BASE_TABLE_SIZE + PQ_MS_BERNOULLI_TABLE_SIZE) +
                                   uniform_r_size + 1)) { pq_private_wipe_local(r, sizeof r); pq_private_wipe_local(z, sizeof z); pq_private_wipe_local(b, sizeof b); return; }

        pq_ref_uniform_dispatch(rng, profile, r + 2 * (PQ_MS_BASE_TABLE_SIZE + PQ_MS_BERNOULLI_TABLE_SIZE), &v_y1,
                        &v_y2);
        if (rng->status) { pq_private_wipe_local(r, sizeof r); pq_private_wipe_local(z, sizeof z); pq_private_wipe_local(b, sizeof b); return; }

        r1 = r;
        v_x = pq_ref_cdt_sampler(r1);
        v_x = pq_mm256_mul_epu32(v_x, v_k);
        v_z = pq_mm256_add_epi64(v_x, v_y1);
        pq_mm256_store_si256((__private ulong *)(z), v_z);
        /* b<--Bernoulli(exp(-y(y+2kx)/2sigma_0^2)) */
        v_b_in = pq_mm256_add_epi64(v_z, v_x);
        v_b_in = pq_mm256_mul_epu32(v_b_in, v_y1);
        pq_ref_bernoulli_sampler(b, v_b_in, r1 + PQ_MS_BASE_TABLE_SIZE, v_k_2_inv);

        r1 = r + (PQ_MS_BASE_TABLE_SIZE + PQ_MS_BERNOULLI_TABLE_SIZE);
        v_x = pq_ref_cdt_sampler(r1);
        v_x = pq_mm256_mul_epu32(v_x, v_k);
        v_z = pq_mm256_add_epi64(v_x, v_y2);
        pq_mm256_store_si256((__private ulong *)(z + 4), v_z);
        /* b<--Bernoulli(exp(-y(y+2kx)/2sigma_0^2)) */
        v_b_in = pq_mm256_add_epi64(v_z, v_x);
        v_b_in = pq_mm256_mul_epu32(v_b_in, v_y2);
        pq_ref_bernoulli_sampler(b + 4, v_b_in, r1 + PQ_MS_BASE_TABLE_SIZE, v_k_2_inv);

        i = 0;
      }

      k = (r[2 * (PQ_MS_BASE_TABLE_SIZE + PQ_MS_BERNOULLI_TABLE_SIZE) + uniform_r_size] >>
           i) &
          0x1;
      i++;
    } while (1 ^
             ((b[i - 1] & ((z[i - 1] | -z[i - 1]) | (k | -k))) >>
              63)); /* rejection condition: b=0 or ((b=1) && (z=0) && (k=0)) */

    sample[j++] =
        z[i - 1] * (1 ^ ((-k) & 0xfffffffffffffffe)); /* sample=z*(-1)^k */
  }

  pq_private_wipe_local(r, sizeof r); pq_private_wipe_local(z, sizeof z); pq_private_wipe_local(b, sizeof b);
}

inline void pq_ref_gaussian_b(__private pq_private_rng_state *rng, __global pq_private_poly *out, const uint64_t m, const pq_i4 v_k,
                              const pq_d4 v_k_2_inv,
                              const uint64_t uniform_r_size,
                              const uint profile) {
  uint64_t i;

  for (i = 0; i < m; i++) {
    pq_ref_gaussian_sampler(rng, (__global uint64_t *)((out + i)->poly), PQ_MS_D, v_k, v_k_2_inv,
                     uniform_r_size, profile);
    if (rng->status) return;
  }
}

inline void pq_ref_sample_b_nk1(__private pq_private_rng_state *rng, __global pq_private_poly *out) {
  pq_ref_gaussian_b(rng, out, PQ_MS_N + PQ_MS_K + 1, PQ_MS_V_B_K, PQ_MS_V_B_K_2_INV,
             PQ_MS_UNIFORM_REJ_B_K * PQ_MS_UNIFORM_SIZE_B_K, 0u);
}

inline void pq_ref_sample_b_nk3(__private pq_private_rng_state *rng, __global pq_private_poly *out) {
  pq_ref_gaussian_b(rng, out, PQ_MS_N + PQ_MS_K + 3, PQ_MS_V_B_K, PQ_MS_V_B_K_2_INV,
             PQ_MS_UNIFORM_REJ_B_K * PQ_MS_UNIFORM_SIZE_B_K, 0u);
}

inline void pq_ref_sample_b_nhatkhat(__private pq_private_rng_state *rng, __global pq_private_poly *out) {
  pq_ref_gaussian_b(rng, out, PQ_MS_N_HAT + PQ_MS_K_HAT, PQ_MS_V_B_K, PQ_MS_V_B_K_2_INV,
             PQ_MS_UNIFORM_REJ_B_K * PQ_MS_UNIFORM_SIZE_B_K, 0u);
}

inline void pq_ref_sample_brs_13_nbark(__private pq_private_rng_state *rng, __global pq_private_poly *out) {
  pq_ref_gaussian_b(rng, out, PQ_MS_N_BAR + PQ_MS_K, PQ_MS_V_BRS_13_K, PQ_MS_V_BRS_13_K_2_INV,
             PQ_MS_UNIFORM_REJ_BRS_13_K * PQ_MS_UNIFORM_SIZE_BRS_13_K,
             2u);
}

inline void pq_ref_sample_ba_n1(__private pq_private_rng_state *rng, __global pq_private_poly *out) {
  pq_ref_gaussian_b(rng, out, PQ_MS_N_SPENT + 1, PQ_MS_V_BA_10_K, PQ_MS_V_BA_10_K_2_INV,
             PQ_MS_UNIFORM_REJ_BA_10_K * PQ_MS_UNIFORM_SIZE_BA_10_K,
             1u);
}

inline uint64_t pq_ref_rej_bernoulli_sampler(__private pq_private_rng_state *rng, uint64_t x, const unsigned char *r,
                                             const pq_d2 v_k_2_inv,
                                             const pq_d2 v_mu) {
  /* coefficients of the exp evaluation polynomial */
  const uint64_t PQ_MS_EXP_COFF[] = {0x3e833b70ffa2c5d4, 0x3eb4a480fda7e6e1,
                                      0x3ef01b254493363f, 0x3f242e0e0aa273cc,
                                      0x3f55d8a2334ed31b, 0x3f83b2aa56db0f1a,
                                      0x3fac6b08e11fc57e, 0x3fcebfbdff556072,
                                      0x3fe62e42fefa7fe6, 0x3ff0000000000000};

  pq_d2 vx, vx_1, vx_2, vsum;
  pq_i2 vt, vres;

  uint64_t res, res_mantissa, res_exponent;
  uint64_t r_mantissa, r_exponent;
  uint64_t r1, r2;

  /* 2^x=2^(floor(x)+a)=2^(floor(x))*2^a, where a is in [0,1]
   * we only evaluate 2^a by using a polynomial */
  vx = pq_mm_cvtsi64_sd(pq_mm_setzero_pd(), x);
  vx = pq_mm_mul_sd(vx, v_k_2_inv);
  vx = pq_mm_sub_sd(vx, v_mu);

  vx_1 = pq_mm_floor_pd(vx);
  vt = pq_mm_cvtpd_epi32(vx_1);
  vt = pq_mm_slli_epi64(vt, 52);

  /* evaluate 2^a */
  vx_2 = pq_mm_sub_sd(vx, vx_1);
  vsum = pq_mm_add_sd(
      pq_mm_mul_sd(pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[0])), vx_2),
      pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[1])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[2])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[3])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[4])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[5])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[6])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[7])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[8])));
  vsum = pq_mm_add_sd(pq_mm_mul_sd(vsum, vx_2),
                    pq_mm_castsi128_pd(pq_mm_cvtsi64x_si128(PQ_MS_EXP_COFF[9])));

  /* combine to compute 2^x */
  vres = pq_mm_add_epi64(vt, pq_mm_castpd_si128(vsum));
  pq_mm_storel_epi64((__private ulong *)(&res), vres);

  res_mantissa = (res & PQ_MS_EXP_MANTISSA_MASK) | (1L << PQ_MS_EXP_MANTISSA_PRECISION);
  res_exponent = PQ_MS_REJ_R_EXPONENT_L - 1023 + 1 + (res >> PQ_MS_EXP_MANTISSA_PRECISION);
  if (res_exponent >= 64) { pq_private_poison(rng, PQ_PRIVATE_NUMERIC_CONTRACT); return 1; }

  r1 = pq_ref_load_64(r);
  r2 = (uint64_t)(r[8]);

  r_mantissa = r1 & PQ_MS_R_MANTISSA_MASK;
  r_exponent =
      (r1 >> PQ_MS_R_MANTISSA_PRECISION) | (r2 << (64 - PQ_MS_R_MANTISSA_PRECISION));

  /* ~((res == 1.0) || ((r_mantissa < res_mantissa) && (r_exponent < (1 <<
   * res_exponent)))) */
  return (((res - PQ_MS_DOUBLE_ONE) | (PQ_MS_DOUBLE_ONE - res)) &
          ((PQ_REF_UINT64_C(1) << 63) ^ ((r_mantissa - res_mantissa) &
                          (r_exponent - (PQ_REF_UINT64_C(1) << res_exponent))))) >>
         63;
}

inline uint64_t pq_ref_rej(__private pq_private_rng_state *rng, __global const pq_private_poly *z, __global const pq_private_poly *c,
                           const uint64_t slen, const pq_d2 v_k_2_inv,
                           const pq_d2 v_mu, const uint64_t sigma_6) {
  unsigned char r[PQ_MS_REJ_BERNOULLI_ENTRY_SIZE];

  uint64_t ret = 0, x = 0;

  uint64_t i, j;

  for (i = 0; i < slen; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      /* check z norm */
      ret |= pq_ref_ct_lt(sigma_6, z[i].poly[j]) | pq_ref_ct_lt(z[i].poly[j], -sigma_6);

      /* -2 * <z, c> + ||c||^2 */
      x += (c[i].poly[j]) * (c[i].poly[j]) -
           2 * (z[i].poly[j]) * (c[i].poly[j]);
    }
  }

  if (!pq_private_random_bytes(rng, r, PQ_MS_REJ_BERNOULLI_ENTRY_SIZE)) { pq_private_wipe_local(r, sizeof r); return 1; }
  ret |= pq_ref_rej_bernoulli_sampler(rng, x, r, v_k_2_inv, v_mu);

  { pq_private_wipe_local(r, sizeof r); return ret; }
}

inline uint64_t pq_ref_rej_op(__private pq_private_rng_state *rng, __global const pq_private_poly z_out[][PQ_MS_N + PQ_MS_K + 1], __global const pq_private_poly *z1,
                __global const pq_private_poly *z2, __global const pq_private_poly *z0, __global const pq_private_poly *zb,
                __global const pq_private_poly x_rout[][PQ_MS_N + PQ_MS_K + 1], __global const pq_private_poly *x_rho,
                __global const pq_private_poly *x_aut_rho, __global const pq_private_poly *x_ri,
                __global const pq_private_poly *x_rb) {
  unsigned char r[PQ_MS_REJ_BERNOULLI_ENTRY_SIZE];

  uint64_t ret = 0, x = 0;

  uint64_t i, j;

  /* <z, c> ?< 0 */
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (z_out[0][i].poly[j]) * (x_rout[0][i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (z_out[1][i].poly[j]) * (x_rout[1][i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 3; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (z1[i].poly[j]) * (x_rho[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 3; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (z2[i].poly[j]) * (x_aut_rho[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (z0[i].poly[j]) * (x_ri[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N_HAT + PQ_MS_K_HAT; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      x += (zb[i].poly[j]) * (x_rb[i].poly[j]);
    }
  }

  if (x >> 63) {
    { pq_private_wipe_local(r, sizeof r); return 1; }
  }

  x *= -2;
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, z_out[0][i].poly[j]) | pq_ref_ct_lt(z_out[0][i].poly[j], -PQ_MS_B_6);

      x += (x_rout[0][i].poly[j]) * (x_rout[0][i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, z_out[1][i].poly[j]) | pq_ref_ct_lt(z_out[1][i].poly[j], -PQ_MS_B_6);

      x += (x_rout[1][i].poly[j]) * (x_rout[1][i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 3; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, z1[i].poly[j]) | pq_ref_ct_lt(z1[i].poly[j], -PQ_MS_B_6);

      x += (x_rho[i].poly[j]) * (x_rho[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 3; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, z2[i].poly[j]) | pq_ref_ct_lt(z2[i].poly[j], -PQ_MS_B_6);

      x += (x_aut_rho[i].poly[j]) * (x_aut_rho[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N + PQ_MS_K + 1; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, z0[i].poly[j]) | pq_ref_ct_lt(z0[i].poly[j], -PQ_MS_B_6);

      x += (x_ri[i].poly[j]) * (x_ri[i].poly[j]);
    }
  }
  for (i = 0; i < PQ_MS_N_HAT + PQ_MS_K_HAT; i++) {
    for (j = 0; j < PQ_MS_D; j++) {
      ret |= pq_ref_ct_lt(PQ_MS_B_6, zb[i].poly[j]) | pq_ref_ct_lt(zb[i].poly[j], -PQ_MS_B_6);

      x += (x_rb[i].poly[j]) * (x_rb[i].poly[j]);
    }
  }

  if (!pq_private_random_bytes(rng, r, PQ_MS_REJ_BERNOULLI_ENTRY_SIZE)) { pq_private_wipe_local(r, sizeof r); return 1; }
  ret |= pq_ref_rej_bernoulli_sampler(rng, x, r, PQ_MS_REJ_V_B_K_2_INV, PQ_MS_V_MU_B);

  { pq_private_wipe_local(r, sizeof r); return ret; }
}

inline uint64_t pq_ref_rej_f(__private pq_private_rng_state *rng, __global const pq_private_poly *z, __global const pq_private_poly *c) {
  return pq_ref_rej(rng, z, c, PQ_MS_N_SPENT + 1, PQ_MS_REJ_V_BA_10_K_2_INV, PQ_MS_V_MU_A, PQ_MS_BA_10_6);
}

inline uint64_t pq_ref_rej_z(__private pq_private_rng_state *rng, __global const pq_private_poly *z, __global const pq_private_poly *c) {
  return pq_ref_rej(rng, z, c, PQ_MS_N_BAR + PQ_MS_K, PQ_MS_REJ_V_BRS_13_K_2_INV, PQ_MS_V_MU_RS, PQ_MS_BRS_13_6);
}

#endif

// end reference_gaussian.clh

inline void pq_ref_sample_1(__private pq_private_rng_state *rng,
                            __global pq_private_poly *out, uint rows) {
    uchar bytes[11 * 128];
    if (rows == 0 || rows > 11) { pq_private_poison(rng,PQ_PRIVATE_BAD_INPUT); return; }
    if (!pq_private_random_bytes(rng,bytes,(ulong)rows * 128)) {
        pq_private_wipe_local(bytes,sizeof bytes); return;
    }
    for(uint row=0;row<rows;++row) for(uint j=0;j<256;j+=2) {
        ulong r=bytes[row*128+j/2];
        ulong a=(r&1)+((r>>1)&1)-((r>>2)&1)-((r>>3)&1);
        ulong b=((r>>4)&1)+((r>>5)&1)-((r>>6)&1)-((r>>7)&1);
        a += pq_ref_ct_eq(a,(ulong)-2)-pq_ref_ct_eq(a,2);
        b += pq_ref_ct_eq(b,(ulong)-2)-pq_ref_ct_eq(b,2);
        out[row].poly[j]=a; out[row].poly[j+1]=b;
    }
    pq_private_wipe_local(bytes,sizeof bytes);
}
inline uint pq_private_gaussian_rows(uint profile) {
    return profile==0?9u:profile==1?11u:profile==2?10u:profile==3?8u:profile==4?11u:0u;
}
inline void pq_private_gaussian_dispatch(__private pq_private_rng_state *rng,
                                         __global pq_private_poly *out,uint profile) {
    if(profile==0) pq_ref_sample_b_nk1(rng,out);
    else if(profile==1) pq_ref_sample_b_nk3(rng,out);
    else if(profile==2) pq_ref_sample_b_nhatkhat(rng,out);
    else if(profile==3) pq_ref_sample_brs_13_nbark(rng,out);
    else if(profile==4) pq_ref_sample_ba_n1(rng,out);
    else pq_private_poison(rng,PQ_PRIVATE_BAD_INPUT);
}
#endif

// end private_sampling.clh
// begin sampler_kernels.cl
// ISOLATED UNCOMPILED/UNTESTED candidate. All buffers/counts must be admitted by owner.

inline int pq_private_region(ulong base,ulong stride,uint job,ulong words,ulong limit,
                              __private ulong *offset) {
    if (stride && (ulong)job > (0xffffffffffffffffUL-base)/stride) return 0;
    ulong at=base+(ulong)job*stride;
    if(at>limit || words>limit-at) return 0;
    *offset=at;return 1;
}
inline int pq_private_begin(__global uint *status,uint job,
                             __global const pq_private_rng_state *states,
                             __private pq_private_rng_state *rng) {
    if(status[16UL*job+1]>2u) {
        pq_private_publish(status,job,PQ_PRIVATE_BAD_INPUT);
        return 0;
    }
    if(status[16UL*job] || status[16UL*job+1]) return 0;
    *rng=states[job];
    if(rng->status) {
        pq_private_publish(status,job,pq_private_error_code(rng->status));
        pq_private_clear_rng(rng);
        return 0;
    }
    return 1;
}
inline void pq_private_finish(__global pq_private_rng_state *states,
                               __global uint *status,uint job,
                               __private pq_private_rng_state *rng) {
    uint code=pq_private_error_code(rng->status);
    if(code) { pq_private_clear_rng(rng); rng->status=code; }
    states[job]=*rng;
    pq_private_publish(status,job,code);
    pq_private_clear_rng(rng);
}
inline void pq_private_zero_region(__global ulong *arena,ulong at,ulong words) {
    volatile __global ulong *wipe=arena+at;
    for(ulong i=0;i<words;++i) wipe[i]=0;
}
__kernel void pq_private_rng_init(__global const ulong *packed_input,ulong input_words,
    ulong seed_word_offset,ulong input_job_stride,__global pq_private_rng_state *states,
    ulong random_call_limit,ulong proposal_limit,uint jobs,__global uint *status) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    if(status[16UL*job])return;
    pq_private_rng_state rng;pq_private_clear_rng(&rng);
    ulong seed_at=0;
    if(status[16UL*job+1] || status[16UL*job+2]
       || (jobs>1 && input_job_stride<32) || !random_call_limit || !proposal_limit
       || !pq_private_region(seed_word_offset,input_job_stride,job,32,input_words,&seed_at)) {
        pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    } else {
        rng.random_call_limit=random_call_limit;rng.proposal_limit=proposal_limit;
        pq_private_expand_key_words(&rng,packed_input+seed_at);
    }
    status[16UL*job+1]=0;status[16UL*job+2]=0;
    for(uint i=3;i<16;++i) if(status[16UL*job+i])pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    pq_private_finish(states,status,job,&rng);
}
__kernel void pq_sample_one(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,ulong output_word_offset,ulong job_stride,uint rows,uint jobs,
    __global uint *status,uint phase_id) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    pq_private_rng_state rng;if(!pq_private_begin(status,job,states,&rng))return;
    ulong at=0,words=(ulong)rows*256;
    int valid=rows>0 && rows<=11 && (jobs==1 || job_stride>=words)
        && pq_private_region(output_word_offset,job_stride,job,words,arena_words,&at);
    if(!valid)pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    else pq_ref_sample_1(&rng,(__global pq_private_poly *)(arena+at),rows);
    if(valid && rng.status)pq_private_zero_region(arena,at,words);
    status[16UL*job+2]=phase_id;pq_private_finish(states,status,job,&rng);
}
__kernel void pq_sample_gaussian(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,ulong output_word_offset,ulong job_stride,uint profile,uint jobs,
    __global uint *status,uint phase_id) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    pq_private_rng_state rng;if(!pq_private_begin(status,job,states,&rng))return;
    uint rows=pq_private_gaussian_rows(profile);ulong words=(ulong)rows*256,at=0;
    int valid=rows && (jobs==1 || job_stride>=words)
        && pq_private_region(output_word_offset,job_stride,job,words,arena_words,&at);
    if(!valid)pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    else pq_private_gaussian_dispatch(&rng,(__global pq_private_poly *)(arena+at),profile);
    if(valid && rng.status)pq_private_zero_region(arena,at,words);
    status[16UL*job+2]=phase_id;pq_private_finish(states,status,job,&rng);
}
inline void pq_private_reject_rows(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,ulong z_word_offset,ulong c_word_offset,ulong job_stride,uint job,uint jobs,
    __global uint *status,uint phase_id,uint rows) {
    pq_private_rng_state rng;if(!pq_private_begin(status,job,states,&rng))return;
    ulong z_at=0,c_at=0,words=(ulong)rows*256;
    int valid=(jobs==1 || job_stride>=words)
        && pq_private_region(z_word_offset,job_stride,job,words,arena_words,&z_at)
        && pq_private_region(c_word_offset,job_stride,job,words,arena_words,&c_at);
    ulong rejected=1;
    if(!valid)pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    else if(rows==11)rejected=pq_ref_rej_f(&rng,(__global const pq_private_poly *)(arena+z_at),(__global const pq_private_poly *)(arena+c_at));
    else if(rows==8)rejected=pq_ref_rej_z(&rng,(__global const pq_private_poly *)(arena+z_at),(__global const pq_private_poly *)(arena+c_at));
    else pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    if(!rng.status && rejected)status[16UL*job+1]=1;
    status[16UL*job+2]=phase_id;pq_private_finish(states,status,job,&rng);
}
__kernel void pq_reject_f(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,ulong z_word_offset,ulong c_word_offset,ulong job_stride,uint jobs,
    __global uint *status,uint phase_id) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    pq_private_reject_rows(states,arena,arena_words,z_word_offset,c_word_offset,job_stride,job,jobs,status,phase_id,11);
}
__kernel void pq_reject_z(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,ulong z_word_offset,ulong c_word_offset,ulong job_stride,uint jobs,
    __global uint *status,uint phase_id) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    pq_private_reject_rows(states,arena,arena_words,z_word_offset,c_word_offset,job_stride,job,jobs,status,phase_id,8);
}
__kernel void pq_reject_op(__global pq_private_rng_state *states,__global ulong *arena,
    ulong arena_words,__global const ulong *operand_offsets,uint offset_count,ulong job_stride,
    uint jobs,__global uint *status,uint phase_id) {
    size_t gid=get_global_id(0);if(gid>=(size_t)jobs)return;uint job=(uint)gid;
    pq_private_rng_state rng;if(!pq_private_begin(status,job,states,&rng))return;
    // Ordered: z_out,z1,z2,z0,zb,x_rout,x_rho,x_aut_rho,x_ri,x_rb.
    const uint rows[10]={18,11,11,9,10,18,11,11,9,10};ulong at[10];int valid=offset_count==10;
    for(uint i=0;i<10 && valid;++i)valid=(jobs==1 || job_stride>=(ulong)rows[i]*256)
        && pq_private_region(operand_offsets[i],job_stride,job,(ulong)rows[i]*256,arena_words,&at[i]);
    if(!valid)pq_private_poison(&rng,PQ_PRIVATE_BAD_INPUT);
    else {
        ulong rejected=pq_ref_rej_op(&rng,
          (__global const pq_private_poly (*)[9])(arena+at[0]),
          (__global const pq_private_poly *)(arena+at[1]),(__global const pq_private_poly *)(arena+at[2]),
          (__global const pq_private_poly *)(arena+at[3]),(__global const pq_private_poly *)(arena+at[4]),
          (__global const pq_private_poly (*)[9])(arena+at[5]),
          (__global const pq_private_poly *)(arena+at[6]),(__global const pq_private_poly *)(arena+at[7]),
          (__global const pq_private_poly *)(arena+at[8]),(__global const pq_private_poly *)(arena+at[9]));
        if(!rng.status && rejected)status[16UL*job+1]=1;
    }
    status[16UL*job+2]=phase_id;pq_private_finish(states,status,job,&rng);
}
__kernel void pq_wipe_words(__global ulong *words,ulong count) {
    ulong at=get_global_id(0);if(at<count)((volatile __global ulong *)words)[at]=0;
}
__kernel void pq_wipe_bytes(__global uchar *bytes,ulong count) {
    ulong at=get_global_id(0);if(at<count)((volatile __global uchar *)bytes)[at]=0;
}

// end sampler_kernels.cl
// begin pq_spend_abi.h
// ISOLATED, UNCOMPILED, UNTESTED. Include sampler ABI before this file.
// pq_private_poly is exactly 256 ulong coefficient words (signed bitpatterns).
// No absolute arena offsets are defined: the root worker assigns named slots.
#ifndef PQ_SPEND_ABI_V1
#define PQ_SPEND_ABI_V1
#define PQ_SPEND_ERROR_SHAPE 1u
#define PQ_SPEND_ERROR_CANONICAL 2u
#define PQ_SPEND_ERROR_BOUND 4u
#define PQ_SPEND_ERROR_OVERFLOW 8u
#define PQ_SPEND_ERROR_INTERNAL 128u
typedef struct { pq_private_poly pk[4], cn[5]; } pq_spend_act;
typedef struct { pq_private_poly pk[4]; } pq_spend_pk;
typedef struct { pq_private_poly cn[5]; } pq_spend_cn;
typedef struct { pq_private_poly ck[9]; } pq_spend_ck;
typedef struct {
    pq_private_poly c,v[4],v1,v2,b[5]; uchar alpha[32]; pq_private_poly x;
    pq_private_poly z_out[2][9],z0[9],z1[11],z2[11],f1[11],zb[10],z[8];
} pq_spend_proof;
typedef char pq_spend_poly_size_guard[(sizeof(pq_private_poly)==2048)?1:-1];
typedef char pq_spend_proof_size_guard[(sizeof(pq_spend_proof)==186400)?1:-1];
enum { PQ_SPEND_IMPORT=10, PQ_SPEND_SETUP=20, PQ_SPEND_MINT=30,
       PQ_SPEND_BEGIN=35, PQ_SPEND_EARLY=40, PQ_SPEND_LATE=50,
       PQ_SPEND_F=60, PQ_SPEND_GZ=70, PQ_SPEND_OP=80, PQ_SPEND_ENCODE=90 };
#define PQ_SPEND_CRYPTO_BYTES 32L
#define PQ_SPEND_M 2L
#define PQ_SPEND_S 2L
#define PQ_SPEND_N_SPENT 10L
#define PQ_SPEND_W 44L
#define PQ_SPEND_WA 39L
#define PQ_SPEND_N 4L
#define PQ_SPEND_K 4L
#define PQ_SPEND_N_BAR 4L
#define PQ_SPEND_N_HAT 5L
#define PQ_SPEND_K_HAT 5L
#define PQ_SPEND_B_K 7525L
#define PQ_SPEND_BA_10_K 111L
#define PQ_SPEND_BETA 40L
#define PQ_SPEND_BRS_13_K 1219127L
#define PQ_SPEND_BG_0 6825771L
#define PQ_SPEND_BG_1 1137628L
#define PQ_SPEND_B_6 38346L
#define PQ_SPEND_BA_10_6 565L
#define PQ_SPEND_BRS_13_6 6212586L
#define PQ_SPEND_R 64L
#define PQ_SPEND_D 256L /* ring dimension */
#define PQ_SPEND_Q 167770241L
#define PQ_SPEND_Q_BYTE 4L
#define PQ_SPEND_QHAT 3489661057L
#define PQ_SPEND_QHAT_BYTE 4L
#define PQ_SPEND_SUBRING_SIZE (PQ_SPEND_D / PQ_SPEND_R)
#define PQ_SPEND_RED_SHORT_SHIFT_1_Q 27L
#define PQ_SPEND_RED_SHORT_CONST_Q 33552513L
#define PQ_SPEND_RED_SHORT_MASK_Q ((1L << PQ_SPEND_RED_SHORT_SHIFT_1_Q) - 1)
#define PQ_SPEND_RED_SHORT_SHIFT_1_QHAT 32L
#define PQ_SPEND_RED_SHORT_CONST_QHAT 805306239L
#define PQ_SPEND_RED_SHORT_MASK_QHAT ((1L << PQ_SPEND_RED_SHORT_SHIFT_1_QHAT) - 1)
#define PQ_SPEND_MONTGOMERY_FACTOR_Q 2887272321L
#define PQ_SPEND_MONTGOMERY_SHIFT_Q 32L
#define PQ_SPEND_MONTGOMERY_MASK_Q ((1L << PQ_SPEND_MONTGOMERY_SHIFT_Q) - 1)
#define PQ_SPEND_MONTGOMERY_CONVERT_FACTOR_Q 138438709L
#define PQ_SPEND_MONTGOMERY_32_Q 100711271L
#define PQ_SPEND_MONTGOMERY_FACTOR_QHAT 1071660929L
#define PQ_SPEND_MONTGOMERY_SHIFT_QHAT 32L
#define PQ_SPEND_MONTGOMERY_MASK_QHAT ((1L << PQ_SPEND_MONTGOMERY_SHIFT_QHAT) - 1)
#define PQ_SPEND_MONTGOMERY_CONVERT_FACTOR_QHAT 2333348873L
#define PQ_SPEND_SLOT_SETUP_SEED 0u
#define PQ_SPEND_SLOT_CONTEXT 1u
#define PQ_SPEND_SLOT_PRIVATE_SEED 2u
#define PQ_SPEND_SLOT_A_IN 3u
#define PQ_SPEND_SLOT_PK_OUT 4u
#define PQ_SPEND_SLOT_SK_IN 5u
#define PQ_SPEND_SLOT_CK_IN 6u
#define PQ_SPEND_SLOT_SN_OUT 7u
#define PQ_SPEND_SLOT_SCALARS 8u
#define PQ_SPEND_SLOT_CN_OUT 9u
#define PQ_SPEND_SLOT_CK_OUT 10u
#define PQ_SPEND_SLOT_MAT1 11u
#define PQ_SPEND_SLOT_MAT2 12u
#define PQ_SPEND_SLOT_MAT3 13u
#define PQ_SPEND_SLOT_PP 14u
#define PQ_SPEND_SLOT_OUT 15u
#define PQ_SPEND_SLOT_A_HAT 16u
#define PQ_SPEND_SLOT_C 17u
#define PQ_SPEND_SLOT_DELTA 18u
#define PQ_SPEND_SLOT_MINT_NTT 19u
#define PQ_SPEND_SLOT_Y_OUT 20u
#define PQ_SPEND_SLOT_Y_OUT_NTT 21u
#define PQ_SPEND_SLOT_W_OUT 22u
#define PQ_SPEND_SLOT_Y0 23u
#define PQ_SPEND_SLOT_Y0_NTT 24u
#define PQ_SPEND_SLOT_W0 25u
#define PQ_SPEND_SLOT_A 26u
#define PQ_SPEND_SLOT_A_NTT 27u
#define PQ_SPEND_SLOT_A_NTT_QHAT 28u
#define PQ_SPEND_SLOT_TMP_R 29u
#define PQ_SPEND_SLOT_T_IN_SUM 30u
#define PQ_SPEND_SLOT_RHO 31u
#define PQ_SPEND_SLOT_RHO_NTT 32u
#define PQ_SPEND_SLOT_Y1 33u
#define PQ_SPEND_SLOT_Y2 34u
#define PQ_SPEND_SLOT_Y1_NTT 35u
#define PQ_SPEND_SLOT_Y2_NTT 36u
#define PQ_SPEND_SLOT_W1 37u
#define PQ_SPEND_SLOT_W2 38u
#define PQ_SPEND_SLOT_W 39u
#define PQ_SPEND_SLOT_TMP_Q 40u
#define PQ_SPEND_SLOT_A3Y1 41u
#define PQ_SPEND_SLOT_A3Y1_2 42u
#define PQ_SPEND_SLOT_B1YOUT 43u
#define PQ_SPEND_SLOT_ALPHA 44u
#define PQ_SPEND_SLOT_ALPHA_PRIME_0 45u
#define PQ_SPEND_SLOT_V0 46u
#define PQ_SPEND_SLOT_ALPHA_B1YOUT 47u
#define PQ_SPEND_SLOT_PK_HAT 48u
#define PQ_SPEND_SLOT_G_GAMMA 49u
#define PQ_SPEND_SLOT_P 50u
#define PQ_SPEND_SLOT_ALPHA_PRIME_0_NTT 51u
#define PQ_SPEND_SLOT_S 52u
#define PQ_SPEND_SLOT_A2_NTT 53u
#define PQ_SPEND_SLOT_RB 54u
#define PQ_SPEND_SLOT_RA 55u
#define PQ_SPEND_SLOT_RB_NTT 56u
#define PQ_SPEND_SLOT_RA_NTT 57u
#define PQ_SPEND_SLOT_A_RS 58u
#define PQ_SPEND_SLOT_Y 59u
#define PQ_SPEND_SLOT_Y_NTT 60u
#define PQ_SPEND_SLOT_E 61u
#define PQ_SPEND_SLOT_G 62u
#define PQ_SPEND_SLOT_F0 63u
#define PQ_SPEND_SLOT_TMP_AUT 64u
#define PQ_SPEND_SLOT_TMP_AUT_R 65u
#define PQ_SPEND_SLOT_X_DELTA 66u
#define PQ_SPEND_SLOT_X_S 67u
#define PQ_SPEND_SLOT_X_RB 68u
#define PQ_SPEND_SLOT_X_ROUT 69u
#define PQ_SPEND_SLOT_X_RI 70u
#define PQ_SPEND_SLOT_X_RHO 71u
#define PQ_SPEND_SLOT_X_AUT_RHO 72u
#define PQ_SPEND_SLOT_BYTE_WORK 73u
#define PQ_SPEND_SLOT_HASH_X_BYTES 74u
#define PQ_SPEND_SLOT_STATEMENT_BYTES 75u
#define PQ_SPEND_SLOT_PROOF_BYTES 76u
#define PQ_SPEND_SLOT_CONTROL 77u
#define PQ_SPEND_SLOT_COUNT 78u
__constant ulong pq_spend_slot_words[PQ_SPEND_SLOT_COUNT] = {
4ul,4ul,4ul,46080ul,2048ul,4096ul,4608ul,8ul,5ul,2560ul,4608ul,7168ul,3072ul,37120ul,4ul,23300ul,128ul,64ul,12ul,2304ul,4608ul,4608ul,2048ul,2304ul,2304ul,1024ul,3072ul,3072ul,3072ul,256ul,12800ul,2816ul,2816ul,2816ul,2816ul,2816ul,2816ul,1024ul,1024ul,256ul,256ul,256ul,256ul,512ul,512ul,256ul,256ul,512ul,20480ul,1024ul,10240ul,256ul,2048ul,3072ul,2560ul,2560ul,2560ul,2560ul,1280ul,2048ul,2048ul,1024ul,3072ul,256ul,256ul,256ul,2816ul,2048ul,2560ul,4608ul,2304ul,2816ul,2816ul,28812ul,18ul,25356ul,6700ul,4ul};
#define PQ_SPEND_INPUT_SETUP_SEED_BYTES 0ul
#define PQ_SPEND_INPUT_CONTEXT_BYTES 32ul
#define PQ_SPEND_INPUT_RING_POLYS 64ul
#define PQ_SPEND_INPUT_RECIPIENT_POLYS 46144ul
#define PQ_SPEND_INPUT_SPENDING_KEY_POLYS 48192ul
#define PQ_SPEND_INPUT_COMMITMENT_KEY_POLYS 52288ul
#define PQ_SPEND_INPUT_SERIAL_BYTES 56896ul
#define PQ_SPEND_INPUT_PRIVATE_SCALARS_INDEX_INPUTS_OUTPUTS 56960ul
#define PQ_SPEND_INPUT_FRESH_PRIVATE_AES_KEY_BYTES 56965ul
#define PQ_SPEND_INPUT_WORDS 56997ul
inline void pq_spend_error(__global uint *status,uint bits) {
    atomic_or((volatile __global uint*)status,bits);
}
inline int pq_spend_arena_ok(__global const ulong *offsets,uint slot_count,
                            ulong arena_words,__global uint *status) {
    if(slot_count!=PQ_SPEND_SLOT_COUNT) {pq_spend_error(status,1u);return 0;}
    for(uint i=0;i<PQ_SPEND_SLOT_COUNT;++i) {
        if(offsets[i]>arena_words || pq_spend_slot_words[i]>arena_words-offsets[i]) {
            pq_spend_error(status,1u);return 0;
        }
    }
    for(uint i=0;i<PQ_SPEND_SLOT_COUNT;++i) for(uint j=0;j<i;++j)
        if(offsets[i]<offsets[j]+pq_spend_slot_words[j] &&
           offsets[j]<offsets[i]+pq_spend_slot_words[i]) {
            pq_spend_error(status,1u);return 0;
        }
    return 1;
}
inline ulong pq_spend_abs(ulong x) {ulong mask=0ul-(x>>63);return (x^mask)+(x>>63);}
inline ulong pq_spend_eq(ulong a,ulong b) {ulong x=a^b;return 1ul-((x|(0ul-x))>>63);}
inline ulong pq_spend_lt(ulong a,ulong b) {return (a-b)>>63;}
inline void pq_spend_copy_poly(__global pq_private_poly *out,__global const pq_private_poly *in) {
    for(uint i=0;i<256;++i)out->poly[i]=in->poly[i];
}
inline void pq_spend_zero_poly(__global pq_private_poly *out) {
    for(uint i=0;i<256;++i)out->poly[i]=0;
}
inline int pq_spend_signed_bound(__global const pq_private_poly *in,ulong count,ulong bound,
                                 __global uint *status) {
    ulong bad=0;
    for(ulong i=0;i<count;++i)for(uint j=0;j<256;++j)bad|=(ulong)(pq_spend_abs(in[i].poly[j])>bound);
    if(bad)pq_spend_error(status,PQ_SPEND_ERROR_BOUND);
    return !bad;
}
#endif

// end pq_spend_abi.h
// begin pq_spend_math.cl
// Exact private-memory native Q/Qhat math; source hashes in base-sha256.json.




inline ulong pq_sref_con_sub(const ulong x, const ulong q) {
  return x - ((-(1 ^ ((x - q) >> 63))) & q);
}

inline ulong pq_sref_con_add(const ulong x, const ulong q) {
  return x + ((-(x >> 63)) & q);
}

inline ulong pq_sref_red_short_q(ulong t) {
  return pq_sref_con_add((t & PQ_SPEND_RED_SHORT_MASK_Q) -
                     ((t >> PQ_SPEND_RED_SHORT_SHIFT_1_Q) * PQ_SPEND_RED_SHORT_CONST_Q),
                 PQ_SPEND_Q);
}

/* Canonical reduction for 0 <= t < 7*PQ_SPEND_Q.  The fold before either correction
 * lies in (-2*PQ_SPEND_Q, PQ_SPEND_Q): floor(t / 2^27) <= 8 and 8*33552513 < 2*PQ_SPEND_Q.
 * A second conditional addition is required for the negative-carry v1 term.
 * Keep the original shorter-range reducer unchanged at its other call sites.
 */
inline ulong pq_sref_red_short_7q(ulong t) {
  return pq_sref_con_add(pq_sref_red_short_q(t), PQ_SPEND_Q);
}

inline ulong pq_sref_red_short_qhat(ulong t) {
  return pq_sref_con_sub((t & PQ_SPEND_RED_SHORT_MASK_QHAT) +
                     ((t >> PQ_SPEND_RED_SHORT_SHIFT_1_QHAT) * PQ_SPEND_RED_SHORT_CONST_QHAT),
                 PQ_SPEND_QHAT);
}



/* Montgomery reduction
 * Input: x < PQ_SPEND_Q*PQ_SPEND_R, where PQ_SPEND_R=2^k
 * Output: m = x*PQ_SPEND_R^{-1} % PQ_SPEND_Q
 *
 * b = PQ_SPEND_Q^{-1} % PQ_SPEND_R
 * t = ((x % PQ_SPEND_R)*b) % PQ_SPEND_R
 * m = x / PQ_SPEND_R - t * PQ_SPEND_Q / PQ_SPEND_R */
inline ulong pq_sref_montgomery(ulong a, ulong b, const ulong q,
                                  const ulong montgomery_factor,
                                  const ulong montgomery_shift,
                                  const ulong montgomery_mask) {
  ulong t, x, y;

  t = a * b;
  x = t & montgomery_mask;
  y = (x * montgomery_factor) & montgomery_mask;

  return pq_sref_con_add((t >> montgomery_shift) - ((y * q) >> montgomery_shift), q);
}

inline ulong pq_sref_montgomery_q(ulong a, ulong b) {
  return pq_sref_montgomery(a, b, PQ_SPEND_Q, PQ_SPEND_MONTGOMERY_FACTOR_Q, PQ_SPEND_MONTGOMERY_SHIFT_Q,
                    PQ_SPEND_MONTGOMERY_MASK_Q);
}

inline ulong pq_sref_montgomery_qhat(ulong a, ulong b) {
  return pq_sref_montgomery(a, b, PQ_SPEND_QHAT, PQ_SPEND_MONTGOMERY_FACTOR_QHAT, PQ_SPEND_MONTGOMERY_SHIFT_QHAT,
                    PQ_SPEND_MONTGOMERY_MASK_QHAT);
}

/* Barrett reduction
 * Input: x < 2^k
 * Output m = x % PQ_SPEND_Q in [0, 2Q)
 *
 * b = floor(2^k/PQ_SPEND_Q)
 * t = floor((x * b) / 2^k), where t is an estimation of x / PQ_SPEND_Q
 * m = x - t * PQ_SPEND_Q */
inline ulong pq_sref_barrett(const ulong x, const ulong q,
                               const ulong barrett_factor,
                               const ulong barrett_shift) {
  return pq_sref_con_sub(x - ((x * barrett_factor) >> barrett_shift) * q, q);
}



__constant ulong pq_sref_omega_q[PQ_SPEND_R] = {
    0,           25298509L,  16654445L,  105313793L, 123808285L,
    52751491L,  98449108L,  15315657L,  7313337L,   159716729L,
    19434864L,  64510017L,  157082068L, 138478139L, 153167634L,
    162331005L, 93193167L,  88710966L,  142824326L, 68055267L,
    143926375L, 2409315L,   55525686L,  1320151L,   132830388L,
    127359629L, 77393886L,  66119492L,  115649674L, 74322832L,
    38402839L,  133169436L, 88335286L,  99920198L,  164068287L,
    29239969L,  68974339L,  111338276L, 117209794L, 20738257L,
    74667747L,  127912654L, 140345503L, 44063037L,  118114731L,
    88157867L,  112738182L, 67712443L,  123200480L, 75774403L,
    3140516L,   12139007L,  125420424L, 140275625L, 108225137L,
    56438098L,  128481306L, 89488910L,  165713817L, 101098166L,
    89492208L,  117624798L, 129032747L, 56613722L};

__constant ulong pq_sref_perm_ntt[PQ_SPEND_R] = {
    0,  32, 8,  44, 5,  39, 13, 40, 2,  35, 10, 47, 7,  37, 15, 43,
    1,  33, 9,  45, 4,  38, 12, 41, 3,  34, 11, 46, 6,  36, 14, 42,
    63, 31, 55, 19, 58, 24, 50, 23, 61, 28, 53, 16, 56, 26, 48, 20,
    62, 30, 54, 18, 59, 25, 51, 22, 60, 29, 52, 17, 57, 27, 49, 21};

__constant ulong pq_sref_perm_inv_aut[PQ_SPEND_D] = {
    0,   3,   6,   9,   12,  15,  18,  21,  24,  27,  30,  33,  36,  39,  42,
    45,  48,  51,  54,  57,  60,  63,  66,  69,  72,  75,  78,  81,  84,  87,
    90,  93,  96,  99,  102, 105, 108, 111, 114, 117, 120, 123, 126, 129, 132,
    135, 138, 141, 144, 147, 150, 153, 156, 159, 162, 165, 168, 171, 174, 177,
    180, 183, 186, 189, 192, 195, 198, 201, 204, 207, 210, 213, 216, 219, 222,
    225, 228, 231, 234, 237, 240, 243, 246, 249, 252, 255, 2,   5,   8,   11,
    14,  17,  20,  23,  26,  29,  32,  35,  38,  41,  44,  47,  50,  53,  56,
    59,  62,  65,  68,  71,  74,  77,  80,  83,  86,  89,  92,  95,  98,  101,
    104, 107, 110, 113, 116, 119, 122, 125, 128, 131, 134, 137, 140, 143, 146,
    149, 152, 155, 158, 161, 164, 167, 170, 173, 176, 179, 182, 185, 188, 191,
    194, 197, 200, 203, 206, 209, 212, 215, 218, 221, 224, 227, 230, 233, 236,
    239, 242, 245, 248, 251, 254, 1,   4,   7,   10,  13,  16,  19,  22,  25,
    28,  31,  34,  37,  40,  43,  46,  49,  52,  55,  58,  61,  64,  67,  70,
    73,  76,  79,  82,  85,  88,  91,  94,  97,  100, 103, 106, 109, 112, 115,
    118, 121, 124, 127, 130, 133, 136, 139, 142, 145, 148, 151, 154, 157, 160,
    163, 166, 169, 172, 175, 178, 181, 184, 187, 190, 193, 196, 199, 202, 205,
    208, 211, 214, 217, 220, 223, 226, 229, 232, 235, 238, 241, 244, 247, 250,
    253};

__constant ulong pq_sref_omega_qhat[PQ_SPEND_R] = {0,
                                       1783426224L,
                                       2351192601L,
                                       1746590616L,
                                       3398309680L,
                                       1748669978L,
                                       1231514205L,
                                       3013816622L,
                                       1109357322L,
                                       1001963140L,
                                       119423006L,
                                       2779991497L,
                                       2908661274L,
                                       992186722L,
                                       167818709L,
                                       1498269039L,
                                       658934918L,
                                       2914796113L,
                                       3206411471L,
                                       798669888L,
                                       2269350985L,
                                       1435531734L,
                                       490445684L,
                                       1342098185L,
                                       1034782091L,
                                       694861507L,
                                       2287372836L,
                                       3001658505L,
                                       3120609358L,
                                       2280115831L,
                                       41486045L,
                                       3177221765L,
                                       2577100799L,
                                       2405279510L,
                                       2975400305L,
                                       1030567863L,
                                       2388041701L,
                                       1001362987L,
                                       1320506885L,
                                       1880364562L,
                                       280026387L,
                                       166102516L,
                                       3065396503L,
                                       306400228L,
                                       826469296L,
                                       2257662681L,
                                       946639311L,
                                       3367646933L,
                                       1105343673L,
                                       1152204420L,
                                       558218157L,
                                       1054335247L,
                                       1120818485L,
                                       1201796820L,
                                       1601846056L,
                                       2569540653L,
                                       38135503L,
                                       362293383L,
                                       1000961578L,
                                       930299718L,
                                       975114724L,
                                       2593543626L,
                                       789382750L,
                                       2762722401L};

/* in bit-reversed order */
inline void pq_sref_ntt_q_bitrev(pq_private_poly *a) {
  ulong t = PQ_SPEND_D >> 1, m, i, j, j_first, j_last;
  ulong u, v;

  /* implicitly convert to Montgomery form and perform the butterfly operations
   */
  for (i = 0; i < PQ_SPEND_D >> 1; i++) {
    u = pq_sref_montgomery_q(a->poly[i], PQ_SPEND_MONTGOMERY_CONVERT_FACTOR_Q);
    v = pq_sref_montgomery_q(a->poly[i + (PQ_SPEND_D >> 1)], pq_sref_omega_q[1]);

    a->poly[i] = pq_sref_con_sub(u + v, PQ_SPEND_Q);
    a->poly[i + (PQ_SPEND_D >> 1)] = pq_sref_con_add(u - v, PQ_SPEND_Q);
  }

  for (m = 2; m < PQ_SPEND_R; m <<= 1) {
    t >>= 1;
    for (i = 0; i < m; i++) {
      j_first = 2 * i * t;
      j_last = j_first + t;
      /* butterfly: (u,v)-->(u+v*omega,u-v*omega) */
      for (j = j_first; j < j_last; j++) {
        u = a->poly[j];
        v = pq_sref_montgomery_q(a->poly[j + t], pq_sref_omega_q[m + i]);

        a->poly[j] = pq_sref_con_sub(u + v, PQ_SPEND_Q);
        a->poly[j + t] = pq_sref_con_add(u - v, PQ_SPEND_Q);
      }
    }
  }
}

/* in the ordering (X - w^{(-1)^s * 3^r % 128}) for s = {0..1}, r = {0..31} */
inline void pq_sref_ntt_q(pq_private_poly *a) {
  pq_private_poly tmp;

  ulong i, j;

  tmp = *a;
  pq_sref_ntt_q_bitrev(&tmp);

  for (i = 0; i < PQ_SPEND_R; i++) {
    for (j = 0; j < PQ_SPEND_SUBRING_SIZE; j++) {
      a->poly[i * PQ_SPEND_SUBRING_SIZE + j] = tmp.poly[pq_sref_perm_ntt[i] * PQ_SPEND_SUBRING_SIZE + j];
    }
  }
}

inline void pq_sref_mult_4_plus_q(ulong *out, const ulong *a,
                                 const ulong *b, const ulong omega) {
  out[0] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[0]) +
                       pq_sref_montgomery_q(pq_sref_montgomery_q(a[1], b[3]) +
                                        pq_sref_montgomery_q(a[2], b[2]) +
                                        pq_sref_montgomery_q(a[3], b[1]),
                                    omega));
  out[1] = pq_sref_red_short_q(
      pq_sref_montgomery_q(a[0], b[1]) + pq_sref_montgomery_q(a[1], b[0]) +
      pq_sref_montgomery_q(pq_sref_montgomery_q(a[2], b[3]) + pq_sref_montgomery_q(a[3], b[2]), omega));
  out[2] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[2]) + pq_sref_montgomery_q(a[1], b[1]) +
                       pq_sref_montgomery_q(a[2], b[0]) +
                       pq_sref_montgomery_q(pq_sref_montgomery_q(a[3], b[3]), omega));
  out[3] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[3]) + pq_sref_montgomery_q(a[1], b[2]) +
                       pq_sref_montgomery_q(a[2], b[1]) + pq_sref_montgomery_q(a[3], b[0]));
}

inline void pq_sref_mult_4_minus_q(ulong *out, const ulong *a,
                                  const ulong *b, const ulong omega) {
  out[0] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[0]) + PQ_SPEND_Q -
                       pq_sref_montgomery_q(pq_sref_montgomery_q(a[1], b[3]) +
                                        pq_sref_montgomery_q(a[2], b[2]) +
                                        pq_sref_montgomery_q(a[3], b[1]),
                                    omega));
  out[1] = pq_sref_red_short_q(
      pq_sref_montgomery_q(a[0], b[1]) + pq_sref_montgomery_q(a[1], b[0]) + PQ_SPEND_Q -
      pq_sref_montgomery_q(pq_sref_montgomery_q(a[2], b[3]) + pq_sref_montgomery_q(a[3], b[2]), omega));
  out[2] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[2]) + pq_sref_montgomery_q(a[1], b[1]) +
                       pq_sref_montgomery_q(a[2], b[0]) + PQ_SPEND_Q -
                       pq_sref_montgomery_q(pq_sref_montgomery_q(a[3], b[3]), omega));
  out[3] = pq_sref_red_short_q(pq_sref_montgomery_q(a[0], b[3]) + pq_sref_montgomery_q(a[1], b[2]) +
                       pq_sref_montgomery_q(a[2], b[1]) + pq_sref_montgomery_q(a[3], b[0]));
}

/* in the ordering (X - w^{(-1)^s * 3^r % 128}) for s = {0..1}, r = {0..31} */
inline void pq_sref_mult_rq(pq_private_poly *out, const pq_private_poly *a, const pq_private_poly *b) {
  pq_sref_mult_4_plus_q(out->poly, a->poly, b->poly, pq_sref_omega_q[32]);
  pq_sref_mult_4_plus_q(out->poly + PQ_SPEND_SUBRING_SIZE, a->poly + PQ_SPEND_SUBRING_SIZE,
                b->poly + PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[48]);
  pq_sref_mult_4_plus_q(out->poly + 2 * PQ_SPEND_SUBRING_SIZE, a->poly + 2 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 2 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[36]);
  pq_sref_mult_4_plus_q(out->poly + 3 * PQ_SPEND_SUBRING_SIZE, a->poly + 3 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 3 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[54]);
  pq_sref_mult_4_minus_q(out->poly + 4 * PQ_SPEND_SUBRING_SIZE, a->poly + 4 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 4 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[34]);
  pq_sref_mult_4_minus_q(out->poly + 5 * PQ_SPEND_SUBRING_SIZE, a->poly + 5 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 5 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[51]);
  pq_sref_mult_4_minus_q(out->poly + 6 * PQ_SPEND_SUBRING_SIZE, a->poly + 6 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 6 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[38]);
  pq_sref_mult_4_plus_q(out->poly + 7 * PQ_SPEND_SUBRING_SIZE, a->poly + 7 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 7 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[52]);
  pq_sref_mult_4_plus_q(out->poly + 8 * PQ_SPEND_SUBRING_SIZE, a->poly + 8 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 8 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[33]);
  pq_sref_mult_4_minus_q(out->poly + 9 * PQ_SPEND_SUBRING_SIZE, a->poly + 9 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 9 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[49]);
  pq_sref_mult_4_plus_q(out->poly + 10 * PQ_SPEND_SUBRING_SIZE, a->poly + 10 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 10 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[37]);
  pq_sref_mult_4_minus_q(out->poly + 11 * PQ_SPEND_SUBRING_SIZE, a->poly + 11 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 11 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[55]);
  pq_sref_mult_4_minus_q(out->poly + 12 * PQ_SPEND_SUBRING_SIZE, a->poly + 12 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 12 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[35]);
  pq_sref_mult_4_minus_q(out->poly + 13 * PQ_SPEND_SUBRING_SIZE, a->poly + 13 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 13 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[50]);
  pq_sref_mult_4_minus_q(out->poly + 14 * PQ_SPEND_SUBRING_SIZE, a->poly + 14 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 14 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[39]);
  pq_sref_mult_4_minus_q(out->poly + 15 * PQ_SPEND_SUBRING_SIZE, a->poly + 15 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 15 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[53]);
  pq_sref_mult_4_minus_q(out->poly + 16 * PQ_SPEND_SUBRING_SIZE, a->poly + 16 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 16 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[32]);
  pq_sref_mult_4_minus_q(out->poly + 17 * PQ_SPEND_SUBRING_SIZE, a->poly + 17 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 17 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[48]);
  pq_sref_mult_4_minus_q(out->poly + 18 * PQ_SPEND_SUBRING_SIZE, a->poly + 18 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 18 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[36]);
  pq_sref_mult_4_minus_q(out->poly + 19 * PQ_SPEND_SUBRING_SIZE, a->poly + 19 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 19 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[54]);
  pq_sref_mult_4_plus_q(out->poly + 20 * PQ_SPEND_SUBRING_SIZE, a->poly + 20 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 20 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[34]);
  pq_sref_mult_4_plus_q(out->poly + 21 * PQ_SPEND_SUBRING_SIZE, a->poly + 21 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 21 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[51]);
  pq_sref_mult_4_plus_q(out->poly + 22 * PQ_SPEND_SUBRING_SIZE, a->poly + 22 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 22 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[38]);
  pq_sref_mult_4_minus_q(out->poly + 23 * PQ_SPEND_SUBRING_SIZE, a->poly + 23 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 23 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[52]);
  pq_sref_mult_4_minus_q(out->poly + 24 * PQ_SPEND_SUBRING_SIZE, a->poly + 24 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 24 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[33]);
  pq_sref_mult_4_plus_q(out->poly + 25 * PQ_SPEND_SUBRING_SIZE, a->poly + 25 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 25 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[49]);
  pq_sref_mult_4_minus_q(out->poly + 26 * PQ_SPEND_SUBRING_SIZE, a->poly + 26 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 26 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[37]);
  pq_sref_mult_4_plus_q(out->poly + 27 * PQ_SPEND_SUBRING_SIZE, a->poly + 27 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 27 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[55]);
  pq_sref_mult_4_plus_q(out->poly + 28 * PQ_SPEND_SUBRING_SIZE, a->poly + 28 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 28 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[35]);
  pq_sref_mult_4_plus_q(out->poly + 29 * PQ_SPEND_SUBRING_SIZE, a->poly + 29 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 29 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[50]);
  pq_sref_mult_4_plus_q(out->poly + 30 * PQ_SPEND_SUBRING_SIZE, a->poly + 30 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 30 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[39]);
  pq_sref_mult_4_plus_q(out->poly + 31 * PQ_SPEND_SUBRING_SIZE, a->poly + 31 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 31 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[53]);
  pq_sref_mult_4_minus_q(out->poly + 32 * PQ_SPEND_SUBRING_SIZE, a->poly + 32 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 32 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[63]);
  pq_sref_mult_4_minus_q(out->poly + 33 * PQ_SPEND_SUBRING_SIZE, a->poly + 33 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 33 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[47]);
  pq_sref_mult_4_minus_q(out->poly + 34 * PQ_SPEND_SUBRING_SIZE, a->poly + 34 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 34 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[59]);
  pq_sref_mult_4_minus_q(out->poly + 35 * PQ_SPEND_SUBRING_SIZE, a->poly + 35 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 35 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[41]);
  pq_sref_mult_4_plus_q(out->poly + 36 * PQ_SPEND_SUBRING_SIZE, a->poly + 36 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 36 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[61]);
  pq_sref_mult_4_plus_q(out->poly + 37 * PQ_SPEND_SUBRING_SIZE, a->poly + 37 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 37 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[44]);
  pq_sref_mult_4_plus_q(out->poly + 38 * PQ_SPEND_SUBRING_SIZE, a->poly + 38 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 38 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[57]);
  pq_sref_mult_4_minus_q(out->poly + 39 * PQ_SPEND_SUBRING_SIZE, a->poly + 39 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 39 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[43]);
  pq_sref_mult_4_minus_q(out->poly + 40 * PQ_SPEND_SUBRING_SIZE, a->poly + 40 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 40 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[62]);
  pq_sref_mult_4_plus_q(out->poly + 41 * PQ_SPEND_SUBRING_SIZE, a->poly + 41 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 41 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[46]);
  pq_sref_mult_4_minus_q(out->poly + 42 * PQ_SPEND_SUBRING_SIZE, a->poly + 42 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 42 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[58]);
  pq_sref_mult_4_plus_q(out->poly + 43 * PQ_SPEND_SUBRING_SIZE, a->poly + 43 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 43 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[40]);
  pq_sref_mult_4_plus_q(out->poly + 44 * PQ_SPEND_SUBRING_SIZE, a->poly + 44 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 44 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[60]);
  pq_sref_mult_4_plus_q(out->poly + 45 * PQ_SPEND_SUBRING_SIZE, a->poly + 45 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 45 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[45]);
  pq_sref_mult_4_plus_q(out->poly + 46 * PQ_SPEND_SUBRING_SIZE, a->poly + 46 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 46 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[56]);
  pq_sref_mult_4_plus_q(out->poly + 47 * PQ_SPEND_SUBRING_SIZE, a->poly + 47 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 47 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[42]);
  pq_sref_mult_4_plus_q(out->poly + 48 * PQ_SPEND_SUBRING_SIZE, a->poly + 48 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 48 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[63]);
  pq_sref_mult_4_plus_q(out->poly + 49 * PQ_SPEND_SUBRING_SIZE, a->poly + 49 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 49 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[47]);
  pq_sref_mult_4_plus_q(out->poly + 50 * PQ_SPEND_SUBRING_SIZE, a->poly + 50 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 50 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[59]);
  pq_sref_mult_4_plus_q(out->poly + 51 * PQ_SPEND_SUBRING_SIZE, a->poly + 51 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 51 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[41]);
  pq_sref_mult_4_minus_q(out->poly + 52 * PQ_SPEND_SUBRING_SIZE, a->poly + 52 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 52 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[61]);
  pq_sref_mult_4_minus_q(out->poly + 53 * PQ_SPEND_SUBRING_SIZE, a->poly + 53 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 53 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[44]);
  pq_sref_mult_4_minus_q(out->poly + 54 * PQ_SPEND_SUBRING_SIZE, a->poly + 54 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 54 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[57]);
  pq_sref_mult_4_plus_q(out->poly + 55 * PQ_SPEND_SUBRING_SIZE, a->poly + 55 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 55 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[43]);
  pq_sref_mult_4_plus_q(out->poly + 56 * PQ_SPEND_SUBRING_SIZE, a->poly + 56 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 56 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[62]);
  pq_sref_mult_4_minus_q(out->poly + 57 * PQ_SPEND_SUBRING_SIZE, a->poly + 57 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 57 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[46]);
  pq_sref_mult_4_plus_q(out->poly + 58 * PQ_SPEND_SUBRING_SIZE, a->poly + 58 * PQ_SPEND_SUBRING_SIZE,
                b->poly + 58 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[58]);
  pq_sref_mult_4_minus_q(out->poly + 59 * PQ_SPEND_SUBRING_SIZE, a->poly + 59 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 59 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[40]);
  pq_sref_mult_4_minus_q(out->poly + 60 * PQ_SPEND_SUBRING_SIZE, a->poly + 60 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 60 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[60]);
  pq_sref_mult_4_minus_q(out->poly + 61 * PQ_SPEND_SUBRING_SIZE, a->poly + 61 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 61 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[45]);
  pq_sref_mult_4_minus_q(out->poly + 62 * PQ_SPEND_SUBRING_SIZE, a->poly + 62 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 62 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[56]);
  pq_sref_mult_4_minus_q(out->poly + 63 * PQ_SPEND_SUBRING_SIZE, a->poly + 63 * PQ_SPEND_SUBRING_SIZE,
                 b->poly + 63 * PQ_SPEND_SUBRING_SIZE, pq_sref_omega_q[42]);
}

inline void pq_sref_aut_ntt_plus(ulong *out, const ulong *a, const ulong omega_pos) {
  out[0] = a[0];
  out[1] = pq_sref_montgomery_q(
      a[3], pq_sref_con_add((1 - 2 * (omega_pos & 0x1)) * pq_sref_omega_q[omega_pos >> 1], PQ_SPEND_Q));
  out[2] = pq_sref_montgomery_q(a[2], pq_sref_omega_q[omega_pos]);
  out[3] = a[1];
}

inline void pq_sref_aut_ntt_minus(ulong *out, const ulong *a, const ulong omega_pos) {
  out[0] = a[0];
  out[1] = pq_sref_montgomery_q(
      a[3], pq_sref_con_add((1 - 2 * (omega_pos & 0x1)) * pq_sref_omega_q[omega_pos >> 1], PQ_SPEND_Q));
  out[2] = PQ_SPEND_Q - pq_sref_montgomery_q(a[2], pq_sref_omega_q[omega_pos]);
  out[3] = a[1];
}

/* automorphism: \sigma_3(a) (on NTT domain) */
inline void pq_sref_aut(pq_private_poly *out, const pq_private_poly *a) {
  pq_private_poly tmp;

  ulong i;

  for (i = 0; i < (PQ_SPEND_D >> 1) - PQ_SPEND_SUBRING_SIZE; i++) {
    tmp.poly[i] = (a->poly)[i + PQ_SPEND_SUBRING_SIZE];
    tmp.poly[i + (PQ_SPEND_D >> 1)] = (a->poly)[i + (PQ_SPEND_D >> 1) + PQ_SPEND_SUBRING_SIZE];
  }
  for (i = 0; i < PQ_SPEND_SUBRING_SIZE; i++) {
    tmp.poly[(PQ_SPEND_D >> 1) - PQ_SPEND_SUBRING_SIZE + i] = (a->poly)[i];
    tmp.poly[PQ_SPEND_D - PQ_SPEND_SUBRING_SIZE + i] = (a->poly)[i + (PQ_SPEND_D >> 1)];
  }

  pq_sref_aut_ntt_plus(out->poly, tmp.poly, 32);
  pq_sref_aut_ntt_plus(out->poly + PQ_SPEND_SUBRING_SIZE, tmp.poly + PQ_SPEND_SUBRING_SIZE, 48);
  pq_sref_aut_ntt_plus(out->poly + 2 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 2 * PQ_SPEND_SUBRING_SIZE, 36);
  pq_sref_aut_ntt_plus(out->poly + 3 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 3 * PQ_SPEND_SUBRING_SIZE, 54);
  pq_sref_aut_ntt_minus(out->poly + 4 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 4 * PQ_SPEND_SUBRING_SIZE, 34);
  pq_sref_aut_ntt_minus(out->poly + 5 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 5 * PQ_SPEND_SUBRING_SIZE, 51);
  pq_sref_aut_ntt_minus(out->poly + 6 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 6 * PQ_SPEND_SUBRING_SIZE, 38);
  pq_sref_aut_ntt_plus(out->poly + 7 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 7 * PQ_SPEND_SUBRING_SIZE, 52);
  pq_sref_aut_ntt_plus(out->poly + 8 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 8 * PQ_SPEND_SUBRING_SIZE, 33);
  pq_sref_aut_ntt_minus(out->poly + 9 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 9 * PQ_SPEND_SUBRING_SIZE, 49);
  pq_sref_aut_ntt_plus(out->poly + 10 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 10 * PQ_SPEND_SUBRING_SIZE, 37);
  pq_sref_aut_ntt_minus(out->poly + 11 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 11 * PQ_SPEND_SUBRING_SIZE,
                55);
  pq_sref_aut_ntt_minus(out->poly + 12 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 12 * PQ_SPEND_SUBRING_SIZE,
                35);
  pq_sref_aut_ntt_minus(out->poly + 13 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 13 * PQ_SPEND_SUBRING_SIZE,
                50);
  pq_sref_aut_ntt_minus(out->poly + 14 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 14 * PQ_SPEND_SUBRING_SIZE,
                39);
  pq_sref_aut_ntt_minus(out->poly + 15 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 15 * PQ_SPEND_SUBRING_SIZE,
                53);
  pq_sref_aut_ntt_minus(out->poly + 16 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 16 * PQ_SPEND_SUBRING_SIZE,
                32);
  pq_sref_aut_ntt_minus(out->poly + 17 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 17 * PQ_SPEND_SUBRING_SIZE,
                48);
  pq_sref_aut_ntt_minus(out->poly + 18 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 18 * PQ_SPEND_SUBRING_SIZE,
                36);
  pq_sref_aut_ntt_minus(out->poly + 19 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 19 * PQ_SPEND_SUBRING_SIZE,
                54);
  pq_sref_aut_ntt_plus(out->poly + 20 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 20 * PQ_SPEND_SUBRING_SIZE, 34);
  pq_sref_aut_ntt_plus(out->poly + 21 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 21 * PQ_SPEND_SUBRING_SIZE, 51);
  pq_sref_aut_ntt_plus(out->poly + 22 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 22 * PQ_SPEND_SUBRING_SIZE, 38);
  pq_sref_aut_ntt_minus(out->poly + 23 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 23 * PQ_SPEND_SUBRING_SIZE,
                52);
  pq_sref_aut_ntt_minus(out->poly + 24 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 24 * PQ_SPEND_SUBRING_SIZE,
                33);
  pq_sref_aut_ntt_plus(out->poly + 25 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 25 * PQ_SPEND_SUBRING_SIZE, 49);
  pq_sref_aut_ntt_minus(out->poly + 26 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 26 * PQ_SPEND_SUBRING_SIZE,
                37);
  pq_sref_aut_ntt_plus(out->poly + 27 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 27 * PQ_SPEND_SUBRING_SIZE, 55);
  pq_sref_aut_ntt_plus(out->poly + 28 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 28 * PQ_SPEND_SUBRING_SIZE, 35);
  pq_sref_aut_ntt_plus(out->poly + 29 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 29 * PQ_SPEND_SUBRING_SIZE, 50);
  pq_sref_aut_ntt_plus(out->poly + 30 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 30 * PQ_SPEND_SUBRING_SIZE, 39);
  pq_sref_aut_ntt_plus(out->poly + 31 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 31 * PQ_SPEND_SUBRING_SIZE, 53);
  pq_sref_aut_ntt_minus(out->poly + 32 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 32 * PQ_SPEND_SUBRING_SIZE,
                63);
  pq_sref_aut_ntt_minus(out->poly + 33 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 33 * PQ_SPEND_SUBRING_SIZE,
                47);
  pq_sref_aut_ntt_minus(out->poly + 34 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 34 * PQ_SPEND_SUBRING_SIZE,
                59);
  pq_sref_aut_ntt_minus(out->poly + 35 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 35 * PQ_SPEND_SUBRING_SIZE,
                41);
  pq_sref_aut_ntt_plus(out->poly + 36 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 36 * PQ_SPEND_SUBRING_SIZE, 61);
  pq_sref_aut_ntt_plus(out->poly + 37 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 37 * PQ_SPEND_SUBRING_SIZE, 44);
  pq_sref_aut_ntt_plus(out->poly + 38 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 38 * PQ_SPEND_SUBRING_SIZE, 57);
  pq_sref_aut_ntt_minus(out->poly + 39 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 39 * PQ_SPEND_SUBRING_SIZE,
                43);
  pq_sref_aut_ntt_minus(out->poly + 40 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 40 * PQ_SPEND_SUBRING_SIZE,
                62);
  pq_sref_aut_ntt_plus(out->poly + 41 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 41 * PQ_SPEND_SUBRING_SIZE, 46);
  pq_sref_aut_ntt_minus(out->poly + 42 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 42 * PQ_SPEND_SUBRING_SIZE,
                58);
  pq_sref_aut_ntt_plus(out->poly + 43 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 43 * PQ_SPEND_SUBRING_SIZE, 40);
  pq_sref_aut_ntt_plus(out->poly + 44 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 44 * PQ_SPEND_SUBRING_SIZE, 60);
  pq_sref_aut_ntt_plus(out->poly + 45 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 45 * PQ_SPEND_SUBRING_SIZE, 45);
  pq_sref_aut_ntt_plus(out->poly + 46 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 46 * PQ_SPEND_SUBRING_SIZE, 56);
  pq_sref_aut_ntt_plus(out->poly + 47 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 47 * PQ_SPEND_SUBRING_SIZE, 42);
  pq_sref_aut_ntt_plus(out->poly + 48 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 48 * PQ_SPEND_SUBRING_SIZE, 63);
  pq_sref_aut_ntt_plus(out->poly + 49 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 49 * PQ_SPEND_SUBRING_SIZE, 47);
  pq_sref_aut_ntt_plus(out->poly + 50 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 50 * PQ_SPEND_SUBRING_SIZE, 59);
  pq_sref_aut_ntt_plus(out->poly + 51 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 51 * PQ_SPEND_SUBRING_SIZE, 41);
  pq_sref_aut_ntt_minus(out->poly + 52 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 52 * PQ_SPEND_SUBRING_SIZE,
                61);
  pq_sref_aut_ntt_minus(out->poly + 53 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 53 * PQ_SPEND_SUBRING_SIZE,
                44);
  pq_sref_aut_ntt_minus(out->poly + 54 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 54 * PQ_SPEND_SUBRING_SIZE,
                57);
  pq_sref_aut_ntt_plus(out->poly + 55 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 55 * PQ_SPEND_SUBRING_SIZE, 43);
  pq_sref_aut_ntt_plus(out->poly + 56 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 56 * PQ_SPEND_SUBRING_SIZE, 62);
  pq_sref_aut_ntt_minus(out->poly + 57 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 57 * PQ_SPEND_SUBRING_SIZE,
                46);
  pq_sref_aut_ntt_plus(out->poly + 58 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 58 * PQ_SPEND_SUBRING_SIZE, 58);
  pq_sref_aut_ntt_minus(out->poly + 59 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 59 * PQ_SPEND_SUBRING_SIZE,
                40);
  pq_sref_aut_ntt_minus(out->poly + 60 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 60 * PQ_SPEND_SUBRING_SIZE,
                60);
  pq_sref_aut_ntt_minus(out->poly + 61 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 61 * PQ_SPEND_SUBRING_SIZE,
                45);
  pq_sref_aut_ntt_minus(out->poly + 62 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 62 * PQ_SPEND_SUBRING_SIZE,
                56);
  pq_sref_aut_ntt_minus(out->poly + 63 * PQ_SPEND_SUBRING_SIZE, tmp.poly + 63 * PQ_SPEND_SUBRING_SIZE,
                42);
}

/* automorphism inverse: \sigma_{171}(a) (in PQ_SPEND_R) */
inline void pq_sref_iaut_r(pq_private_poly *out, const pq_private_poly *a) {
  ulong i;

  for (i = 0; i < PQ_SPEND_D; i++) {
    (out->poly)[i] = (a->poly)[pq_sref_perm_inv_aut[i]];
  }
  for (i = 86; i < 171; i++) {
    (out->poly)[i] = -(out->poly)[i];
  }
}

/* in bit-reversed order (seems there is no need to permute) */
inline void pq_sref_ntt_qhat(pq_private_poly *a) {
  ulong t = PQ_SPEND_D >> 1, m, i, j, j_first, j_last;
  ulong u, v;

  /* implicitly convert to Montgomery form and perform the butterfly operations
   */
  for (i = 0; i < PQ_SPEND_D >> 1; i++) {
    u = pq_sref_montgomery_qhat(a->poly[i], PQ_SPEND_MONTGOMERY_CONVERT_FACTOR_QHAT);
    v = pq_sref_montgomery_qhat(a->poly[i + (PQ_SPEND_D >> 1)], pq_sref_omega_qhat[1]);

    a->poly[i] = pq_sref_con_sub(u + v, PQ_SPEND_QHAT);
    a->poly[i + (PQ_SPEND_D >> 1)] = pq_sref_con_add(u - v, PQ_SPEND_QHAT);
  }

  for (m = 2; m < PQ_SPEND_R; m <<= 1) {
    t >>= 1;
    for (i = 0; i < m; i++) {
      j_first = 2 * i * t;
      j_last = j_first + t;
      /* butterfly: (u,v)-->(u+v*omega,u-v*omega) */
      for (j = j_first; j < j_last; j++) {
        u = a->poly[j];
        v = pq_sref_montgomery_qhat(a->poly[j + t], pq_sref_omega_qhat[m + i]);

        a->poly[j] = pq_sref_con_sub(u + v, PQ_SPEND_QHAT);
        a->poly[j + t] = pq_sref_con_add(u - v, PQ_SPEND_QHAT);
      }
    }
  }
}

inline void pq_sref_mult_4_plus_qhat(ulong *out, const ulong *a,
                                    const ulong *b, const ulong omega) {
  out[0] = pq_sref_red_short_qhat(
      pq_sref_montgomery_qhat(a[0], b[0]) +
      pq_sref_montgomery_qhat(pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[1], b[3]) +
                                     pq_sref_montgomery_qhat(a[2], b[2]) +
                                     pq_sref_montgomery_qhat(a[3], b[1])),
                      omega));
  out[1] = pq_sref_red_short_qhat(
      pq_sref_montgomery_qhat(a[0], b[1]) + pq_sref_montgomery_qhat(a[1], b[0]) +
      pq_sref_montgomery_qhat(pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[2], b[3]) +
                                     pq_sref_montgomery_qhat(a[3], b[2])),
                      omega));
  out[2] =
      pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[0], b[2]) + pq_sref_montgomery_qhat(a[1], b[1]) +
                     pq_sref_montgomery_qhat(a[2], b[0]) +
                     pq_sref_montgomery_qhat(pq_sref_montgomery_qhat(a[3], b[3]), omega));
  out[3] =
      pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[0], b[3]) + pq_sref_montgomery_qhat(a[1], b[2]) +
                     pq_sref_montgomery_qhat(a[2], b[1]) + pq_sref_montgomery_qhat(a[3], b[0]));
}

inline void pq_sref_mult_4_minus_qhat(ulong *out, const ulong *a,
                                     const ulong *b, const ulong omega) {
  out[0] = pq_sref_red_short_qhat(
      pq_sref_montgomery_qhat(a[0], b[0]) + PQ_SPEND_QHAT -
      pq_sref_montgomery_qhat(pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[1], b[3]) +
                                     pq_sref_montgomery_qhat(a[2], b[2]) +
                                     pq_sref_montgomery_qhat(a[3], b[1])),
                      omega));
  out[1] = pq_sref_red_short_qhat(
      pq_sref_montgomery_qhat(a[0], b[1]) + pq_sref_montgomery_qhat(a[1], b[0]) + PQ_SPEND_QHAT -
      pq_sref_montgomery_qhat(pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[2], b[3]) +
                                     pq_sref_montgomery_qhat(a[3], b[2])),
                      omega));
  out[2] =
      pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[0], b[2]) + pq_sref_montgomery_qhat(a[1], b[1]) +
                     pq_sref_montgomery_qhat(a[2], b[0]) + PQ_SPEND_QHAT -
                     pq_sref_montgomery_qhat(pq_sref_montgomery_qhat(a[3], b[3]), omega));
  out[3] =
      pq_sref_red_short_qhat(pq_sref_montgomery_qhat(a[0], b[3]) + pq_sref_montgomery_qhat(a[1], b[2]) +
                     pq_sref_montgomery_qhat(a[2], b[1]) + pq_sref_montgomery_qhat(a[3], b[0]));
}

/* in bit-reversed order */
inline void pq_sref_mult_rqhat(pq_private_poly *out, const pq_private_poly *a, const pq_private_poly *b) {
  ulong i;

  for (i = 0; i < (PQ_SPEND_R >> 1); i++) {
    pq_sref_mult_4_plus_qhat(out->poly + i * PQ_SPEND_SUBRING_SIZE * 2,
                     a->poly + i * PQ_SPEND_SUBRING_SIZE * 2,
                     b->poly + i * PQ_SPEND_SUBRING_SIZE * 2, pq_sref_omega_qhat[(PQ_SPEND_R >> 1) + i]);
    pq_sref_mult_4_minus_qhat(out->poly + i * PQ_SPEND_SUBRING_SIZE * 2 + PQ_SPEND_SUBRING_SIZE,
                      a->poly + i * PQ_SPEND_SUBRING_SIZE * 2 + PQ_SPEND_SUBRING_SIZE,
                      b->poly + i * PQ_SPEND_SUBRING_SIZE * 2 + PQ_SPEND_SUBRING_SIZE,
                      pq_sref_omega_qhat[(PQ_SPEND_R >> 1) + i]);
  }
}

inline void pq_spend_ntt_q(__global pq_private_poly *a) {
    pq_private_poly tmp;
    for(uint i=0;i<256;++i)tmp.poly[i]=a->poly[i];
    pq_sref_ntt_q(&tmp);
    for(uint i=0;i<256;++i)a->poly[i]=tmp.poly[i];
}

inline void pq_spend_ntt_qhat(__global pq_private_poly *a) {
    pq_private_poly tmp;
    for(uint i=0;i<256;++i)tmp.poly[i]=a->poly[i];
    pq_sref_ntt_qhat(&tmp);
    for(uint i=0;i<256;++i)a->poly[i]=tmp.poly[i];
}

inline void pq_spend_aut(__global pq_private_poly *out,__global const pq_private_poly *a) {
    pq_private_poly x,result;
    for(uint i=0;i<256;++i)x.poly[i]=a->poly[i];
    pq_sref_aut(&result,&x);
    for(uint i=0;i<256;++i)out->poly[i]=result.poly[i];
}

inline void pq_spend_iaut_r(__global pq_private_poly *out,__global const pq_private_poly *a) {
    pq_private_poly x,result;
    for(uint i=0;i<256;++i)x.poly[i]=a->poly[i];
    pq_sref_iaut_r(&result,&x);
    for(uint i=0;i<256;++i)out->poly[i]=result.poly[i];
}

inline void pq_spend_mult_rq(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rq(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=result.poly[i];
}
inline void pq_spend_mult_plus_rq(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rq(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=pq_sref_con_sub(out->poly[i]+result.poly[i],PQ_SPEND_Q);
}
inline void pq_spend_mult_minus_rq(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rq(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=pq_sref_con_add(out->poly[i]-result.poly[i],PQ_SPEND_Q);
}

inline void pq_spend_mult_rqhat(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rqhat(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=result.poly[i];
}
inline void pq_spend_mult_plus_rqhat(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rqhat(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=pq_sref_con_sub(out->poly[i]+result.poly[i],PQ_SPEND_QHAT);
}
inline void pq_spend_mult_minus_rqhat(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rqhat(&result,&x,&y);
    for(uint i=0;i<256;++i)out->poly[i]=pq_sref_con_add(out->poly[i]-result.poly[i],PQ_SPEND_QHAT);
}

inline void pq_spend_mult_plus_rqhat_pm(__global pq_private_poly *out,
        __global const pq_private_poly *a,__global const pq_private_poly *b,ulong pm) {
    pq_private_poly x,y,result;
    for(uint i=0;i<256;++i){x.poly[i]=a->poly[i];y.poly[i]=b->poly[i];}
    pq_sref_mult_rqhat(&result,&x,&y);
    ulong sign=1ul-2ul*pm;
    for(uint i=0;i<256;++i)out->poly[i]=pq_sref_con_sub(
        pq_sref_con_add(out->poly[i]+sign*result.poly[i],PQ_SPEND_QHAT),PQ_SPEND_QHAT);
}
// Inputs are bounded before any multiply. 256 * 2^23 * 2^23 = 2^54,
// so each signed product and each sum fits i64. Products/sums use defined
// unsigned bitpattern arithmetic anyway; no signed-overflow UB is possible.
inline void pq_spend_mult_r(__global pq_private_poly *out,__global const pq_private_poly *a,
                            __global const pq_private_poly *b,__global uint *status) {
    if(!pq_spend_signed_bound(a,1,1ul<<23,status) ||
       !pq_spend_signed_bound(b,1,1ul<<23,status))return;
    ulong result[256];
    for(uint k=0;k<256;++k) {
        ulong sum=0;
        for(uint i=0;i<256;++i) {
            uint j=(k+256-i)&255;
            ulong product=a->poly[i]*b->poly[j];
            sum+=i<=k?product:0ul-product;
        }
        result[k]=sum;
    }
    for(uint k=0;k<256;++k)out->poly[k]=result[k];
}
inline void pq_spend_mult_fxf(__global pq_private_poly *out,__global const pq_private_poly *f,
                             __global const pq_private_poly *x,__global uint *status) {
    if(!pq_spend_signed_bound(f,1,(1ul<<23)-1,status) ||
       !pq_spend_signed_bound(x,1,1,status))return;
    ulong result[256];
    for(uint k=0;k<256;++k) {
        ulong sum=0;
        for(uint i=0;i<256;++i) {
            uint j=(k+256-i)&255;
            ulong product=f->poly[i]*(x->poly[j]-f->poly[j]);
            sum+=i<=k?product:0ul-product;
        }
        result[k]=sum;
    }
    for(uint k=0;k<256;++k)out->poly[k]=result[k];
}

// end pq_spend_math.cl
// begin pq_spend_keccak.cl
// Exact existing helper prefix; no AIR program dependency.
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

// end pq_spend_keccak.cl
// begin pq_spend_transcript.cl
// Scalar helpers reuse the exact Keccak permutation and sampler's table-free AES.
// All byte spans remain in the resident arena. Callers supply fixed checked spans.
inline void pq_spend_store32(__global uchar *dst,ulong value) {
    for(uint j=0;j<4;++j)dst[j]=(uchar)(value>>(8*j));
}
inline ulong pq_spend_load_bytes(__global const uchar *src,uint count) {
    ulong value=0;for(uint j=0;j<count;++j)value|=((ulong)src[j])<<(8*j);return value;
}
inline void pq_spend_shake(__global const uchar *src,ulong length,
                           __global uchar *dst,ulong output_length) {
    ulong state[25]={0},rotated[25];
    ulong blocks=length/136+1;
    for(ulong block=0;block<blocks;++block) {
        ulong offset=block*136;
        uint take=(uint)min((ulong)136,length-offset);
        for(uint j=0;j<take;++j)state[j/8]^=((ulong)src[offset+j])<<(8*(j%8));
        if(block+1==blocks) {
            state[take/8]^=0x1ful<<(8*(take%8));state[16]^=0x8000000000000000ul;
        }
        for(uint round=0;round<24;++round)pq_keccak_round(state,rotated,round);
    }
    for(ulong offset=0;offset<output_length;offset+=136) {
        uint take=(uint)min((ulong)136,output_length-offset);
        for(uint j=0;j<take;++j)dst[offset+j]=(uchar)(state[j/8]>>(8*(j%8)));
        if(offset+take<output_length)
            for(uint round=0;round<24;++round)pq_keccak_round(state,rotated,round);
    }
    // Explicit volatile wipe covers these declared arrays, not arbitrary compiler copies.
    for(uint j=0;j<25;++j) {
        ((__private volatile ulong*)state)[j]=0;
        ((__private volatile ulong*)rotated)[j]=0;
    }
}
inline void pq_spend_aes_bytes(__global const uchar *key,ulong domain,uint counter,
    __global uchar *dst,ulong count,__global uint *status) {
    ulong blocks=(count+15)/16;
    if(blocks>0x100000000ul-(ulong)counter) {pq_spend_error(status,16u);return;}
    pq_private_rng_state rng;
    // Initialization only; this independent public/challenge stream never advances
    // the private sampler stream. Exact AES helper definitions are supplied by sampler.
    for(ulong j=0;j<sizeof(rng);++j)((__private uchar*)&rng)[j]=0;
    pq_private_expand_key(&rng,key);
    for(ulong block=0;block<blocks;++block) {
        uchar iv[16]={0},encrypted[16];uint ctr=counter+(uint)block;
        for(uint j=0;j<4;++j)iv[j]=(uchar)(ctr>>(8*j));
        for(uint j=0;j<8;++j)iv[8+j]=(uchar)(domain>>(8*j));
        pq_private_aes_encrypt16(&rng,iv,encrypted);
        for(uint j=0;j<16 && block*16+j<count;++j)dst[block*16+j]=encrypted[j];
        for(uint j=0;j<16;++j)((__private volatile uchar*)encrypted)[j]=0;
    }
    for(ulong j=0;j<sizeof(rng);++j)((__private volatile uchar*)&rng)[j]=0;
}
inline ulong pq_spend_uniform_one(__global const uchar *bytes,ulong length,
    __private ulong *cursor,uint width,ulong limit,ulong modulus,__global uint *status) {
    while(*cursor<=length && width<=length-*cursor) {
        ulong value=pq_spend_load_bytes(bytes+*cursor,width);*cursor+=width;
        if(value<limit)return value%modulus;
    }
    pq_spend_error(status,PQ_SPEND_ERROR_BOUND);return 0;
}
inline ulong pq_spend_pack_poly32(__global uchar *dst,ulong cursor,
    __global const pq_private_poly *polys,ulong count,ulong modulus,__global uint *status) {
    for(ulong i=0;i<count;++i)for(uint j=0;j<256;++j) {
        ulong value=polys[i].poly[j];
        if(value>=modulus)pq_spend_error(status,PQ_SPEND_ERROR_CANONICAL);
        pq_spend_store32(dst+cursor,value);cursor+=4;
    }
    return cursor;
}
inline ulong pq_spend_copy_bytes(__global uchar *dst,ulong cursor,
                                 __global const uchar *src,ulong count) {
    for(ulong i=0;i<count;++i)dst[cursor++]=src[i];return cursor;
}
// Sparse position decisions are transcript-derived. Avoid index-addressed writes
// and used[position] tables anyway: positions are private until acceptance.
inline void pq_spend_sparse(__global const uchar *bytes,ulong length,uint is_alpha,
    __global pq_private_poly *dst,__global uint *status) {
    uint count=is_alpha?39u:44u, sign_bytes=is_alpha?5u:6u;
    ulong signs=pq_spend_load_bytes(bytes,sign_bytes),cursor=sign_bytes;
    uint positions[44],used=0;
    for(uint n=0;n<count;++n) {
        uint group=is_alpha?0u:(n<4u?n:(n-4u)/10u);
        uint candidate=0,duplicate=1;
        while(duplicate) {
            if(cursor>=length) {pq_spend_error(status,PQ_SPEND_ERROR_BOUND);return;}
            uint byte=bytes[cursor++];candidate=is_alpha?byte:((byte&63u)*4u+group);
            duplicate=0;
            for(uint i=0;i<used;++i)duplicate|=(uint)(positions[i]==candidate);
        }
        positions[used++]=candidate;
    }
    for(uint coefficient=0;coefficient<256;++coefficient) {
        ulong value=0;
        for(uint n=0;n<count;++n) {
            ulong mask=0ul-(ulong)(positions[n]==coefficient);
            value|=mask&(1ul-2ul*((signs>>n)&1ul));
        }
        dst->poly[coefficient]=value;
    }
    for(uint n=0;n<44;++n)((__private volatile uint*)positions)[n]=0;
}
inline void pq_spend_put_bits(__global uchar *dst,__private ulong *cursor,
    ulong value,uint width,__global uint *status) {
    if(width>32 || *cursor>428800ul || width>428800ul-*cursor ||
       (width<64 && (value>>width))) {pq_spend_error(status,4u);return;}
    for(uint i=0;i<width;++i,++*cursor)dst[*cursor/8]|=(uchar)(((value>>i)&1ul)<<(*cursor%8));
}
inline void pq_spend_public_bits(__global uchar *dst,__private ulong *cursor,
    __global const pq_private_poly *src,uint count,uint width,ulong modulus,__global uint *status) {
    for(uint i=0;i<count;++i)for(uint j=0;j<256;++j) {
        ulong value=src[i].poly[j];
        if(value>=modulus){pq_spend_error(status,2u);return;}
        pq_spend_put_bits(dst,cursor,value,width,status);
    }
}
inline void pq_spend_signed_bits(__global uchar *dst,__private ulong *cursor,
    __global const pq_private_poly *src,uint count,uint width,ulong bound,__global uint *status) {
    for(uint i=0;i<count;++i)for(uint j=0;j<256;++j) {
        ulong value=src[i].poly[j];
        if(pq_spend_abs(value)>bound){pq_spend_error(status,4u);return;}
        pq_spend_put_bits(dst,cursor,value+bound,width,status);
    }
}

#define pq_sc_setup_seed ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_SETUP_SEED]))
#define pq_sc_context ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_CONTEXT]))
#define pq_sc_private_seed ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PRIVATE_SEED]))
#define pq_sc_a_in ((__global pq_spend_act (*)[2])(arena+offsets[PQ_SPEND_SLOT_A_IN]))
#define pq_sc_pk_out ((__global pq_spend_pk*)(arena+offsets[PQ_SPEND_SLOT_PK_OUT]))
#define pq_sc_sk_in ((__global pq_private_poly (*)[8])(arena+offsets[PQ_SPEND_SLOT_SK_IN]))
#define pq_sc_ck_in ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_CK_IN]))
#define pq_sc_sn_out ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_SN_OUT]))
#define pq_sc_scalars ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_SCALARS]))
#define pq_sc_cn_out ((__global pq_spend_cn*)(arena+offsets[PQ_SPEND_SLOT_CN_OUT]))
#define pq_sc_ck_out ((__global pq_spend_ck*)(arena+offsets[PQ_SPEND_SLOT_CK_OUT]))
#define pq_sc_mat1 ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_MAT1]))
#define pq_sc_mat2 ((__global pq_private_poly (*)[3])(arena+offsets[PQ_SPEND_SLOT_MAT2]))
#define pq_sc_mat3 ((__global pq_private_poly (*)[5])(arena+offsets[PQ_SPEND_SLOT_MAT3]))
#define pq_sc_pp ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PP]))
#define pq_sc_out ((__global pq_spend_proof*)(arena+offsets[PQ_SPEND_SLOT_OUT]))
#define pq_sc_a_hat ((__global ulong (*)[64])(arena+offsets[PQ_SPEND_SLOT_A_HAT]))
#define pq_sc_c ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_C]))
#define pq_sc_delta ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_DELTA]))
#define pq_sc_mint_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_MINT_NTT]))
#define pq_sc_y_out ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_Y_OUT]))
#define pq_sc_y_out_ntt ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_Y_OUT_NTT]))
#define pq_sc_w_out ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_W_OUT]))
#define pq_sc_y0 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y0]))
#define pq_sc_y0_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y0_NTT]))
#define pq_sc_w0 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W0]))
#define pq_sc_a ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A]))
#define pq_sc_a_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_NTT]))
#define pq_sc_a_ntt_qhat ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_NTT_QHAT]))
#define pq_sc_tmp_r (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_R]))
#define pq_sc_t_in_sum ((__global pq_private_poly (*)[5])(arena+offsets[PQ_SPEND_SLOT_T_IN_SUM]))
#define pq_sc_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RHO]))
#define pq_sc_rho_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RHO_NTT]))
#define pq_sc_y1 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y1]))
#define pq_sc_y2 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y2]))
#define pq_sc_y1_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y1_NTT]))
#define pq_sc_y2_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y2_NTT]))
#define pq_sc_w1 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W1]))
#define pq_sc_w2 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W2]))
#define pq_sc_w (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W]))
#define pq_sc_tmp_q (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_Q]))
#define pq_sc_a3y1 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A3Y1]))
#define pq_sc_a3y1_2 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A3Y1_2]))
#define pq_sc_b1yout ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_B1YOUT]))
#define pq_sc_alpha ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA]))
#define pq_sc_alpha_prime_0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_PRIME_0]))
#define pq_sc_v0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_V0]))
#define pq_sc_alpha_b1yout ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_B1YOUT]))
#define pq_sc_pk_hat ((__global pq_private_poly (*)[2][4])(arena+offsets[PQ_SPEND_SLOT_PK_HAT]))
#define pq_sc_g_gamma ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_G_GAMMA]))
#define pq_sc_p ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_P]))
#define pq_sc_alpha_prime_0_ntt (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_PRIME_0_NTT]))
#define pq_sc_s ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_S]))
#define pq_sc_a2_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A2_NTT]))
#define pq_sc_rb ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RB]))
#define pq_sc_ra ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RA]))
#define pq_sc_rb_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RB_NTT]))
#define pq_sc_ra_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RA_NTT]))
#define pq_sc_a_rs ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_RS]))
#define pq_sc_y ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y]))
#define pq_sc_y_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y_NTT]))
#define pq_sc_e ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_E]))
#define pq_sc_g ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_G]))
#define pq_sc_f0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_F0]))
#define pq_sc_tmp_aut (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_AUT]))
#define pq_sc_tmp_aut_r (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_AUT_R]))
#define pq_sc_x_delta ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_DELTA]))
#define pq_sc_x_s ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_S]))
#define pq_sc_x_rb ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RB]))
#define pq_sc_x_rout ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_X_ROUT]))
#define pq_sc_x_ri ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RI]))
#define pq_sc_x_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RHO]))
#define pq_sc_x_aut_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_AUT_RHO]))
#define pq_sc_byte_work ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_BYTE_WORK]))
#define pq_sc_hash_x_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_HASH_X_BYTES]))
#define pq_sc_statement_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_STATEMENT_BYTES]))
#define pq_sc_proof_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PROOF_BYTES]))
#define pq_sc_control ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_CONTROL]))
inline void pq_spend_hash_alpha(__global ulong *arena,__global const ulong *offsets,
                                __global uint *status) {
    ulong cursor=0;
    cursor=pq_spend_copy_bytes(pq_sc_byte_work,cursor,pq_sc_pp,32);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,(__global pq_private_poly*)pq_sc_a_in,180,PQ_SPEND_Q,status);
    cursor=pq_spend_copy_bytes(pq_sc_byte_work,cursor,pq_sc_sn_out,64);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,(__global pq_private_poly*)pq_sc_pk_out,8,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,(__global pq_private_poly*)pq_sc_cn_out,10,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,(__global pq_private_poly*)pq_sc_w_out,8,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_w0,4,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_out->v,4,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,&pq_sc_out->v2,1,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,&pq_sc_out->c,1,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,&pq_sc_w,1,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_w1,4,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_w2,4,PQ_SPEND_Q,status);
    if(cursor!=230496ul){pq_spend_error(status,128u);return;}
    if(!status[0])pq_spend_shake(pq_sc_byte_work,cursor,pq_sc_out->alpha,32);
}
inline void pq_spend_expand_alpha(__global ulong *arena,__global const ulong *offsets,
                                  __global uint *status) {
    if(status[0])return;
    pq_spend_aes_bytes(pq_sc_out->alpha,0x4368ul,0,pq_sc_byte_work,2572,status);
    ulong cursor=0;
    for(uint i=0;i<2;++i)for(uint j=0;j<256;++j)
        pq_sc_alpha[i].poly[j]=pq_spend_uniform_one(pq_sc_byte_work,2572,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
    if(status[0])return;
    // First request is ceil(2572/16)=161 whole blocks. Its 4-byte tail is discarded.
    pq_spend_aes_bytes(pq_sc_out->alpha,0x4368ul,161,pq_sc_byte_work,127,status);
    pq_spend_sparse(pq_sc_byte_work,127,1,&pq_sc_alpha_prime_0,status);
}
inline void pq_spend_hash_x(__global ulong *arena,__global const ulong *offsets,
                            __global uint *status) {
    ulong cursor=0;
    cursor=pq_spend_copy_bytes(pq_sc_byte_work,cursor,pq_sc_out->alpha,32);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,&pq_sc_v0,1,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,&pq_sc_out->v1,1,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_a_rs,5,PQ_SPEND_QHAT,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_out->b,5,PQ_SPEND_QHAT,status);
    cursor=pq_spend_pack_poly32(pq_sc_byte_work,cursor,pq_sc_e,4,PQ_SPEND_Q,status);
    if(cursor!=16416ul){pq_spend_error(status,128u);return;}
    if(status[0])return;
    pq_spend_shake(pq_sc_byte_work,cursor,pq_sc_hash_x_bytes,137);
    pq_spend_sparse(pq_sc_hash_x_bytes,137,0,&pq_sc_out->x,status);
}

__kernel void pq_spend_import(__global const ulong *packed,ulong packed_words,
    __global ulong *arena,ulong arena_words,__global const ulong *offsets,
    uint slot_count,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || packed_words!=PQ_SPEND_INPUT_WORDS ||
       !pq_spend_arena_ok(offsets,slot_count,arena_words,status)) {
        pq_spend_error(status,1u);return;
    }
    for(uint slot=0;slot<PQ_SPEND_SLOT_COUNT;++slot)
        for(ulong j=0;j<pq_spend_slot_words[slot];++j)arena[offsets[slot]+j]=0;
    for(uint i=0;i<32;++i) {
        ulong seed=packed[PQ_SPEND_INPUT_SETUP_SEED_BYTES+i];
        ulong ctx=packed[PQ_SPEND_INPUT_CONTEXT_BYTES+i];
        ulong key=packed[PQ_SPEND_INPUT_FRESH_PRIVATE_AES_KEY_BYTES+i];
        if((seed|ctx|key)>255ul)pq_spend_error(status,2u);
        pq_sc_setup_seed[i]=(uchar)seed;pq_sc_context[i]=(uchar)ctx;pq_sc_private_seed[i]=(uchar)key;
    }
    for(uint i=0;i<64;++i) {
        ulong serial=packed[PQ_SPEND_INPUT_SERIAL_BYTES+i];
        if(serial>255ul)pq_spend_error(status,2u);
        pq_sc_sn_out[i]=(uchar)serial;
    }
    uint distinct=0;for(uint i=0;i<32;++i)distinct|=pq_sc_sn_out[i]^pq_sc_sn_out[32+i];
    if(!distinct)pq_spend_error(status,1u);
    for(uint i=0;i<180*256;++i) {
        ulong value=packed[PQ_SPEND_INPUT_RING_POLYS+i];
        if(value>=PQ_SPEND_Q)pq_spend_error(status,2u);
        ((__global ulong*)pq_sc_a_in)[i]=value;
    }
    for(uint i=0;i<8*256;++i) {
        ulong value=packed[PQ_SPEND_INPUT_RECIPIENT_POLYS+i];
        if(value>=PQ_SPEND_Q)pq_spend_error(status,2u);
        ((__global ulong*)pq_sc_pk_out)[i]=value;
    }
    for(uint i=0;i<16*256;++i) {
        ulong value=packed[PQ_SPEND_INPUT_SPENDING_KEY_POLYS+i];
        if(pq_spend_abs(value)>1ul)pq_spend_error(status,4u);
        ((__global ulong*)pq_sc_sk_in)[i]=value;
    }
    for(uint i=0;i<18*256;++i) {
        ulong value=packed[PQ_SPEND_INPUT_COMMITMENT_KEY_POLYS+i];
        if(pq_spend_abs(value)>1ul)pq_spend_error(status,4u);
        ((__global ulong*)pq_sc_ck_in)[i]=value;
    }
    for(uint i=0;i<5;++i)pq_sc_scalars[i]=packed[PQ_SPEND_INPUT_PRIVATE_SCALARS_INDEX_INPUTS_OUTPUTS+i];
    if(pq_sc_scalars[0]>=10ul)pq_spend_error(status,1u);
    for(uint i=1;i<5;++i)if(pq_sc_scalars[i]>=(1ul<<52))pq_spend_error(status,4u);
    if(pq_sc_scalars[1]+pq_sc_scalars[2]!=pq_sc_scalars[3]+pq_sc_scalars[4])pq_spend_error(status,1u);
    status[1]=0;status[2]=PQ_SPEND_IMPORT;pq_sc_control[0]=PQ_SPEND_SETUP;
}

__constant uchar pq_spend_context_domain[]="lattica/pq-ringct/matrict-plus-n10/fixture-v1";
__kernel void pq_spend_setup(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    if(status[1] || pq_sc_control[0]!=PQ_SPEND_SETUP){pq_spend_error(status,1u);return;}
    status[2]=PQ_SPEND_SETUP;
    for(uint i=0;i<32;++i)pq_sc_byte_work[i]=pq_sc_setup_seed[i];
    pq_sc_byte_work[32]=64;pq_sc_byte_work[33]=4;pq_sc_byte_work[34]=4;pq_sc_byte_work[35]=4;
    pq_sc_byte_work[36]=5;pq_sc_byte_work[37]=5;pq_sc_byte_work[38]=0;pq_sc_byte_work[39]=1;
    pq_spend_store32(pq_sc_byte_work+40,PQ_SPEND_Q);pq_spend_store32(pq_sc_byte_work+44,PQ_SPEND_QHAT);
    pq_sc_byte_work[48]=44;pq_spend_shake(pq_sc_byte_work,49,pq_sc_pp,32);
    ulong cursor=0;
    for(uint i=0;i<sizeof(pq_spend_context_domain)-1;++i)pq_sc_byte_work[cursor++]=pq_spend_context_domain[i];
    cursor=pq_spend_copy_bytes(pq_sc_byte_work,cursor,pq_sc_pp,32);
    cursor=pq_spend_copy_bytes(pq_sc_byte_work,cursor,pq_sc_context,32);
    pq_spend_shake(pq_sc_byte_work,cursor,pq_sc_pp,32);
    pq_spend_aes_bytes(pq_sc_setup_seed,0x4d617431ul,0,pq_sc_byte_work,30592,status);
    cursor=0;
    for(uint i=0;i<7;++i)for(uint j=0;j<4;++j)for(uint k=0;k<256;++k)
        pq_sc_mat1[i][j].poly[k]=pq_spend_uniform_one(pq_sc_byte_work,30592,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
    pq_spend_aes_bytes(pq_sc_setup_seed,0x4d617432ul,0,pq_sc_byte_work,13464,status);
    cursor=0;
    for(uint i=0;i<4;++i)for(uint j=0;j<2;++j)for(uint k=0;k<256;++k)
        pq_sc_mat2[i][j].poly[k]=pq_spend_uniform_one(pq_sc_byte_work,13464,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
    for(uint i=0;i<4;++i) {
        for(uint j=0;j<4;++j){pq_sc_mat2[i][2].poly[j]=0;pq_sc_mat2[i][2].poly[j+128]=0;}
        for(uint k=4;k<128;++k) {
            pq_sc_mat2[i][2].poly[k]=pq_spend_uniform_one(pq_sc_byte_work,13464,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
            pq_sc_mat2[i][2].poly[128+k]=pq_spend_uniform_one(pq_sc_byte_work,13464,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
        }
    }
    pq_spend_aes_bytes(pq_sc_setup_seed,0x4d617433ul,0,pq_sc_byte_work,186160,status);
    cursor=0;
    for(uint i=0;i<29;++i)for(uint j=0;j<5;++j)for(uint k=0;k<256;++k)
        pq_sc_mat3[i][j].poly[k]=pq_spend_uniform_one(pq_sc_byte_work,186160,&cursor,5,1099243232955ul,PQ_SPEND_QHAT,status);
    if(!status[0])pq_sc_control[0]=PQ_SPEND_MINT;
}

__kernel void pq_spend_mint_static(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    if(status[1] || pq_sc_control[0]!=PQ_SPEND_MINT){pq_spend_error(status,1u);return;}
    if(!pq_spend_signed_bound((__global pq_private_poly*)pq_sc_ck_out,18,1,status))return;
    status[2]=PQ_SPEND_MINT;
    for(uint output_index=0;output_index<2;++output_index) {
        for(uint i=0;i<64;++i)pq_sc_a_hat[output_index][i]=(pq_sc_scalars[3+output_index]>>i)&1ul;
        for(uint i=0;i<9;++i) {
            for(uint j=0;j<256;++j)pq_sc_mint_ntt[i].poly[j]=pq_sref_con_add(pq_sc_ck_out[output_index].ck[i].poly[j],PQ_SPEND_Q);
            pq_spend_ntt_q(pq_sc_mint_ntt+i);
        }
        for(uint i=0;i<5;++i)pq_spend_copy_poly(pq_sc_cn_out[output_index].cn+i,pq_sc_mint_ntt+i);
        for(uint i=0;i<5;++i)for(uint j=0;j<4;++j)
            pq_spend_mult_plus_rq(pq_sc_cn_out[output_index].cn+j,pq_sc_mat1[i]+j,pq_sc_mint_ntt+4+i);
        for(uint i=0;i<2;++i)pq_spend_mult_plus_rq(pq_sc_cn_out[output_index].cn+4,pq_sc_mat2[i],pq_sc_mint_ntt+7+i);
        for(uint i=0;i<64;++i)pq_sc_cn_out[output_index].cn[4].poly[4*i]=pq_sref_con_sub(
            pq_sc_cn_out[output_index].cn[4].poly[4*i]+((0ul-pq_sc_a_hat[output_index][i])&PQ_SPEND_MONTGOMERY_32_Q),PQ_SPEND_Q);
    }
    pq_sc_c[0]=0;
    for(uint i=0;i<63;++i) {
        ulong value=pq_sc_c[i]+((pq_sc_scalars[3]>>i)&1ul)+((pq_sc_scalars[4]>>i)&1ul)
                         -((pq_sc_scalars[1]>>i)&1ul)-((pq_sc_scalars[2]>>i)&1ul);
        // Explicit arithmetic right shift of a two-complement word.
        pq_sc_c[i+1]=(value>>1)|(value&0x8000000000000000ul);
        if(pq_spend_abs(pq_sc_c[i+1])>1ul)pq_spend_error(status,4u);
    }
    for(uint i=0;i<10;++i)for(uint j=0;j<5;++j)for(uint k=0;k<256;++k)
        pq_sc_t_in_sum[i][j].poly[k]=pq_sref_con_sub(pq_sc_a_in[i][0].cn[j].poly[k]+pq_sc_a_in[i][1].cn[j].poly[k],PQ_SPEND_Q);
    for(uint member=0;member<2;++member) {
        pq_spend_aes_bytes(pq_sc_sn_out+32*member,0,0,pq_sc_byte_work,4788,status);
        ulong cursor=0;
        for(uint j=0;j<4;++j)for(uint k=0;k<256;++k)
            pq_sc_g_gamma[j].poly[k]=pq_spend_uniform_one(pq_sc_byte_work,4788,&cursor,4,4194256025ul,PQ_SPEND_Q,status);
        for(uint i=0;i<10;++i)for(uint j=0;j<4;++j)for(uint k=0;k<256;++k)
            pq_sc_pk_hat[i][member][j].poly[k]=pq_sref_con_add(pq_sc_a_in[i][member].pk[j].poly[k]-pq_sc_g_gamma[j].poly[k],PQ_SPEND_Q);
    }
    for(uint i=0;i<10;++i)pq_sc_delta[i]=pq_spend_eq(i,pq_sc_scalars[0]);
    pq_sc_delta[10]=(0ul-pq_sc_c[32])>>63;pq_sc_delta[11]=pq_sc_c[32]>>63;pq_sc_c[32]=0;
    if(!status[0])pq_sc_control[0]=PQ_SPEND_BEGIN;
}

__kernel void pq_spend_begin_attempt(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,ulong attempt_limit,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    if(!attempt_limit || (pq_sc_control[0]!=PQ_SPEND_BEGIN && status[1]!=1u) || status[1]==2u) {
        pq_spend_error(status,1u);return;
    }
    if(pq_sc_control[1] && pq_sc_control[2]!=attempt_limit){pq_spend_error(status,1u);return;}
    if(pq_sc_control[1]>=attempt_limit){pq_spend_error(status,64u);return;}
    ++pq_sc_control[1];pq_sc_control[2]=attempt_limit;pq_sc_control[0]=PQ_SPEND_EARLY;
    status[1]=0;status[2]=PQ_SPEND_BEGIN;
}

__kernel void pq_spend_encode(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    if(status[1] || pq_sc_control[0]!=PQ_SPEND_ENCODE){pq_spend_error(status,1u);return;}
    status[2]=PQ_SPEND_ENCODE;
    ulong cursor=pq_spend_copy_bytes(pq_sc_statement_bytes,0,pq_sc_setup_seed,32);
    cursor=pq_spend_pack_poly32(pq_sc_statement_bytes,cursor,(__global pq_private_poly*)pq_sc_a_in,180,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_statement_bytes,cursor,(__global pq_private_poly*)pq_sc_pk_out,8,PQ_SPEND_Q,status);
    cursor=pq_spend_pack_poly32(pq_sc_statement_bytes,cursor,(__global pq_private_poly*)pq_sc_cn_out,10,PQ_SPEND_Q,status);
    cursor=pq_spend_copy_bytes(pq_sc_statement_bytes,cursor,pq_sc_sn_out,64);
    if(cursor!=202848ul){pq_spend_error(status,128u);return;}
    for(uint i=0;i<53600;++i)pq_sc_proof_bytes[i]=0;
    cursor=0;
    pq_spend_public_bits(pq_sc_proof_bytes,&cursor,&pq_sc_out->c,1,28,PQ_SPEND_Q,status);
    pq_spend_public_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->v,4,28,PQ_SPEND_Q,status);
    pq_spend_public_bits(pq_sc_proof_bytes,&cursor,&pq_sc_out->v1,1,28,PQ_SPEND_Q,status);
    pq_spend_public_bits(pq_sc_proof_bytes,&cursor,&pq_sc_out->v2,1,28,PQ_SPEND_Q,status);
    pq_spend_public_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->b,5,32,PQ_SPEND_QHAT,status);
    for(uint i=0;i<32;++i)pq_spend_put_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->alpha[i],8,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,&pq_sc_out->x,1,2,1,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z_out[0],9,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z_out[1],9,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z0,9,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z1,11,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z2,11,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->f1,11,11,PQ_SPEND_BA_10_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->zb,10,17,PQ_SPEND_B_6,status);
    pq_spend_signed_bits(pq_sc_proof_bytes,&cursor,pq_sc_out->z,8,24,PQ_SPEND_BRS_13_6,status);
    if(cursor!=428800ul)pq_spend_error(status,128u);
    if(!status[0]){status[1]=2u;pq_sc_control[0]=0;}
}
#undef pq_sc_setup_seed
#undef pq_sc_context
#undef pq_sc_private_seed
#undef pq_sc_a_in
#undef pq_sc_pk_out
#undef pq_sc_sk_in
#undef pq_sc_ck_in
#undef pq_sc_sn_out
#undef pq_sc_scalars
#undef pq_sc_cn_out
#undef pq_sc_ck_out
#undef pq_sc_mat1
#undef pq_sc_mat2
#undef pq_sc_mat3
#undef pq_sc_pp
#undef pq_sc_out
#undef pq_sc_a_hat
#undef pq_sc_c
#undef pq_sc_delta
#undef pq_sc_mint_ntt
#undef pq_sc_y_out
#undef pq_sc_y_out_ntt
#undef pq_sc_w_out
#undef pq_sc_y0
#undef pq_sc_y0_ntt
#undef pq_sc_w0
#undef pq_sc_a
#undef pq_sc_a_ntt
#undef pq_sc_a_ntt_qhat
#undef pq_sc_tmp_r
#undef pq_sc_t_in_sum
#undef pq_sc_rho
#undef pq_sc_rho_ntt
#undef pq_sc_y1
#undef pq_sc_y2
#undef pq_sc_y1_ntt
#undef pq_sc_y2_ntt
#undef pq_sc_w1
#undef pq_sc_w2
#undef pq_sc_w
#undef pq_sc_tmp_q
#undef pq_sc_a3y1
#undef pq_sc_a3y1_2
#undef pq_sc_b1yout
#undef pq_sc_alpha
#undef pq_sc_alpha_prime_0
#undef pq_sc_v0
#undef pq_sc_alpha_b1yout
#undef pq_sc_pk_hat
#undef pq_sc_g_gamma
#undef pq_sc_p
#undef pq_sc_alpha_prime_0_ntt
#undef pq_sc_s
#undef pq_sc_a2_ntt
#undef pq_sc_rb
#undef pq_sc_ra
#undef pq_sc_rb_ntt
#undef pq_sc_ra_ntt
#undef pq_sc_a_rs
#undef pq_sc_y
#undef pq_sc_y_ntt
#undef pq_sc_e
#undef pq_sc_g
#undef pq_sc_f0
#undef pq_sc_tmp_aut
#undef pq_sc_tmp_aut_r
#undef pq_sc_x_delta
#undef pq_sc_x_s
#undef pq_sc_x_rb
#undef pq_sc_x_rout
#undef pq_sc_x_ri
#undef pq_sc_x_rho
#undef pq_sc_x_aut_rho
#undef pq_sc_byte_work
#undef pq_sc_hash_x_bytes
#undef pq_sc_statement_bytes
#undef pq_sc_proof_bytes
#undef pq_sc_control

// end pq_spend_transcript.cl
// begin pq_spend_phases.cl
// Reference equation blocks; private sampling is scheduled between public phases.
// Include pq_spend_transcript.cl first. Every pointer below remains on device.
#define pq_sc_setup_seed ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_SETUP_SEED]))
#define pq_sc_context ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_CONTEXT]))
#define pq_sc_private_seed ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PRIVATE_SEED]))
#define pq_sc_a_in ((__global pq_spend_act (*)[2])(arena+offsets[PQ_SPEND_SLOT_A_IN]))
#define pq_sc_pk_out ((__global pq_spend_pk*)(arena+offsets[PQ_SPEND_SLOT_PK_OUT]))
#define pq_sc_sk_in ((__global pq_private_poly (*)[8])(arena+offsets[PQ_SPEND_SLOT_SK_IN]))
#define pq_sc_ck_in ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_CK_IN]))
#define pq_sc_sn_out ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_SN_OUT]))
#define pq_sc_scalars ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_SCALARS]))
#define pq_sc_cn_out ((__global pq_spend_cn*)(arena+offsets[PQ_SPEND_SLOT_CN_OUT]))
#define pq_sc_ck_out ((__global pq_spend_ck*)(arena+offsets[PQ_SPEND_SLOT_CK_OUT]))
#define pq_sc_mat1 ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_MAT1]))
#define pq_sc_mat2 ((__global pq_private_poly (*)[3])(arena+offsets[PQ_SPEND_SLOT_MAT2]))
#define pq_sc_mat3 ((__global pq_private_poly (*)[5])(arena+offsets[PQ_SPEND_SLOT_MAT3]))
#define pq_sc_pp ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PP]))
#define pq_sc_out ((__global pq_spend_proof*)(arena+offsets[PQ_SPEND_SLOT_OUT]))
#define pq_sc_a_hat ((__global ulong (*)[64])(arena+offsets[PQ_SPEND_SLOT_A_HAT]))
#define pq_sc_c ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_C]))
#define pq_sc_delta ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_DELTA]))
#define pq_sc_mint_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_MINT_NTT]))
#define pq_sc_y_out ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_Y_OUT]))
#define pq_sc_y_out_ntt ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_Y_OUT_NTT]))
#define pq_sc_w_out ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_W_OUT]))
#define pq_sc_y0 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y0]))
#define pq_sc_y0_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y0_NTT]))
#define pq_sc_w0 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W0]))
#define pq_sc_a ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A]))
#define pq_sc_a_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_NTT]))
#define pq_sc_a_ntt_qhat ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_NTT_QHAT]))
#define pq_sc_tmp_r (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_R]))
#define pq_sc_t_in_sum ((__global pq_private_poly (*)[5])(arena+offsets[PQ_SPEND_SLOT_T_IN_SUM]))
#define pq_sc_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RHO]))
#define pq_sc_rho_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RHO_NTT]))
#define pq_sc_y1 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y1]))
#define pq_sc_y2 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y2]))
#define pq_sc_y1_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y1_NTT]))
#define pq_sc_y2_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y2_NTT]))
#define pq_sc_w1 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W1]))
#define pq_sc_w2 ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W2]))
#define pq_sc_w (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_W]))
#define pq_sc_tmp_q (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_Q]))
#define pq_sc_a3y1 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A3Y1]))
#define pq_sc_a3y1_2 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A3Y1_2]))
#define pq_sc_b1yout ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_B1YOUT]))
#define pq_sc_alpha ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA]))
#define pq_sc_alpha_prime_0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_PRIME_0]))
#define pq_sc_v0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_V0]))
#define pq_sc_alpha_b1yout ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_B1YOUT]))
#define pq_sc_pk_hat ((__global pq_private_poly (*)[2][4])(arena+offsets[PQ_SPEND_SLOT_PK_HAT]))
#define pq_sc_g_gamma ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_G_GAMMA]))
#define pq_sc_p ((__global pq_private_poly (*)[4])(arena+offsets[PQ_SPEND_SLOT_P]))
#define pq_sc_alpha_prime_0_ntt (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_ALPHA_PRIME_0_NTT]))
#define pq_sc_s ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_S]))
#define pq_sc_a2_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A2_NTT]))
#define pq_sc_rb ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RB]))
#define pq_sc_ra ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RA]))
#define pq_sc_rb_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RB_NTT]))
#define pq_sc_ra_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_RA_NTT]))
#define pq_sc_a_rs ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_A_RS]))
#define pq_sc_y ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y]))
#define pq_sc_y_ntt ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_Y_NTT]))
#define pq_sc_e ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_E]))
#define pq_sc_g ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_G]))
#define pq_sc_f0 (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_F0]))
#define pq_sc_tmp_aut (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_AUT]))
#define pq_sc_tmp_aut_r (*(__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_TMP_AUT_R]))
#define pq_sc_x_delta ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_DELTA]))
#define pq_sc_x_s ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_S]))
#define pq_sc_x_rb ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RB]))
#define pq_sc_x_rout ((__global pq_private_poly (*)[9])(arena+offsets[PQ_SPEND_SLOT_X_ROUT]))
#define pq_sc_x_ri ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RI]))
#define pq_sc_x_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_RHO]))
#define pq_sc_x_aut_rho ((__global pq_private_poly*)(arena+offsets[PQ_SPEND_SLOT_X_AUT_RHO]))
#define pq_sc_byte_work ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_BYTE_WORK]))
#define pq_sc_hash_x_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_HASH_X_BYTES]))
#define pq_sc_statement_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_STATEMENT_BYTES]))
#define pq_sc_proof_bytes ((__global uchar*)(arena+offsets[PQ_SPEND_SLOT_PROOF_BYTES]))
#define pq_sc_control ((__global ulong*)(arena+offsets[PQ_SPEND_SLOT_CONTROL]))

// Independent polynomial preparation. All launches share the in-order queue.
// No barrier is used: queue completion separates admission, transforms, rows,
// and the original dependent suffix. Samplers and all arithmetic helpers remain
// unchanged. The preparation ticket uses the existing fourth control word.
#define PQ_SPEND_PARALLEL_ARENA_WORDS 336839ul
__kernel void pq_spend_parallel_admit(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,uint phase,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    pq_sc_control[3]=0;
    if(status[1] || pq_sc_control[0]!=phase){pq_spend_error(status,1u);return;}
    if(phase==PQ_SPEND_EARLY) {
        if(!pq_spend_signed_bound(pq_sc_a+1,11,10ul*PQ_SPEND_BA_10_K-1,status) ||
           !pq_spend_signed_bound((__global pq_private_poly*)pq_sc_y_out,18,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y0,9,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_rho,11,1,status) ||
           !pq_spend_signed_bound(pq_sc_y1,11,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y2,11,10ul*PQ_SPEND_B_K-1,status))return;
    } else if(phase==PQ_SPEND_LATE) {
        if(!pq_spend_signed_bound(pq_sc_rb,10,1,status) ||
           !pq_spend_signed_bound(pq_sc_ra,10,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y,8,10ul*PQ_SPEND_BRS_13_K-1,status))return;
    } else {pq_spend_error(status,1u);return;}
    pq_sc_control[3]=phase;
}

inline void pq_spend_parallel_convert_q(__global pq_private_poly *out,
    __global const pq_private_poly *in) {
    for(ulong j=0;j<PQ_SPEND_D;++j)out->poly[j]=pq_sref_con_add(in->poly[j],PQ_SPEND_Q);
    pq_spend_ntt_q(out);
}
inline void pq_spend_parallel_convert_qhat(__global pq_private_poly *out,
    __global const pq_private_poly *in) {
    for(ulong j=0;j<PQ_SPEND_D;++j)out->poly[j]=pq_sref_con_add(in->poly[j],PQ_SPEND_QHAT);
    pq_spend_ntt_qhat(out);
}

// Status and admission remain read-only throughout every parallel launch.
// A work item owns whole destination polynomials, including private NTT scratch.
__kernel void pq_spend_parallel_polynomials(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,uint phase,__global const uint *status) {
    const ulong lane=get_global_id(0);
    if(status[0] || status[1])return;
    if(slot_count!=PQ_SPEND_SLOT_COUNT || arena_words<PQ_SPEND_PARALLEL_ARENA_WORDS)return;
    if(pq_sc_control[3]!=(ulong)phase || pq_sc_control[0]!=(ulong)phase)return;
    ulong i,j,k;
    if(phase==PQ_SPEND_EARLY) {
        if(lane>=72)return;
        if(lane==0) {
    /* a_0 = -\sum_{j = 1}^{PQ_SPEND_N_SPENT - 1} a_j */
    pq_spend_zero_poly(pq_sc_a);
    for (i = 1; i < PQ_SPEND_N_SPENT; i++) {
      for (j = 0; j < PQ_SPEND_D; j++) {
        pq_sc_a[0].poly[j] -= pq_sc_a[i].poly[j];
      }
    }
    for (j = 0; j < PQ_SPEND_D; j++) {
      pq_sc_a_ntt[0].poly[j] = pq_sref_con_add(pq_sc_a[0].poly[j], PQ_SPEND_Q);
      pq_sc_a_ntt_qhat[0].poly[j] = pq_sref_con_add(pq_sc_a[0].poly[j], PQ_SPEND_QHAT);
    }
    pq_spend_ntt_q(pq_sc_a_ntt);
    pq_spend_ntt_qhat(pq_sc_a_ntt_qhat);

        } else if(lane<12) {
            i=lane;

      for (j = 0; j < PQ_SPEND_D; j++) {
        pq_sc_a_ntt[i].poly[j] = pq_sref_con_add(pq_sc_a[i].poly[j], PQ_SPEND_Q);
        pq_sc_a_ntt_qhat[i].poly[j] = pq_sref_con_add(pq_sc_a[i].poly[j], PQ_SPEND_QHAT);
      }

      pq_spend_ntt_q(pq_sc_a_ntt + i);
      pq_spend_ntt_qhat(pq_sc_a_ntt_qhat + i);
    
        } else if(lane<39) {
            const ulong group=(lane-12)/9; i=(lane-12)%9;
            if(group==0)pq_spend_parallel_convert_q(pq_sc_y_out_ntt[0]+i,pq_sc_y_out[0]+i);
            else if(group==1)pq_spend_parallel_convert_q(pq_sc_y_out_ntt[1]+i,pq_sc_y_out[1]+i);
            else pq_spend_parallel_convert_q(pq_sc_y0_ntt+i,pq_sc_y0+i);
        } else {
            const ulong group=(lane-39)/11; i=(lane-39)%11;
            if(group==0)pq_spend_parallel_convert_q(pq_sc_rho_ntt+i,pq_sc_rho+i);
            else if(group==1)pq_spend_parallel_convert_q(pq_sc_y1_ntt+i,pq_sc_y1+i);
            else pq_spend_parallel_convert_q(pq_sc_y2_ntt+i,pq_sc_y2+i);
        }
    } else if(phase==PQ_SPEND_LATE) {
        if(lane>=80)return;
        if(lane<12) {
            i=lane;

      pq_spend_mult_rqhat(pq_sc_a2_ntt + i, pq_sc_a_ntt_qhat + i, pq_sc_a_ntt_qhat + i);
    
        } else if(lane<32) {
            i=(lane-12)%10;
            if(lane<22)pq_spend_parallel_convert_qhat(pq_sc_rb_ntt+i,pq_sc_rb+i);
            else pq_spend_parallel_convert_qhat(pq_sc_ra_ntt+i,pq_sc_ra+i);
        } else if(lane<40) {
            i=lane-32;pq_spend_parallel_convert_q(pq_sc_y_ntt+i,pq_sc_y+i);
        } else {
            i=(lane-40)/4;j=(lane-40)%4;

        pq_spend_mult_rq(pq_sc_p[i] + j, &pq_sc_alpha_prime_0_ntt, pq_sc_pk_hat[i][0] + j);

        for (k = 0; k < PQ_SPEND_D; k++) {
          pq_sc_p[i][j].poly[k] =
              pq_sref_con_sub(pq_sc_p[i][j].poly[k] + pq_sc_pk_hat[i][1][j].poly[k], PQ_SPEND_Q);
        }
      
        }
    }
}

// One row owner retains the original accumulator sequence for that row.
__kernel void pq_spend_parallel_early_rows(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,uint phase,__global const uint *status) {
    const ulong lane=get_global_id(0);
    if(lane>=24 || status[0] || status[1])return;
    if(slot_count!=PQ_SPEND_SLOT_COUNT || arena_words<PQ_SPEND_PARALLEL_ARENA_WORDS)return;
    if(phase!=PQ_SPEND_EARLY || pq_sc_control[3]!=(ulong)phase || pq_sc_control[0]!=(ulong)phase)return;
    const ulong group=lane/4,row=lane%4;
    __global pq_private_poly *out;
    __global const pq_private_poly *in;
    if(group==0){out=pq_sc_w_out[0];in=pq_sc_y_out_ntt[0];}
    else if(group==1){out=pq_sc_w_out[1];in=pq_sc_y_out_ntt[1];}
    else if(group==2){out=pq_sc_w0;in=pq_sc_y0_ntt;}
    else if(group==3){out=pq_sc_out->v;in=pq_sc_rho_ntt;}
    else if(group==4){out=pq_sc_w1;in=pq_sc_y1_ntt;}
    else {out=pq_sc_w2;in=pq_sc_y2_ntt;}
    pq_spend_copy_poly(out+row,in+row);
    for(ulong i=0;i<(group<3?PQ_SPEND_K+1:PQ_SPEND_K+3);++i)
        pq_spend_mult_plus_rq(out+row,pq_sc_mat1[i]+row,in+PQ_SPEND_N+i);
    if(group==2)for(ulong i=0;i<PQ_SPEND_N_SPENT;++i)
        pq_spend_mult_minus_rq(out+row,pq_sc_a_ntt+i,pq_sc_t_in_sum[i]+row);
}

__kernel void pq_spend_equations(__global ulong *arena,ulong arena_words,
    __global const ulong *offsets,uint slot_count,uint phase,__global uint *status) {
    if(get_global_id(0))return;
    if(status[0] || !pq_spend_arena_ok(offsets,slot_count,arena_words,status))return;
    if(status[1] || pq_sc_control[0]!=phase) {pq_spend_error(status,1u);return;}
    // The host records every preparation event before entering this suffix.
    // This single-use ticket proves admission, not completion of parallel lanes.
    if(phase==PQ_SPEND_EARLY || phase==PQ_SPEND_LATE) {
        if(pq_sc_control[3]!=(ulong)phase){pq_spend_error(status,1u);return;}
        pq_sc_control[3]=0;
    }
    status[2]=phase;
    ulong i,j,k,rej=0,rej1;
    if(phase==PQ_SPEND_EARLY) {
        if(!pq_spend_signed_bound(pq_sc_a+1,11,10ul*PQ_SPEND_BA_10_K-1,status) ||
           !pq_spend_signed_bound((__global pq_private_poly*)pq_sc_y_out,18,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y0,9,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_rho,11,1,status) ||
           !pq_spend_signed_bound(pq_sc_y1,11,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y2,11,10ul*PQ_SPEND_B_K-1,status))return;
    /* a_1,...,a_{PQ_SPEND_N_SPENT + 1} <-- D_{10 * B_a} */

    /* Parallel preparation supplies a. */

/* Parallel preparation supplies a0. */    /* y_{out, i} <-- D_{B}^{PQ_SPEND_N + PQ_SPEND_K + 1} */
    /* y_0 <-- D_B^{PQ_SPEND_N + PQ_SPEND_K + 1} */



    /* Parallel preparation supplies yout. */

/* Parallel preparation supplies early_commitments. */    /* rho <-- S_1^{PQ_SPEND_N + PQ_SPEND_K + 3} */
    /* y_1, y_2 <-- D_{B}^{PQ_SPEND_N + PQ_SPEND_K + 3} */



    /* Parallel preparation supplies rho. */

/* Parallel preparation supplies early_v_w1_w2. */    /* C = <a_3', \rho> + c */
    pq_spend_copy_poly(&(pq_sc_out->c), pq_sc_rho_ntt + PQ_SPEND_N + 2);
    for (i = 0; i < PQ_SPEND_SUBRING_SIZE; i++) {
      (pq_sc_out->c).poly[i] = 0;
      (pq_sc_out->c).poly[i + (PQ_SPEND_D >> 1)] = 0;
    }
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&(pq_sc_out->c), pq_sc_mat2[i] + 2, pq_sc_rho_ntt + PQ_SPEND_N + 3 + i);
    }
    for (i = 0; i < PQ_SPEND_R; i++) {
      (pq_sc_out->c).poly[i * PQ_SPEND_SUBRING_SIZE] = pq_sref_red_short_q(
          (pq_sc_out->c).poly[i * PQ_SPEND_SUBRING_SIZE] + (pq_sc_c[i] * PQ_SPEND_MONTGOMERY_32_Q) + PQ_SPEND_Q);
    }

    /* w = <a_3', y_1> - 2\sigma(<a_3', y_2>) + <b_1, \sum_{i = 0}^{PQ_SPEND_S - 1}
     * y_{out_i} - y_0> + \sum_{j = 0}^{PQ_SPEND_N_SPENT - 1} (a_j * \sum_{i = 0}^{PQ_SPEND_M - 1}
     * v_{in, j}^(i) - (a_{PQ_SPEND_N_SPENT} - a_{PQ_SPEND_N_SPENT + 1}) * [0^{r' - 1}, -2, 1,
     * 0^{r' - 1}] */
    /* <a_3', y_1> */
    pq_spend_copy_poly(&pq_sc_a3y1, pq_sc_y1_ntt + PQ_SPEND_N + 2);
    for (i = 0; i < PQ_SPEND_SUBRING_SIZE; i++) {
      pq_sc_a3y1.poly[i] = 0;
      pq_sc_a3y1.poly[i + (PQ_SPEND_D >> 1)] = 0;
    }
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&pq_sc_a3y1, pq_sc_mat2[i] + 2, pq_sc_y1_ntt + PQ_SPEND_N + 3 + i);
    }

    /* <b_1, y_{out, i}> */
    pq_spend_copy_poly(pq_sc_b1yout, pq_sc_y_out_ntt[0] + PQ_SPEND_N);
    pq_spend_copy_poly(pq_sc_b1yout + 1, pq_sc_y_out_ntt[1] + PQ_SPEND_N);
    for (i = 0; i < PQ_SPEND_K - 2; i++) {
      pq_spend_mult_plus_rq(pq_sc_b1yout, pq_sc_mat2[i], pq_sc_y_out_ntt[0] + PQ_SPEND_N + 3 + i);
      pq_spend_mult_plus_rq(pq_sc_b1yout + 1, pq_sc_mat2[i], pq_sc_y_out_ntt[1] + PQ_SPEND_N + 3 + i);
    }

    /* <a_3', y_2> */
    pq_spend_copy_poly(&pq_sc_tmp_q, pq_sc_y2_ntt + PQ_SPEND_N + 2);
    for (i = 0; i < PQ_SPEND_SUBRING_SIZE; i++) {
      pq_sc_tmp_q.poly[i] = 0;
      pq_sc_tmp_q.poly[i + (PQ_SPEND_D >> 1)] = 0;
    }
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&pq_sc_tmp_q, pq_sc_mat2[i] + 2, pq_sc_y2_ntt + PQ_SPEND_N + 3 + i);
    }

    /* \sigma(<a_3', y_2>) */
    pq_spend_aut(&pq_sc_tmp_aut, &pq_sc_tmp_q);

    /* <a_3', y_1> - 2\sigma(<a_3', y_2>) + <b_1, \sum_{i = 0}^{PQ_SPEND_S - 1} y_{out_i}
     * - y_0> */
    for (i = 0; i < PQ_SPEND_D; i++) {
      pq_sc_w.poly[i] = pq_sref_red_short_q(pq_sref_con_add(pq_sc_a3y1.poly[i] - 2 * pq_sc_tmp_aut.poly[i] +
                                          pq_sc_b1yout[0].poly[i] +
                                          pq_sc_b1yout[1].poly[i] - pq_sc_y0_ntt[PQ_SPEND_N].poly[i],
                                      PQ_SPEND_Q * 3));
    }
    for (i = 0; i < PQ_SPEND_K - 2; i++) {
      pq_spend_mult_minus_rq(&pq_sc_w, pq_sc_mat2[i], pq_sc_y0_ntt + PQ_SPEND_N + 3 + i);
    }

    /* <a_3', y_1> - 2\sigma(<a_3', y_2>) + <b_1, \sum_{i = 0}^{PQ_SPEND_S - 1} y_{out_i}
     * - y_0> + \sum_{j = 0}^{PQ_SPEND_N_SPENT - 1} (a_j * \sum_{i = 0}^{PQ_SPEND_M - 1} v_{in,
     * j}^(i) */
    for (i = 0; i < PQ_SPEND_N_SPENT; i++) {
      pq_spend_mult_plus_rq(&pq_sc_w, pq_sc_a_ntt + i, pq_sc_t_in_sum[i] + PQ_SPEND_N);
    }

    /* <a_3', y_1> - 2\sigma(<a_3', y_2>) + <b_1, \sum_{i = 0}^{PQ_SPEND_S - 1} y_{out_i}
     * - y_0> + \sum_{j = 0}^{PQ_SPEND_N_SPENT - 1} (a_j * \sum_{i = 0}^{PQ_SPEND_M - 1} v_{in,
     * j}^(i) - (a_{PQ_SPEND_N_SPENT} - a_{PQ_SPEND_N_SPENT + 1}) * [0^{r' - 1}, -2, 1, 0^{r' -
     * 1}] */
    for (i = 0; i < PQ_SPEND_SUBRING_SIZE; i++) {
      pq_sc_w.poly[31 * PQ_SPEND_SUBRING_SIZE + i] = pq_sref_red_short_q(
          pq_sref_con_add(pq_sc_w.poly[31 * PQ_SPEND_SUBRING_SIZE + i] +
                      2 * (pq_sc_a_ntt[PQ_SPEND_N_SPENT].poly[31 * PQ_SPEND_SUBRING_SIZE + i] -
                           pq_sc_a_ntt[PQ_SPEND_N_SPENT + 1].poly[31 * PQ_SPEND_SUBRING_SIZE + i]),
                  PQ_SPEND_Q << 1));
      pq_sc_w.poly[32 * PQ_SPEND_SUBRING_SIZE + i] =
          pq_sref_red_short_q(pq_sc_w.poly[32 * PQ_SPEND_SUBRING_SIZE + i] + PQ_SPEND_Q -
                      pq_sc_a_ntt[PQ_SPEND_N_SPENT].poly[32 * PQ_SPEND_SUBRING_SIZE + i] +
                      pq_sc_a_ntt[PQ_SPEND_N_SPENT + 1].poly[32 * PQ_SPEND_SUBRING_SIZE + i]);
    }

    /* v_2 = <a_2, \rho> + g_2,
     * g_2 = (3c^2 - 1) * <a_3', y_1> */
    /* <a_2, \rho> */
    pq_spend_copy_poly(&(pq_sc_out->v2), pq_sc_rho_ntt + PQ_SPEND_N + 1);
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&(pq_sc_out->v2), pq_sc_mat2[i] + 1, pq_sc_rho_ntt + PQ_SPEND_N + 3 + i);
    }

    /* <a_2, \rho> + (3c^2 - 1) * <a_3', y_1> */
    for (i = 0; i < PQ_SPEND_R; i++) {
      for (j = 0; j < PQ_SPEND_SUBRING_SIZE; j++) {
        (pq_sc_out->v2).poly[i * PQ_SPEND_SUBRING_SIZE + j] = pq_sref_red_short_q(
            (pq_sc_out->v2).poly[i * PQ_SPEND_SUBRING_SIZE + j] + PQ_SPEND_Q +
            (3 * pq_sc_c[i] * pq_sc_c[i] - 1) * pq_sc_a3y1.poly[i * PQ_SPEND_SUBRING_SIZE + j]);
      }
    }


        pq_spend_hash_alpha(arena,offsets,status);
        pq_spend_expand_alpha(arena,offsets,status);
        for(i=0;i<256;++i)pq_sc_alpha_prime_0_ntt.poly[i]=pq_sref_con_add(pq_sc_alpha_prime_0.poly[i],PQ_SPEND_Q);
        pq_spend_ntt_q(&pq_sc_alpha_prime_0_ntt);
        for(i=0;i<64;++i) {
            rej1=1;
            for(j=0;j<4;++j)rej1&=pq_spend_eq(pq_sc_alpha_prime_0_ntt.poly[4*i+j],0);
            rej|=rej1;
        }
        status[1]=(uint)rej;
        pq_sc_control[0]=PQ_SPEND_LATE;
    } else if(phase==PQ_SPEND_LATE) {
        if(!pq_spend_signed_bound(pq_sc_rb,10,1,status) ||
           !pq_spend_signed_bound(pq_sc_ra,10,10ul*PQ_SPEND_B_K-1,status) ||
           !pq_spend_signed_bound(pq_sc_y,8,10ul*PQ_SPEND_BRS_13_K-1,status))return;
    /* v_0 = <a_1, y_1> + \hat{g}_0,
     * \hat{g}_0 = \sum_{i = 0}^{PQ_SPEND_S - 1} (\alpha_i * g_0^(i)) + g_0^(PQ_SPEND_S)
     * g_0^(i) = <b_1, y_{out, i}>^2
     * g_0^(PQ_SPEND_S) = <a_3', y_1>^3 */
    /* \alpha_i * <b_1, y_{out, i}> */
    pq_spend_mult_rq(pq_sc_alpha_b1yout, pq_sc_alpha, pq_sc_b1yout);
    pq_spend_mult_rq(pq_sc_alpha_b1yout + 1, pq_sc_alpha + 1, pq_sc_b1yout + 1);

    /* <a_1, y_1> */
    pq_spend_copy_poly(&pq_sc_v0, pq_sc_y1_ntt + PQ_SPEND_N);
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&pq_sc_v0, pq_sc_mat2[i], pq_sc_y1_ntt + PQ_SPEND_N + 3 + i);
    }

    /* <a_1, y_1> + <a_3', y_1>^3 */
    pq_spend_mult_rq(&pq_sc_a3y1_2, &pq_sc_a3y1, &pq_sc_a3y1);
    pq_spend_mult_plus_rq(&pq_sc_v0, &pq_sc_a3y1_2, &pq_sc_a3y1);

    /* <a_1, y_1> + \sum_{i = 0}^{PQ_SPEND_S - 1} (\alpha_i * <b_1, y_{out, i}>^2) +
     * <a_3', y_1>^3 */
    pq_spend_mult_plus_rq(&pq_sc_v0, pq_sc_alpha_b1yout, pq_sc_b1yout);
    pq_spend_mult_plus_rq(&pq_sc_v0, pq_sc_alpha_b1yout + 1, pq_sc_b1yout + 1);

    /* v_1 = <a_1, \rho> + <a_2, y_1> + \hat{g}_1,
     * \hat{g}_1 = \sum_{i = 0}^{PQ_SPEND_S - 1} (\alpha_i * g_1^(i)) + g_1^(PQ_SPEND_S)
     * g_1^(i) = (-2 \hat{a}_i + 1) * <b_1, y_{out, i}>
     * g_1^(PQ_SPEND_S) = (-3c) * <a_3', y_1>^2 */
    /* <a_1, \rho> + <a_2, y_1> */
    for (i = 0; i < PQ_SPEND_D; i++) {
      (pq_sc_out->v1).poly[i] =
          pq_sref_con_sub(pq_sc_rho_ntt[PQ_SPEND_N].poly[i] + pq_sc_y1_ntt[PQ_SPEND_N + 1].poly[i], PQ_SPEND_Q);
    }
    for (i = 0; i < PQ_SPEND_K; i++) {
      pq_spend_mult_plus_rq(&(pq_sc_out->v1), pq_sc_mat2[i], pq_sc_rho_ntt + PQ_SPEND_N + 3 + i);
      pq_spend_mult_plus_rq(&(pq_sc_out->v1), pq_sc_mat2[i] + 1, pq_sc_y1_ntt + PQ_SPEND_N + 3 + i);
    }

    /* <a_1, \rho> + <a_2, y_1> + \sum_{i = 0}^{PQ_SPEND_S - 1} (\alpha_i * (-2 \hat{a}_i
     * + 1) * <b_1, y_{out, i}>) + (-3c) * <a_3', y_1>^2 */
    /* The inner reduction is in [0,PQ_SPEND_Q).  Since c is -1, 0 or 1, the outer
     * input is in [0,7Q), requiring two conditional additions after folding.
     * Canonicalize here, before v1 is included in the Fiat-Shamir transcript.
     */
    for (i = 0; i < PQ_SPEND_R; i++) {
      for (j = 0; j < PQ_SPEND_SUBRING_SIZE; j++) {
        (pq_sc_out->v1).poly[i * PQ_SPEND_SUBRING_SIZE + j] =
            pq_sref_red_short_7q(pq_sref_red_short_q(pq_sref_con_add(
                            (pq_sc_out->v1).poly[i * PQ_SPEND_SUBRING_SIZE + j] +
                                (1 - 2 * pq_sc_a_hat[0][i]) *
                                    pq_sc_alpha_b1yout[0].poly[i * PQ_SPEND_SUBRING_SIZE + j] +
                                (1 - 2 * pq_sc_a_hat[1][i]) *
                                    pq_sc_alpha_b1yout[1].poly[i * PQ_SPEND_SUBRING_SIZE + j],
                            PQ_SPEND_Q << 1)) +
                        3 * (PQ_SPEND_Q - pq_sc_c[i] * pq_sc_a3y1_2.poly[i * PQ_SPEND_SUBRING_SIZE + j]));
      }
    }

    /* P_j = \sum_{i = 0}^{PQ_SPEND_M - 2} (a_i' * \hat{pk}_{i, j}) + \hat{pk}_{PQ_SPEND_M - 1, j}
     */
    /* Parallel preparation supplies p. */

    /* s = \sum_{i = 0}^{PQ_SPEND_M - 2} (a_i' * sk_i) + sk_{PQ_SPEND_M - 1} */
    for (i = 0; i < PQ_SPEND_N_BAR + PQ_SPEND_K; i++) {
      pq_spend_mult_r(pq_sc_s + i, &pq_sc_alpha_prime_0, (pq_sc_sk_in[0]) + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        pq_sc_s[i].poly[j] += pq_sc_sk_in[1][i].poly[j];
      }
    }

    /* (a_0^2,...,a_{PQ_SPEND_N_SPENT + 1}^2) */
    /* Parallel preparation supplies a2. */

    /* rb <-- S_1^{\hat{n} + \hat{k}} */
    /* ra <-- D_B^{\hat{n} + \hat{k}} */


    /* Parallel preparation supplies rb_ra. */

    /* B = G' * (r_b, b, c) */
    /* A = G' * (r_a, a, d) */
    for (i = 0; i < PQ_SPEND_N_HAT; i++) {
      pq_spend_copy_poly((pq_sc_out->b) + i, pq_sc_rb_ntt + i);
      pq_spend_copy_poly(pq_sc_a_rs + i, pq_sc_ra_ntt + i);
    }
    for (i = 0; i < PQ_SPEND_K_HAT; i++) {
      for (j = 0; j < PQ_SPEND_N_HAT; j++) {
        pq_spend_mult_plus_rqhat((pq_sc_out->b) + j, pq_sc_mat3[i] + j, pq_sc_rb_ntt + PQ_SPEND_N_HAT + i);
        pq_spend_mult_plus_rqhat(pq_sc_a_rs + j, pq_sc_mat3[i] + j, pq_sc_ra_ntt + PQ_SPEND_N_HAT + i);
      }
    }
    for (i = 0; i < PQ_SPEND_N_SPENT + 2; i++) {
      for (j = 0; j < PQ_SPEND_N_HAT; j++) {
        for (k = 0; k < PQ_SPEND_D; k++) {
          (pq_sc_out->b)[j].poly[k] += (-pq_sc_delta[i]) & pq_sc_mat3[PQ_SPEND_K + i][j].poly[k];
        }

        pq_spend_mult_plus_rqhat(pq_sc_a_rs + j, pq_sc_mat3[PQ_SPEND_K + i] + j, pq_sc_a_ntt_qhat + i);
      }
    }
    for (i = 0; i < PQ_SPEND_N_SPENT + 2; i++) {
      for (j = 0; j < PQ_SPEND_N_HAT; j++) {
        pq_spend_mult_plus_rqhat_pm((pq_sc_out->b) + j, pq_sc_mat3[PQ_SPEND_K + PQ_SPEND_N_SPENT + 2 + i] + j,
                           pq_sc_a_ntt_qhat + i, pq_sc_delta[i]);
        pq_spend_mult_minus_rqhat(pq_sc_a_rs + j, pq_sc_mat3[PQ_SPEND_K + PQ_SPEND_N_SPENT + 2 + i] + j, pq_sc_a2_ntt + i);
      }
    }

    /* y <-- D_{13 * B_{rs}}^{\bar{n} + k} */

    /* Parallel preparation supplies y. */

    /* E = G * y - \sum_{j = 0}^{PQ_SPEND_N_SPENT - 1} a_j * P_j */
    for (i = 0; i < PQ_SPEND_N_BAR; i++) {
      pq_spend_copy_poly(pq_sc_e + i, pq_sc_y_ntt + i);
    }
    for (i = 0; i < PQ_SPEND_K; i++) {
      for (j = 0; j < PQ_SPEND_N_BAR; j++) {
        pq_spend_mult_plus_rq(pq_sc_e + j, pq_sc_mat1[i] + j + (PQ_SPEND_N - PQ_SPEND_N_BAR), pq_sc_y_ntt + PQ_SPEND_N_BAR + i);
      }
    }
    for (i = 0; i < PQ_SPEND_N_SPENT; i++) {
      for (j = 0; j < PQ_SPEND_N_BAR; j++) {
        pq_spend_mult_minus_rq(pq_sc_e + j, pq_sc_a_ntt + i, pq_sc_p[i] + j);
      }
    }


        if(status[0])return;
        pq_spend_hash_x(arena,offsets,status);
        pq_sc_control[0]=PQ_SPEND_F;
    } else if(phase==PQ_SPEND_F) {
    /* f_j = x * b_j + a_j */
    for (i = 1; i < PQ_SPEND_N_SPENT + 2; i++) {
      for (j = 0; j < PQ_SPEND_D; j++) {
        pq_sc_x_delta[i - 1].poly[j] = (-pq_sc_delta[i]) & (pq_sc_out->x).poly[j];
        (pq_sc_out->f1)[i - 1].poly[j] = pq_sc_x_delta[i - 1].poly[j] + pq_sc_a[i].poly[j];
      }
    }

        pq_sc_control[0]=PQ_SPEND_GZ;
    } else if(phase==PQ_SPEND_GZ) {
    /* f_0 */
    for (i = 0; i < PQ_SPEND_D; i++) {
      pq_sc_f0.poly[i] = ((-pq_sc_delta[0]) & (pq_sc_out->x).poly[i]) + pq_sc_a[0].poly[i];
    }

    /* g_0 = f_0(x - f_0) */
    pq_spend_mult_fxf(pq_sc_g, &pq_sc_f0, &(pq_sc_out->x), status);

    /* check g_0 norm here */
    for (j = 0; j < PQ_SPEND_D; j++) {
      rej |= pq_spend_lt(PQ_SPEND_BG_0, pq_sc_g[0].poly[j]) | pq_spend_lt(pq_sc_g[0].poly[j], -PQ_SPEND_BG_0);
    }
    if (rej) {status[1]=1u;return;}

    /* g_1 = (f_1(x - f_1),...,f_{PQ_SPEND_N_SPENT + 1}(X - f_{PQ_SPEND_N_SPENT + 1})) */
    for (i = 1; i < PQ_SPEND_N_SPENT + 2; i++) {
      pq_spend_mult_fxf(pq_sc_g + i, (pq_sc_out->f1) + i - 1, &(pq_sc_out->x), status);
    }

    /* check g_1 norm here */
    for (i = 1; i < PQ_SPEND_N_SPENT + 2; i++) {
      for (j = 0; j < PQ_SPEND_D; j++) {
        rej |= pq_spend_lt(PQ_SPEND_BG_1, pq_sc_g[i].poly[j]) | pq_spend_lt(pq_sc_g[i].poly[j], -PQ_SPEND_BG_1);
      }
    }
    if (rej) {status[1]=1u;return;}

    /* z = y + x * s */
    for (i = 0; i < PQ_SPEND_N_BAR + PQ_SPEND_K; i++) {
      pq_spend_mult_r(pq_sc_x_s + i, &(pq_sc_out->x), pq_sc_s + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->z)[i].poly[j] = pq_sc_x_s[i].poly[j] + pq_sc_y[i].poly[j];
      }
    }

        pq_sc_control[0]=PQ_SPEND_OP;
    } else if(phase==PQ_SPEND_OP) {
    /* z_b = r_a + x * r_b */
    for (i = 0; i < PQ_SPEND_N_HAT + PQ_SPEND_K_HAT; i++) {
      pq_spend_mult_r(pq_sc_x_rb + i, &(pq_sc_out->x), pq_sc_rb + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->zb)[i].poly[j] = pq_sc_x_rb[i].poly[j] + pq_sc_ra[i].poly[j];
      }
    }

    /* z_{out, i} = y_{out, i} + x * ck_{out, i} */
    for (i = 0; i < PQ_SPEND_N + PQ_SPEND_K + 1; i++) {
      pq_spend_mult_r(pq_sc_x_rout[0] + i, &(pq_sc_out->x), (pq_sc_ck_out->ck) + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->z_out)[0][i].poly[j] = pq_sc_x_rout[0][i].poly[j] + pq_sc_y_out[0][i].poly[j];
      }
    }
    for (i = 0; i < PQ_SPEND_N + PQ_SPEND_K + 1; i++) {
      pq_spend_mult_r(pq_sc_x_rout[1] + i, &(pq_sc_out->x), ((pq_sc_ck_out + 1)->ck) + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->z_out)[1][i].poly[j] = pq_sc_x_rout[1][i].poly[j] + pq_sc_y_out[1][i].poly[j];
      }
    }

    /* z_0 = y_0 + x * \sum_{i = 0}^{PQ_SPEND_M - 1} ck_i */
    for (i = 0; i < PQ_SPEND_N + PQ_SPEND_K + 1; i++) {
      pq_spend_mult_r(pq_sc_x_ri + i, &(pq_sc_out->x), pq_sc_ck_in[0] + i, status);
      pq_spend_mult_r(&pq_sc_tmp_r, &(pq_sc_out->x), pq_sc_ck_in[1] + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        pq_sc_x_ri[i].poly[j] += pq_sc_tmp_r.poly[j];

        (pq_sc_out->z0)[i].poly[j] = pq_sc_x_ri[i].poly[j] + pq_sc_y0[i].poly[j];
      }
    }

    /* z_1 = y_1 + x * \rho */
    for (i = 0; i < PQ_SPEND_N + PQ_SPEND_K + 3; i++) {
      pq_spend_mult_r(pq_sc_x_rho + i, &(pq_sc_out->x), pq_sc_rho + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->z1)[i].poly[j] = pq_sc_x_rho[i].poly[j] + pq_sc_y1[i].poly[j];
      }
    }

    /* sigma^{-1}(x) */
    pq_spend_iaut_r(&pq_sc_tmp_aut_r, &(pq_sc_out->x));

    /* z_2 = y_2 + \sigma^{-1}(x) * \rho */
    for (i = 0; i < PQ_SPEND_N + PQ_SPEND_K + 3; i++) {
      pq_spend_mult_r(pq_sc_x_aut_rho + i, &pq_sc_tmp_aut_r, pq_sc_rho + i, status);

      for (j = 0; j < PQ_SPEND_D; j++) {
        (pq_sc_out->z2)[i].poly[j] = pq_sc_x_aut_rho[i].poly[j] + pq_sc_y2[i].poly[j];
      }
    }


        pq_sc_control[0]=PQ_SPEND_ENCODE;
    } else {pq_spend_error(status,1u);}
}
#undef pq_sc_setup_seed
#undef pq_sc_context
#undef pq_sc_private_seed
#undef pq_sc_a_in
#undef pq_sc_pk_out
#undef pq_sc_sk_in
#undef pq_sc_ck_in
#undef pq_sc_sn_out
#undef pq_sc_scalars
#undef pq_sc_cn_out
#undef pq_sc_ck_out
#undef pq_sc_mat1
#undef pq_sc_mat2
#undef pq_sc_mat3
#undef pq_sc_pp
#undef pq_sc_out
#undef pq_sc_a_hat
#undef pq_sc_c
#undef pq_sc_delta
#undef pq_sc_mint_ntt
#undef pq_sc_y_out
#undef pq_sc_y_out_ntt
#undef pq_sc_w_out
#undef pq_sc_y0
#undef pq_sc_y0_ntt
#undef pq_sc_w0
#undef pq_sc_a
#undef pq_sc_a_ntt
#undef pq_sc_a_ntt_qhat
#undef pq_sc_tmp_r
#undef pq_sc_t_in_sum
#undef pq_sc_rho
#undef pq_sc_rho_ntt
#undef pq_sc_y1
#undef pq_sc_y2
#undef pq_sc_y1_ntt
#undef pq_sc_y2_ntt
#undef pq_sc_w1
#undef pq_sc_w2
#undef pq_sc_w
#undef pq_sc_tmp_q
#undef pq_sc_a3y1
#undef pq_sc_a3y1_2
#undef pq_sc_b1yout
#undef pq_sc_alpha
#undef pq_sc_alpha_prime_0
#undef pq_sc_v0
#undef pq_sc_alpha_b1yout
#undef pq_sc_pk_hat
#undef pq_sc_g_gamma
#undef pq_sc_p
#undef pq_sc_alpha_prime_0_ntt
#undef pq_sc_s
#undef pq_sc_a2_ntt
#undef pq_sc_rb
#undef pq_sc_ra
#undef pq_sc_rb_ntt
#undef pq_sc_ra_ntt
#undef pq_sc_a_rs
#undef pq_sc_y
#undef pq_sc_y_ntt
#undef pq_sc_e
#undef pq_sc_g
#undef pq_sc_f0
#undef pq_sc_tmp_aut
#undef pq_sc_tmp_aut_r
#undef pq_sc_x_delta
#undef pq_sc_x_s
#undef pq_sc_x_rb
#undef pq_sc_x_rout
#undef pq_sc_x_ri
#undef pq_sc_x_rho
#undef pq_sc_x_aut_rho
#undef pq_sc_byte_work
#undef pq_sc_hash_x_bytes
#undef pq_sc_statement_bytes
#undef pq_sc_proof_bytes
#undef pq_sc_control

// end pq_spend_phases.cl
