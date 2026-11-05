/* Adapted from Intel® Advanced Encryption Standard (Intel® AES) Instructions
 * Set - Rev 3.01
 * https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
 */

#include "fastrandombytes.h"
#include "cpu_generation.h"
#include <string.h>
#include <stdint.h>
#ifdef LATTICA_NATIVE_SPEND_ORACLE
#include "lattica_guard.h"
static uint64_t oracle_blocks,oracle_calls;
#endif
#include <x86intrin.h>

static __m128i round_key_pub[15];
static __m128i round_key_prv[15];
static __m128i round_key_tmp[15];
static __m128i round_key_ch[15];

static __m128i iv_pub;
static __m128i iv_prv;
static __m128i iv_tmp;
static __m128i iv_ch;

static const __m128i ONE = {1, 0};

/* we put the input string in one part of the block, and the counter in the
 * other part */
static const __m128i IV_Mat1 = {0, 0x4D617431};
static const __m128i IV_Mat2 = {0, 0x4D617432};
static const __m128i IV_Mat3 = {0, 0x4D617433};
static const __m128i IV_Ch = {0, 0x00004368};

static inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2) {
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
  temp4 = _mm_slli_si128(*temp1, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
}

static inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3) {
  __m128i temp2, temp4;
  temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
  temp2 = _mm_shuffle_epi32(temp4, 0xaa);
  temp4 = _mm_slli_si128(*temp3, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, temp2);
}

/* round_key <-- aes256_key_expansion(randomness) */
static inline void fastrandombytes_setseed(__m128i *round_key,
                                           const unsigned char *randomness) {
  __m128i temp1, temp2, temp3;

  temp1 = _mm_loadu_si128((__m128i *)randomness);
  temp3 = _mm_loadu_si128((__m128i *)(randomness + 16));
  round_key[0] = temp1;
  round_key[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[2] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[3] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[4] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[5] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[6] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[8] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[9] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[10] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[11] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[12] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  round_key[13] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  KEY_256_ASSIST_1(&temp1, &temp2);
  round_key[14] = temp1;
}

void fastrandombytes_setiv_mat1() { iv_pub = IV_Mat1; }

void fastrandombytes_setiv_mat2() { iv_pub = IV_Mat2; }

void fastrandombytes_setiv_mat3() { iv_pub = IV_Mat3; }

static inline void AES_ctr_round(__m128i *round_key, __m128i *iv,
                                 unsigned char *out) {
  __m128i tmp;

  tmp = _mm_xor_si128(*iv, round_key[0]);
  tmp = _mm_aesenc_si128(tmp, round_key[1]);
  tmp = _mm_aesenc_si128(tmp, round_key[2]);
  tmp = _mm_aesenc_si128(tmp, round_key[3]);
  tmp = _mm_aesenc_si128(tmp, round_key[4]);
  tmp = _mm_aesenc_si128(tmp, round_key[5]);
  tmp = _mm_aesenc_si128(tmp, round_key[6]);
  tmp = _mm_aesenc_si128(tmp, round_key[7]);
  tmp = _mm_aesenc_si128(tmp, round_key[8]);
  tmp = _mm_aesenc_si128(tmp, round_key[9]);
  tmp = _mm_aesenc_si128(tmp, round_key[10]);
  tmp = _mm_aesenc_si128(tmp, round_key[11]);
  tmp = _mm_aesenc_si128(tmp, round_key[12]);
  tmp = _mm_aesenc_si128(tmp, round_key[13]);
  tmp = _mm_aesenclast_si128(tmp, round_key[14]);
  _mm_storeu_si128((__m128i *)out, tmp);

  *iv = _mm_add_epi32(*iv, ONE);
}

/* r <-- aes256_ctr(round_key, iv, rlen) */
static inline void fastrandombytes(__m128i *round_key, __m128i *iv,
                                   unsigned char *r, unsigned long long rlen) {
  unsigned char ct[16];
  unsigned long long num_of_blocks = rlen >> 4;
  unsigned long long i;

  for (i = 0; i < num_of_blocks; i++) {
    AES_ctr_round(round_key, iv, r + (i << 4));
  }

  if (rlen & 0x0f) {
    AES_ctr_round(round_key, iv, ct);

    memcpy(r + (i << 4), ct, rlen & 0x0f);
  }
}

void fastrandombytes_setseed_pub(const unsigned char *randomness) {
  fastrandombytes_setseed(round_key_pub, randomness);
}

/* Independent CTR blocks share a round key, preserving the scalar stream and
 * its whole-block consumption at each call boundary. Only private generation
 * selects this path; public/challenge RNG behavior remains the reference. */
static inline __attribute__((always_inline)) void AES_ctr_group(__m128i *keys, __m128i *iv,
                                 unsigned char *out, unsigned lanes) {
  __m128i blocks[8];
  #pragma GCC unroll 8
  for (unsigned i=0;i<lanes;i++) {
    blocks[i]=_mm_xor_si128(*iv,keys[0]);
    *iv=_mm_add_epi32(*iv,ONE);
  }
  for (unsigned round=1;round<14;round++) {
    #pragma GCC unroll 8
    for (unsigned i=0;i<lanes;i++) blocks[i]=_mm_aesenc_si128(blocks[i],keys[round]);
  }
  #pragma GCC unroll 8
  for (unsigned i=0;i<lanes;i++) {
    blocks[i]=_mm_aesenclast_si128(blocks[i],keys[14]);
    _mm_storeu_si128((__m128i *)(out+16*i),blocks[i]);
  }
  volatile __m128i *wipe_blocks=blocks;
  #pragma GCC unroll 8
  for (unsigned i=0;i<lanes;i++) wipe_blocks[i]=_mm_setzero_si128();
}
static void fastrandombytes_private(unsigned char *out, uint64_t bytes, unsigned lanes) {
  if (lanes==1) { fastrandombytes(round_key_prv,&iv_prv,out,bytes); return; }
  while (bytes >= 16*lanes) {
    if (lanes==4) AES_ctr_group(round_key_prv,&iv_prv,out,4);
    else AES_ctr_group(round_key_prv,&iv_prv,out,8);
    out+=16*lanes; bytes-=16*lanes;
  }
  fastrandombytes(round_key_prv,&iv_prv,out,bytes);
}

void fastrandombytes_setseed_prv(const unsigned char *randomness) {
  fastrandombytes_setseed(round_key_prv, randomness);
  iv_prv = _mm_setzero_si128();
#ifdef LATTICA_NATIVE_SPEND_ORACLE
  oracle_blocks=oracle_calls=0;
#endif
}

void fastrandombytes_setseed_tmp(const unsigned char *randomness) {
  fastrandombytes_setseed(round_key_tmp, randomness);
  iv_tmp = _mm_setzero_si128();
}

void fastrandombytes_setseed_ch(const unsigned char *randomness) {
  fastrandombytes_setseed(round_key_ch, randomness);
  iv_ch = IV_Ch;
}

void fastrandombytes_pub(unsigned char *r, unsigned long long rlen) {
  fastrandombytes(round_key_pub, &iv_pub, r, rlen);
}

void fastrandombytes_prv(unsigned char *r, unsigned long long rlen) {
  lattica_cpu_generation_random_request(rlen);
#ifdef LATTICA_NATIVE_SPEND_ORACLE
  uint64_t blocks=rlen/16+(rlen%16!=0);
  if(blocks>(UINT64_C(1)<<32)-oracle_blocks || oracle_calls==UINT64_MAX)
    lattica_matrict_abort();
  oracle_blocks+=blocks;oracle_calls++;
#endif
  fastrandombytes_private(r,rlen,lattica_cpu_generation_aes_lanes());
}

void fastrandombytes_tmp(unsigned char *r, unsigned long long rlen) {
  fastrandombytes(round_key_tmp, &iv_tmp, r, rlen);
}

void fastrandombytes_ch(unsigned char *r, unsigned long long rlen) {
  fastrandombytes(round_key_ch, &iv_ch, r, rlen);
}

static void erase_owned(void *pointer,size_t length) {
  volatile unsigned char *p=pointer;
  while(length--)*p++=0;
}
void fastrandombytes_clear_private_state(void) {
  erase_owned(round_key_prv,sizeof round_key_prv);
  erase_owned(round_key_tmp,sizeof round_key_tmp);
  erase_owned(round_key_ch,sizeof round_key_ch);
  erase_owned(&iv_prv,sizeof iv_prv);
  erase_owned(&iv_tmp,sizeof iv_tmp);
  erase_owned(&iv_ch,sizeof iv_ch);
#ifdef LATTICA_NATIVE_SPEND_ORACLE
  oracle_blocks=oracle_calls=0;
#endif
}
#ifdef LATTICA_NATIVE_SPEND_ORACLE
uint64_t fastrandombytes_oracle_private_blocks(void){return oracle_blocks;}
uint64_t fastrandombytes_oracle_private_calls(void){return oracle_calls;}
#endif

#ifdef LATTICA_CPU_GENERATION_ORACLE
int lattica_cpu_generation_test_rng(const uint8_t seed[32], uint64_t counter,
    unsigned lanes, uint8_t *out, size_t bytes, uint64_t *next_counter) {
  uint64_t blocks=bytes/16+(bytes%16!=0);
  if (!seed || !out || !next_counter || counter>(UINT64_C(1)<<32) ||
      blocks>(UINT64_C(1)<<32)-counter || (lanes!=1 && lanes!=4 && lanes!=8)) return 0;
  fastrandombytes_setseed_prv(seed);
  iv_prv=_mm_set_epi64x(0,(long long)counter);
  fastrandombytes_private(out,bytes,lanes);
  *next_counter=counter+blocks;
  fastrandombytes_clear_private_state();
  return 1;
}
#endif
