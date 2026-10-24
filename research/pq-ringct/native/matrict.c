#include "matrict.h"
#include "lattica_guard.h"
#include "libXKCP.a.headers/SimpleFIPS202.h"
#include "fastrandombytes.h"
#include "keygen.h"
#include "mint.h"
#include "param.h"
#include "poly_red.h"
#include "sammat.h"
#include "setup.h"
#include "spend.h"
#include "verify.h"
#include <errno.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define STATEMENT_BYTES (32 + (N_SPENT*M*(N_BAR+N+1)+S*(N_BAR+N+1))*D*4 + M*32)
#define PROOF_BYTES 53600
#define AMOUNT_LIMIT (UINT64_C(1) << 52)

_Static_assert(M == 2 && S == 2 && N_SPENT == 10 && D == 256,
    "This codec supports only the pinned two-input/two-output n10 profile");
_Static_assert(N == 4 && K == 4 && N_BAR == 4 && N_HAT == 5 && K_HAT == 5,
    "Unexpected MatRiCT+ matrix dimensions");
_Static_assert(Q == 167770241 && QHAT == 3489661057 && B_6 == 38346 &&
    BA_10_6 == 565 && BRS_13_6 == 6212586,
    "Unexpected MatRiCT+ coefficient bounds");

typedef struct {
  uint8_t seed[32];
  ACT ring[N_SPENT][M];
  PK_OUT recipients[S];
  CN_OUT coins[S];
  SN_OUT serials[M];
  SPEND_OUT proof;
  POLY_Q mat1[K+3][N], mat2[K][3];
  POLY_QHAT mat3[K_HAT+2*N_SPENT+4][N_HAT];
  uint8_t pp[32];
  ASK witnesses[M];
  POLY_R scratch_sk[N_BAR+K];
  POLY_R scratch_ck[N+K+1];
  uint8_t scratch_sn[32];
  uint64_t scratch_bits[R];
  CK_OUT output_keys[S];
} state;

static jmp_buf native_failure;
static int native_failure_armed;

_Noreturn void lattica_matrict_abort(void) {
  if (native_failure_armed) longjmp(native_failure, 1);
  abort();
}

static void wipe(void *pointer, size_t length) {
  volatile uint8_t *p = pointer;
  while (length--) *p++ = 0;
}

static int entropy(uint8_t *out, size_t length) {
  unsigned interrupted = 0;
  while (length) {
    ssize_t count = getrandom(out, length, GRND_NONBLOCK);
    if (count < 0) {
      if (errno == EINTR && interrupted++ < 16) continue;
      return 0;
    }
    if (!count) return 0;
    out += (size_t)count;
    length -= (size_t)count;
  }
  return 1;
}

static void parameters(state *s, const uint8_t context[32]) {
  static const uint8_t domain[] = "lattica/pq-ringct/matrict-plus-n10/fixture-v1";
  uint8_t bound[sizeof(domain)-1 + 64];
  uint8_t original_pp[32];
  fastrandombytes_setseed_pub(s->seed);
  setup(original_pp, s->seed);
  sample_mat1(s->mat1);
  sample_mat2(s->mat2);
  sample_mat3(s->mat3);
  memcpy(bound, domain, sizeof(domain)-1);
  memcpy(bound + sizeof(domain)-1, original_pp, 32);
  memcpy(bound + sizeof(domain)-1 + 32, context, 32);
  if (SHAKE256(s->pp, 32, bound, sizeof(bound)) != 0) lattica_matrict_abort();
}

static void store32(uint8_t **cursor, uint32_t x) {
  for (unsigned i=0;i<4;i++) *(*cursor)++=(uint8_t)(x>>(8*i));
}
static uint32_t load32(const uint8_t **cursor) {
  uint32_t x=0;
  for (unsigned i=0;i<4;i++) x|=(uint32_t)*(*cursor)++<<(8*i);
  return x;
}
static int write_public(uint8_t **cursor,const POLY_Q *p,size_t n) {
  for(size_t i=0;i<n;i++) for(size_t j=0;j<D;j++) {
    if(p[i].poly[j]>=Q) return 0;
    store32(cursor,(uint32_t)p[i].poly[j]);
  }
  return 1;
}
static int read_public(const uint8_t **cursor,POLY_Q *p,size_t n) {
  for(size_t i=0;i<n;i++) for(size_t j=0;j<D;j++) {
    uint64_t x=load32(cursor);
    if(x>=Q) return 0;
    p[i].poly[j]=x;
  }
  return 1;
}
static int statement_encode(const state *s,uint8_t *out) {
  uint8_t *p=out;
  memcpy(p,s->seed,32);p+=32;
  for(size_t i=0;i<N_SPENT;i++) for(size_t j=0;j<M;j++) {
    if(!write_public(&p,s->ring[i][j].pk,N_BAR) ||
       !write_public(&p,s->ring[i][j].cn,N+1)) return 0;
  }
  for(size_t i=0;i<S;i++) if(!write_public(&p,s->recipients[i].pk,N_BAR)) return 0;
  for(size_t i=0;i<S;i++) if(!write_public(&p,s->coins[i].cn,N+1)) return 0;
  for(size_t i=0;i<M;i++){memcpy(p,s->serials[i].sn,32);p+=32;}
  return (size_t)(p-out)==STATEMENT_BYTES;
}
static int statement_decode(state *s,const uint8_t *in) {
  const uint8_t *p=in;
  memcpy(s->seed,p,32);p+=32;
  for(size_t i=0;i<N_SPENT;i++) for(size_t j=0;j<M;j++) {
    if(!read_public(&p,s->ring[i][j].pk,N_BAR) ||
       !read_public(&p,s->ring[i][j].cn,N+1)) return 0;
  }
  for(size_t i=0;i<S;i++) if(!read_public(&p,s->recipients[i].pk,N_BAR)) return 0;
  for(size_t i=0;i<S;i++) if(!read_public(&p,s->coins[i].cn,N+1)) return 0;
  for(size_t i=0;i<M;i++){memcpy(s->serials[i].sn,p,32);p+=32;}
  if(!memcmp(s->serials[0].sn,s->serials[1].sn,32)) return 0;
  return (size_t)(p-in)==STATEMENT_BYTES;
}

typedef struct { uint8_t *out;const uint8_t *in;size_t bit;int ok;} bits;
static void put(bits *b,uint32_t x,unsigned width) {
  if(width>32 || b->bit+width>PROOF_BYTES*8){b->ok=0;return;}
  for(unsigned i=0;i<width;i++,b->bit++) b->out[b->bit/8]|=((x>>i)&1u)<<(b->bit%8);
}
static uint32_t get(bits *b,unsigned width) {
  uint32_t x=0;
  if(width>32 || b->bit+width>PROOF_BYTES*8){b->ok=0;return 0;}
  for(unsigned i=0;i<width;i++,b->bit++) x|=(uint32_t)((b->in[b->bit/8]>>(b->bit%8))&1u)<<i;
  return x;
}
static void public_polys(bits *b,POLY_Q *p,size_t count,unsigned width,uint64_t modulus) {
  for(size_t i=0;i<count;i++) for(size_t j=0;j<D;j++) {
    uint64_t value=b->out?p[i].poly[j]:get(b,width);
    if(value>=modulus){b->ok=0;return;}
    if(b->out) put(b,(uint32_t)value,width);else p[i].poly[j]=value;
  }
}
static void signed_polys(bits *b,POLY_R *p,size_t count,unsigned width,int64_t bound) {
  for(size_t i=0;i<count;i++) for(size_t j=0;j<D;j++) {
    if(b->out){
      int64_t value=(int64_t)p[i].poly[j];
      if(value < -bound || value > bound){b->ok=0;return;}
      put(b,(uint32_t)(value+bound),width);
    }else{
      uint32_t value=get(b,width);
      if(value>(uint64_t)bound*2){b->ok=0;return;}
      p[i].poly[j]=(uint64_t)((int64_t)value-bound);
    }
  }
}
static int proof_codec(SPEND_OUT *p,uint8_t *out,const uint8_t *in) {
  bits b={out,in,0,1};
  if(out) memset(out,0,PROOF_BYTES);
  public_polys(&b,&p->c,1,28,Q);
  public_polys(&b,p->v,N,28,Q);
  public_polys(&b,&p->v1,1,28,Q);
  public_polys(&b,&p->v2,1,28,Q);
  public_polys(&b,p->b,N_HAT,32,QHAT);
  for(size_t i=0;i<32;i++){
    if(out)put(&b,p->alpha[i],8);else p->alpha[i]=(uint8_t)get(&b,8);
  }
  signed_polys(&b,&p->x,1,2,1);
  for(size_t i=0;i<S;i++)signed_polys(&b,p->z_out[i],N+K+1,17,B_6);
  signed_polys(&b,p->z0,N+K+1,17,B_6);
  signed_polys(&b,p->z1,N+K+3,17,B_6);
  signed_polys(&b,p->z2,N+K+3,17,B_6);
  signed_polys(&b,p->f1,N_SPENT+1,11,BA_10_6);
  signed_polys(&b,p->zb,N_HAT+K_HAT,17,B_6);
  signed_polys(&b,p->z,N_BAR+K,24,BRS_13_6);
  return b.ok && b.bit==PROOF_BYTES*8;
}

size_t lattica_matrict_statement_bytes(void){return STATEMENT_BYTES;}
size_t lattica_matrict_proof_bytes(void){return PROOF_BYTES;}

int lattica_matrict_fixture_with_setup_seed(const uint8_t context[32],
    const uint8_t setup_seed[32],uint64_t index,
    uint64_t in0,uint64_t in1,uint64_t out0,uint64_t out1,
    uint8_t *statement,size_t statement_len,uint8_t *proof,size_t proof_len) {
  if(!context || !statement || !proof || statement_len!=STATEMENT_BYTES ||
      proof_len!=PROOF_BYTES || index>=N_SPENT || in0>=AMOUNT_LIMIT ||
      in1>=AMOUNT_LIMIT || out0>=AMOUNT_LIMIT || out1>=AMOUNT_LIMIT ||
      in0+in1!=out0+out1) return 0;
  memset(statement,0,statement_len);memset(proof,0,proof_len);
  state *s=calloc(1,sizeof(*s));
  if(!s)return -1;
  uint8_t private_seed[32];
  int public_seed_ok=1;
  if(setup_seed)memcpy(s->seed,setup_seed,32);
  else public_seed_ok=entropy(s->seed,32);
  if(!public_seed_ok || !entropy(private_seed,32)){
    wipe(private_seed,sizeof private_seed);wipe(s,sizeof *s);free(s);return -1;
  }
  int result=-1;
  native_failure_armed=1;
  if(setjmp(native_failure)) goto done;
  fastrandombytes_setseed_prv(private_seed);
  wipe(private_seed,sizeof private_seed);
  parameters(s,context);
  for(size_t i=0;i<N_SPENT;i++) for(size_t j=0;j<M;j++){
    uint64_t amount=(i==index)?(j?in1:in0):(uint64_t)(1000+i*17+j);
    keygen(s->ring[i][j].pk,s->scratch_sk,s->scratch_sn,s->mat1);
    mint(s->ring[i][j].cn,s->scratch_ck,s->scratch_bits,amount,s->mat1,s->mat2);
    if(i==index){
      memcpy(s->witnesses[j].sk,s->scratch_sk,sizeof s->scratch_sk);
      memcpy(s->witnesses[j].ck,s->scratch_ck,sizeof s->scratch_ck);
      memcpy(s->witnesses[j].sn,s->scratch_sn,32);
      s->witnesses[j].amt_in=amount;
    }
  }
  for(size_t i=0;i<S;i++)keygen(s->recipients[i].pk,s->scratch_sk,s->scratch_sn,s->mat1);
  uint64_t amounts[S]={out0,out1};
  spend(&s->proof,s->coins,s->output_keys,s->serials,s->ring,index,s->witnesses,
      s->recipients,amounts,s->mat1,s->mat2,s->mat3,s->pp);
  if(!memcmp(s->serials[0].sn,s->serials[1].sn,32))goto done;
  if(!statement_encode(s,statement) || !proof_codec(&s->proof,proof,NULL))goto done;
  result=1;
done:
  native_failure_armed=0;
  wipe(private_seed,sizeof private_seed);
  wipe(s,sizeof *s);free(s);
  if(result!=1){memset(statement,0,statement_len);memset(proof,0,proof_len);}
  return result;
}

int lattica_matrict_fixture(const uint8_t context[32],uint64_t index,
    uint64_t in0,uint64_t in1,uint64_t out0,uint64_t out1,
    uint8_t *statement,size_t statement_len,uint8_t *proof,size_t proof_len) {
  return lattica_matrict_fixture_with_setup_seed(context,NULL,index,
      in0,in1,out0,out1,statement,statement_len,proof,proof_len);
}

int lattica_matrict_verify(const uint8_t context[32],const uint8_t *statement,
    size_t statement_len,const uint8_t *proof,size_t proof_len) {
  if(!context || !statement || !proof || statement_len!=STATEMENT_BYTES || proof_len!=PROOF_BYTES)return 0;
  state *s=calloc(1,sizeof(*s));
  if(!s)return -1;
  int result=0;
  if(!statement_decode(s,statement) || !proof_codec(&s->proof,NULL,proof))goto done;
  native_failure_armed=1;
  if(setjmp(native_failure)){result=-1;goto done;}
  parameters(s,context);
  result=(int)verify(s->ring,s->recipients,s->coins,s->serials,&s->proof,
      s->mat1,s->mat2,s->mat3,s->pp);
done:
  native_failure_armed=0;
  wipe(s,sizeof *s);free(s);
  return result;
}

int lattica_matrict_challenge_selftest(void) {
  uint8_t a[64],b[64],c[64],seed0[32]={0},seed1[32]={1};
  fastrandombytes_setseed_ch(seed0);fastrandombytes_ch(a,sizeof a);
  fastrandombytes_setseed_ch(seed1);fastrandombytes_ch(b,sizeof b);
  fastrandombytes_setseed_ch(seed0);fastrandombytes_ch(c,sizeof c);
  return memcmp(a,b,sizeof a)!=0 && memcmp(a,c,sizeof a)==0;
}

int lattica_matrict_reduction_selftest(void) {
  /* Exercise every fold boundary and every multiple of Q in the supported
   * interval, including the old failing 7*Q-4 input. No PRG or hardware calls.
   */
  const uint64_t limit=UINT64_C(7)*Q;
  const uint64_t values[]={0,1,Q/2,Q-2,Q-1};
  if(red_short_q(limit-4)!=(UINT64_MAX-3))return 0;
  for(uint64_t stride=Q;stride;stride=(stride==Q ? UINT64_C(1)<<27 : 0)) {
    for(uint64_t base=0;base<=limit+stride;base+=stride) {
      for(int offset=-2;offset<=2;offset++) {
        int64_t candidate=(int64_t)base+offset;
        if(candidate>=0 && (uint64_t)candidate<limit &&
            red_short_7q((uint64_t)candidate)!=(uint64_t)candidate%Q)return 0;
      }
    }
  }
  for(uint64_t t=limit-3;t<limit;t++)if(red_short_7q(t)!=t%Q)return 0;
  for(int64_t carry=-1;carry<=1;carry++) {
    for(size_t i=0;i<sizeof values/sizeof values[0];i++) {
      for(size_t j=0;j<sizeof values/sizeof values[0];j++) {
        uint64_t folded=values[i]+3*(Q-(uint64_t)carry*values[j]);
        int64_t signed_value=(int64_t)values[i]-3*carry*(int64_t)values[j];
        int64_t expected=signed_value%(int64_t)Q;
        if(expected<0)expected+=Q;
        if(folded>=limit || red_short_7q(folded)!=(uint64_t)expected)return 0;
      }
    }
  }
  return 1;
}

#include "private_spend_fixture.inc"
#include "private_rng_rejection_oracle.inc"
