/* Included by matrict.c to reuse the pinned codecs and guarded native state.
 * Fixture creation stops before spend(). The output is secret owned storage,
 * never a transaction codec. All native entry points require NATIVE_LOCK. */
#define FIXTURE_WORDS 56965u
#define FIXTURE_RING 64u
#define FIXTURE_RECIPIENTS 46144u
#define FIXTURE_SK 48192u
#define FIXTURE_CK 52288u
#define FIXTURE_SERIALS 56896u
#define FIXTURE_SCALARS 56960u
_Static_assert(FIXTURE_RECIPIENTS == FIXTURE_RING + N_SPENT*M*(N_BAR+N+1)*D,
    "fixture ring ABI differs from n10");
_Static_assert(FIXTURE_WORDS == FIXTURE_SCALARS + 1 + M + S,
    "fixture scalar ABI differs from n10");

static int fixture_bounds(uint64_t index, uint64_t in0, uint64_t in1,
    uint64_t out0, uint64_t out1) {
  return index<N_SPENT && in0<AMOUNT_LIMIT && in1<AMOUNT_LIMIT &&
      out0<AMOUNT_LIMIT && out1<AMOUNT_LIMIT && in0+in1==out0+out1;
}

static int fixture_write_q(uint64_t *out, const POLY_Q *p, size_t n) {
  for(size_t i=0;i<n;i++) for(size_t j=0;j<D;j++) {
    if(p[i].poly[j]>=Q) return 0;
    *out++=p[i].poly[j];
  }
  return 1;
}

int lattica_matrict_export_spend_fixture(const uint8_t context[32],
    const uint8_t setup_seed[32], uint64_t index,
    uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    uint64_t *out, size_t words) {
  if(!context || !out || words!=FIXTURE_WORDS) return 0;
  wipe(out,words*sizeof(*out));
  if(!fixture_bounds(index,in0,in1,out0,out1)) return 0;
  state *s=calloc(1,sizeof(*s));
  if(!s)return -1;
  uint8_t private_seed[32]={0};
  int result=-1;
  if(setup_seed)memcpy(s->seed,setup_seed,32);
  else if(!entropy(s->seed,32))goto done;
  if(!entropy(private_seed,32))goto done;
  native_failure_armed=1;
  if(setjmp(native_failure))goto done;
  fastrandombytes_setseed_prv(private_seed);
  wipe(private_seed,sizeof private_seed);
  parameters(s,context);
  for(size_t i=0;i<N_SPENT;i++)for(size_t j=0;j<M;j++){
    uint64_t amount=i==index?(j?in1:in0):(uint64_t)(1000+i*17+j);
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
  if(!memcmp(s->witnesses[0].sn,s->witnesses[1].sn,32))goto done;
  for(size_t i=0;i<32;i++){out[i]=s->seed[i];out[32+i]=context[i];}
  size_t cursor=FIXTURE_RING;
  for(size_t i=0;i<N_SPENT;i++)for(size_t j=0;j<M;j++){
    if(!fixture_write_q(out+cursor,s->ring[i][j].pk,N_BAR))goto done;
    cursor+=N_BAR*D;
    if(!fixture_write_q(out+cursor,s->ring[i][j].cn,N+1))goto done;
    cursor+=(N+1)*D;
  }
  for(size_t i=0;i<S;i++){
    if(!fixture_write_q(out+cursor,s->recipients[i].pk,N_BAR))goto done;
    cursor+=N_BAR*D;
  }
  for(size_t i=0;i<M;i++)for(size_t j=0;j<N_BAR+K;j++)for(size_t k=0;k<D;k++)
    out[cursor++]=s->witnesses[i].sk[j].poly[k];
  for(size_t i=0;i<M;i++)for(size_t j=0;j<N+K+1;j++)for(size_t k=0;k<D;k++)
    out[cursor++]=s->witnesses[i].ck[j].poly[k];
  for(size_t i=0;i<M;i++)for(size_t j=0;j<32;j++)out[cursor++]=s->witnesses[i].sn[j];
  out[cursor++]=index;out[cursor++]=in0;out[cursor++]=in1;
  out[cursor++]=out0;out[cursor++]=out1;
  if(cursor!=FIXTURE_WORDS)goto done;
  result=1;
done:
  native_failure_armed=0;
  fastrandombytes_clear_private_state();
  wipe(private_seed,sizeof private_seed);
  wipe(s,sizeof *s);free(s);
  if(result!=1)wipe(out,words*sizeof(*out));
  return result;
}

#ifdef LATTICA_NATIVE_SPEND_ORACLE
#include "gaussian_avx.h"
#include "hash.h"
#include "sampleb.h"
#include "private_spend_oracle.h"

static lattica_matrict_oracle_record *oracle_records;
static size_t oracle_capacity,oracle_count;
static uint64_t oracle_attempts,oracle_attempt_limit;

void lattica_matrict_oracle_checkpoint(uint32_t phase,uint32_t component,
    const void *data,size_t bytes) {
  if(!oracle_records)return;
  if(phase==35 && component==0 && ++oracle_attempts>oracle_attempt_limit)
    lattica_matrict_abort();
  if(oracle_count>=oracle_capacity)lattica_matrict_abort();
  lattica_matrict_oracle_record *r=oracle_records+oracle_count++;
  memset(r,0,sizeof *r);
  r->phase=phase;r->component=component;r->bytes=bytes;
  r->private_blocks=fastrandombytes_oracle_private_blocks();
  if(SHAKE256(r->digest,32,data,bytes)!=0)lattica_matrict_abort();
}

static int fixture_read_q(const uint64_t *in,POLY_Q *out,size_t n) {
  for(size_t i=0;i<n;i++)for(size_t j=0;j<D;j++){
    uint64_t v=*in++;if(v>=Q)return 0;out[i].poly[j]=v;
  }
  return 1;
}
static int fixture_read_key(const uint64_t *in,POLY_R *out,size_t n) {
  for(size_t i=0;i<n;i++)for(size_t j=0;j<D;j++){
    uint64_t v=*in++;if(v!=UINT64_MAX && v>1)return 0;out[i].poly[j]=v;
  }
  return 1;
}
static int fixture_import(state *s,uint8_t context[32],const uint64_t *in) {
  for(size_t i=0;i<64;i++)if(in[i]>255)return 0;
  for(size_t i=0;i<32;i++){s->seed[i]=(uint8_t)in[i];context[i]=(uint8_t)in[32+i];}
  size_t cursor=FIXTURE_RING;
  for(size_t i=0;i<N_SPENT;i++)for(size_t j=0;j<M;j++){
    if(!fixture_read_q(in+cursor,s->ring[i][j].pk,N_BAR))return 0;
    cursor+=N_BAR*D;
    if(!fixture_read_q(in+cursor,s->ring[i][j].cn,N+1))return 0;
    cursor+=(N+1)*D;
  }
  for(size_t i=0;i<S;i++){
    if(!fixture_read_q(in+cursor,s->recipients[i].pk,N_BAR))return 0;
    cursor+=N_BAR*D;
  }
  for(size_t i=0;i<M;i++){
    if(!fixture_read_key(in+cursor,s->witnesses[i].sk,N_BAR+K))return 0;
    cursor+=(N_BAR+K)*D;
  }
  for(size_t i=0;i<M;i++){
    if(!fixture_read_key(in+cursor,s->witnesses[i].ck,N+K+1))return 0;
    cursor+=(N+K+1)*D;
  }
  for(size_t i=0;i<M;i++)for(size_t j=0;j<32;j++){
    if(in[cursor]>255)return 0;s->witnesses[i].sn[j]=(uint8_t)in[cursor++];
  }
  if(!memcmp(s->witnesses[0].sn,s->witnesses[1].sn,32))return 0;
  if(!fixture_bounds(in[cursor],in[cursor+1],in[cursor+2],in[cursor+3],in[cursor+4]))return 0;
  s->witnesses[0].amt_in=in[cursor+1];s->witnesses[1].amt_in=in[cursor+2];
  return cursor==FIXTURE_SCALARS;
}

int lattica_matrict_spend_oracle(const uint64_t *inputs,size_t words,
    const uint8_t private_seed[32],uint64_t attempt_limit,
    uint8_t *statement,size_t statement_len,uint8_t *proof,size_t proof_len,
    uint64_t *output_keys,size_t key_words,
    lattica_matrict_oracle_record *records,size_t capacity,size_t *record_count) {
  if(!inputs || words!=FIXTURE_WORDS || !private_seed || !statement ||
      statement_len!=STATEMENT_BYTES || !proof || proof_len!=PROOF_BYTES ||
      !output_keys || key_words!=S*(N+K+1)*D || !records || !capacity ||
      capacity>UINT32_MAX || !record_count || !attempt_limit)return 0;
  wipe(statement,statement_len);wipe(proof,proof_len);wipe(output_keys,key_words*8);
  wipe(records,capacity*sizeof(*records));*record_count=0;
  state *s=calloc(1,sizeof(*s));if(!s)return -1;
  uint8_t context[32]={0};
  uint64_t amounts[S]={0};
  int result=-1;
  if(!fixture_import(s,context,inputs)){result=0;goto done;}
  native_failure_armed=1;
  if(setjmp(native_failure))goto done;
  oracle_records=records;oracle_capacity=capacity;oracle_count=0;
  oracle_attempts=0;oracle_attempt_limit=attempt_limit;
  fastrandombytes_setseed_prv(private_seed);
  parameters(s,context);
  amounts[0]=inputs[FIXTURE_SCALARS+3];amounts[1]=inputs[FIXTURE_SCALARS+4];
  spend(&s->proof,s->coins,s->output_keys,s->serials,s->ring,inputs[FIXTURE_SCALARS],
      s->witnesses,s->recipients,amounts,s->mat1,s->mat2,s->mat3,s->pp);
  if(!statement_encode(s,statement) || !proof_codec(&s->proof,proof,NULL))goto done;
  /* This is the original independent public C verifier, not proof self-equality. */
  if(!verify(s->ring,s->recipients,s->coins,s->serials,&s->proof,
      s->mat1,s->mat2,s->mat3,s->pp))goto done;
  size_t cursor=0;
  for(size_t i=0;i<S;i++)for(size_t j=0;j<N+K+1;j++)for(size_t k=0;k<D;k++)
    output_keys[cursor++]=s->output_keys[i].ck[j].poly[k];
  *record_count=oracle_count;result=1;
done:
  native_failure_armed=0;
  oracle_records=NULL;oracle_capacity=oracle_count=0;
  oracle_attempts=oracle_attempt_limit=0;
  spend_clear_private_state();hash_clear_private_state();
  fastrandombytes_clear_private_state();
  wipe(amounts,sizeof amounts);wipe(context,sizeof context);wipe(s,sizeof *s);free(s);
  if(result!=1){
    wipe(statement,statement_len);wipe(proof,proof_len);wipe(output_keys,key_words*8);
    wipe(records,capacity*sizeof(*records));*record_count=0;
  }
  return result;
}

int lattica_matrict_sampler_oracle(const uint8_t private_seed[32],uint32_t kind,
    uint32_t one_rows,uint64_t *out,size_t words,uint64_t *blocks,uint64_t *calls) {
  static const size_t rows[]={N+K+1,N+K+3,N_HAT+K_HAT,N_BAR+K,N_SPENT+1};
  size_t n=kind<5?rows[kind]:(kind==5?one_rows:0);
  if(!private_seed || !out || !blocks || !calls || !n || n>11 || words!=n*D)return 0;
  wipe(out,words*8);*blocks=*calls=0;
  POLY_R *p=calloc(n,sizeof *p);if(!p)return -1;
  int result=-1;
  native_failure_armed=1;
  if(setjmp(native_failure))goto done;
  fastrandombytes_setseed_prv(private_seed);
  switch(kind){
    case 0:sample_b_nk1(p);break;
    case 1:sample_b_nk3(p);break;
    case 2:sample_b_nhatkhat(p);break;
    case 3:sample_brs_13_nbark(p);break;
    case 4:sample_ba_n1(p);break;
    case 5:sample_1(p,n);break;
    default:goto done;
  }
  for(size_t i=0;i<n;i++)for(size_t j=0;j<D;j++)out[i*D+j]=p[i].poly[j];
  *blocks=fastrandombytes_oracle_private_blocks();*calls=fastrandombytes_oracle_private_calls();
  result=1;
done:
  native_failure_armed=0;fastrandombytes_clear_private_state();
  wipe(p,n*sizeof *p);free(p);
  if(result!=1){wipe(out,words*8);*blocks=*calls=0;}
  return result;
}
#endif
