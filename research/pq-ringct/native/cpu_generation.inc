/* Retain only public parameters between fresh private spends. */
#include "cpu_generation.h"
#include "hash.h"
#include <time.h>
typedef struct {
  uint8_t seed[32], context[32], pp[32];
  POLY_Q mat1[K+3][N], mat2[K][3];
  POLY_QHAT mat3[K_HAT+2*N_SPENT+4][N_HAT];
} cpu_public_parameters;
struct lattica_cpu_generation {
  state work;
  cpu_public_parameters public;
  lattica_cpu_generation_limits limits;
  lattica_cpu_generation_stats stats;
  unsigned cache_parameters, cache_ready, aes_lanes;
#ifdef LATTICA_CPU_GENERATION_ORACLE
  uint8_t test_seed[32];
  unsigned test_seed_set, test_entropy_failure;
#endif
};
static lattica_cpu_generation *cpu_generation_active;
static uint64_t cpu_generation_clock(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC,&value)) lattica_matrict_abort();
  return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}
static void cpu_generation_exhausted(uint64_t status) {
  cpu_generation_active->stats.status=status; lattica_matrict_abort();
}
void lattica_cpu_generation_attempt(void) {
  if (!cpu_generation_active) return;
  if (cpu_generation_active->stats.attempts>=cpu_generation_active->limits.max_attempts)
    cpu_generation_exhausted(2);
  cpu_generation_active->stats.attempts++;
}
void lattica_cpu_generation_random_request(uint64_t bytes) {
  if (!cpu_generation_active) return;
  lattica_cpu_generation_stats *s=&cpu_generation_active->stats;
  uint64_t blocks=bytes/16+(bytes%16!=0);
  if (s->random_calls>=cpu_generation_active->limits.random_call_limit ||
      blocks>(UINT64_C(1)<<32)-s->random_blocks) cpu_generation_exhausted(3);
  s->random_calls++; s->random_blocks+=blocks;
}
void lattica_cpu_generation_proposals(uint64_t count) {
  if (!cpu_generation_active) return;
  lattica_cpu_generation_stats *s=&cpu_generation_active->stats;
  if (count>cpu_generation_active->limits.proposal_limit-s->proposals)
    cpu_generation_exhausted(4);
  s->proposals+=count;
}
unsigned lattica_cpu_generation_aes_lanes(void) {
  return cpu_generation_active ? cpu_generation_active->aes_lanes : 1;
}
static void cpu_generation_clear(lattica_cpu_generation *owner) {
  spend_clear_private_state(); hash_clear_private_state(); fastrandombytes_clear_private_state();
  wipe(&owner->work,sizeof owner->work);
}
size_t lattica_cpu_generation_bytes(void) { return sizeof(lattica_cpu_generation); }
lattica_cpu_generation *lattica_cpu_generation_new(const uint8_t seed[32],
    const uint8_t context[32], unsigned cache_parameters, unsigned aes_lanes) {
  if (!seed || !context || cache_parameters>1 || cpu_generation_active ||
      (aes_lanes!=1 && aes_lanes!=4 && aes_lanes!=8)) return NULL;
  lattica_cpu_generation *owner=calloc(1,sizeof(*owner));
  if (!owner) return NULL;
  memcpy(owner->public.seed,seed,32); memcpy(owner->public.context,context,32);
  owner->cache_parameters=cache_parameters; owner->aes_lanes=aes_lanes;
  return owner;
}
void lattica_cpu_generation_free(lattica_cpu_generation *owner) {
  if (!owner) return;
  if (cpu_generation_active) abort();
  wipe(owner,sizeof(*owner)); free(owner);
}
static void cpu_generation_parameters(lattica_cpu_generation *owner) {
  state *s=&owner->work; memcpy(s->seed,owner->public.seed,32);
  if (owner->cache_parameters && owner->cache_ready) {
    memcpy(s->mat1,owner->public.mat1,sizeof s->mat1);
    memcpy(s->mat2,owner->public.mat2,sizeof s->mat2);
    memcpy(s->mat3,owner->public.mat3,sizeof s->mat3);
    memcpy(s->pp,owner->public.pp,sizeof s->pp);
    owner->stats.parameter_cache_hits=1;
  } else {
    parameters(s,owner->public.context);
    if (owner->cache_parameters) {
      memcpy(owner->public.mat1,s->mat1,sizeof s->mat1);
      memcpy(owner->public.mat2,s->mat2,sizeof s->mat2);
      memcpy(owner->public.mat3,s->mat3,sizeof s->mat3);
      memcpy(owner->public.pp,s->pp,sizeof s->pp); owner->cache_ready=1;
    }
  }
}
int lattica_cpu_generation_spend(lattica_cpu_generation *owner,
    uint64_t index, uint64_t in0, uint64_t in1, uint64_t out0, uint64_t out1,
    lattica_cpu_generation_limits limits, uint8_t *statement, size_t statement_len,
    uint8_t *proof, size_t proof_len, lattica_cpu_generation_stats *stats) {
  if (!owner || !statement || !proof || !stats || cpu_generation_active ||
      statement_len!=STATEMENT_BYTES || proof_len!=PROOF_BYTES || index>=N_SPENT ||
      in0>=AMOUNT_LIMIT || in1>=AMOUNT_LIMIT || out0>=AMOUNT_LIMIT || out1>=AMOUNT_LIMIT ||
      in0+in1!=out0+out1 || !limits.max_attempts || limits.max_attempts>1024 ||
      !limits.random_call_limit || limits.random_call_limit>(UINT64_C(1)<<24) ||
      !limits.proposal_limit || limits.proposal_limit>(UINT64_C(1)<<28)) return 0;
  memset(statement,0,statement_len); memset(proof,0,proof_len);
  memset(&owner->stats,0,sizeof owner->stats); owner->limits=limits; owner->stats.status=1;
  uint8_t private_seed[32]={0}; uint64_t amounts[S]={out0,out1}; state *s=&owner->work;
  cpu_generation_active=owner; native_failure_armed=1;
  if (setjmp(native_failure)) goto done;
  uint64_t start=cpu_generation_clock();
#ifdef LATTICA_CPU_GENERATION_ORACLE
  if (owner->test_entropy_failure) { owner->stats.status=5; goto done; }
  if (owner->test_seed_set) memcpy(private_seed,owner->test_seed,32);
  else
#endif
  if (!entropy(private_seed,32)) { owner->stats.status=5; goto done; }
  fastrandombytes_setseed_prv(private_seed); wipe(private_seed,sizeof private_seed);
  cpu_generation_parameters(owner); owner->stats.parameters_ns=cpu_generation_clock()-start;
  start=cpu_generation_clock();
  for (size_t i=0;i<N_SPENT;i++) for (size_t j=0;j<M;j++) {
    uint64_t amount=(i==index)?(j?in1:in0):(uint64_t)(1000+i*17+j);
    keygen(s->ring[i][j].pk,s->scratch_sk,s->scratch_sn,s->mat1);
    mint(s->ring[i][j].cn,s->scratch_ck,s->scratch_bits,amount,s->mat1,s->mat2);
    if (i==index) {
      memcpy(s->witnesses[j].sk,s->scratch_sk,sizeof s->scratch_sk);
      memcpy(s->witnesses[j].ck,s->scratch_ck,sizeof s->scratch_ck);
      memcpy(s->witnesses[j].sn,s->scratch_sn,32); s->witnesses[j].amt_in=amount;
    }
  }
  for (size_t i=0;i<S;i++) keygen(s->recipients[i].pk,s->scratch_sk,s->scratch_sn,s->mat1);
  owner->stats.inputs_ns=cpu_generation_clock()-start; start=cpu_generation_clock();
  spend(&s->proof,s->coins,s->output_keys,s->serials,s->ring,index,s->witnesses,
      s->recipients,amounts,s->mat1,s->mat2,s->mat3,s->pp);
  owner->stats.spend_ns=cpu_generation_clock()-start; start=cpu_generation_clock();
  if (!memcmp(s->serials[0].sn,s->serials[1].sn,32) ||
      !statement_encode(s,statement) || !proof_codec(&s->proof,proof,NULL)) goto done;
  owner->stats.encoding_ns=cpu_generation_clock()-start; owner->stats.status=0;
done:
  native_failure_armed=0; cpu_generation_active=NULL;
  uint64_t cleanup_start=cpu_generation_clock();
  cpu_generation_clear(owner); wipe(private_seed,sizeof private_seed); wipe(amounts,sizeof amounts);
  if (owner->stats.status) { wipe(statement,statement_len); wipe(proof,proof_len); }
  owner->stats.cleanup_ns=cpu_generation_clock()-cleanup_start; *stats=owner->stats;
  return owner->stats.status ? -1 : 1;
}
#ifdef LATTICA_CPU_GENERATION_ORACLE
int lattica_cpu_generation_test_seed(lattica_cpu_generation *owner, const uint8_t seed[32]) {
  if (!owner || !seed || cpu_generation_active) return 0;
  memcpy(owner->test_seed,seed,32); owner->test_seed_set=1; return 1;
}
void lattica_cpu_generation_test_failure(lattica_cpu_generation *owner, unsigned failure) {
  if (owner && !cpu_generation_active) owner->test_entropy_failure=failure;
}
int lattica_cpu_generation_test_clean(lattica_cpu_generation *owner) {
  if (!owner || cpu_generation_active) return 0;
  const uint8_t *bytes=(const uint8_t *)&owner->work; uint8_t any=0;
  for(size_t i=0;i<sizeof owner->work;i++) any|=bytes[i]; return any==0;
}
#endif
