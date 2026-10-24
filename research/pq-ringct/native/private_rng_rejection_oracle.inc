/* Included by matrict.c for its C guard, wipe helper and serialized native state.
 * No diagnostic symbol or private deterministic entry point in normal builds. */
#ifdef LATTICA_NATIVE_SPEND_ORACLE
#include "private_rng_rejection_oracle.h"
#include "gaussian_avx.h"
#include "fastrandombytes.h"

#define ORACLE_RNG_MAX_CALLS 256u
#define ORACLE_RNG_MAX_BYTES (1u << 20)
_Static_assert(D == 256 && S == 2 && N_SPENT == 10 && N_BAR+K == 8 &&
    N+K+1 == 9 && N+K+3 == 11 && N_HAT+K_HAT == 10,
    "rejection oracle requires the fixed n10 layout");
_Static_assert(sizeof(POLY_R) == D*sizeof(uint64_t),
    "rejection oracle requires packed coefficient bitpatterns");

int lattica_matrict_rng_calls_oracle(const uint8_t private_seed[32],
    const uint32_t *lengths, size_t count, uint8_t *out, size_t out_bytes,
    uint64_t *progress, size_t progress_words) {
  if(!private_seed || !lengths || !count || count>ORACLE_RNG_MAX_CALLS ||
      !progress || progress_words!=2*count || (!out && out_bytes))return 0;
  size_t total=0;
  for(size_t i=0;i<count;i++) {
    if(lengths[i]>ORACLE_RNG_MAX_BYTES-total)return 0;
    total+=lengths[i];
  }
  if(out_bytes!=total)return 0;
  wipe(out,out_bytes);wipe(progress,progress_words*sizeof(*progress));
  uint8_t zero_call_output[1]={0};
  int result=-1;
  native_failure_armed=1;
  if(setjmp(native_failure))goto done;
  fastrandombytes_setseed_prv(private_seed);
  size_t cursor=0;
  for(size_t i=0;i<count;i++) {
    /* Preserve the reference call itself even at length zero: calls increments,
     * blocks does not. No invalid empty output pointer is handed to native C. */
    fastrandombytes_prv(lengths[i]?out+cursor:zero_call_output,lengths[i]);
    cursor+=lengths[i];
    progress[2*i]=fastrandombytes_oracle_private_blocks();
    progress[2*i+1]=fastrandombytes_oracle_private_calls();
  }
  result=1;
done:
  native_failure_armed=0;
  fastrandombytes_clear_private_state();
  wipe(zero_call_output,sizeof zero_call_output);
  if(result!=1){wipe(out,out_bytes);wipe(progress,progress_words*sizeof(*progress));}
  return result;
}

enum {
  ORACLE_OP_ZOUT=0,
  ORACLE_OP_Z1=ORACLE_OP_ZOUT+S*(N+K+1),
  ORACLE_OP_Z2=ORACLE_OP_Z1+(N+K+3),
  ORACLE_OP_Z0=ORACLE_OP_Z2+(N+K+3),
  ORACLE_OP_ZB=ORACLE_OP_Z0+(N+K+1),
  ORACLE_OP_XROUT=ORACLE_OP_ZB+(N_HAT+K_HAT),
  ORACLE_OP_XRHO=ORACLE_OP_XROUT+S*(N+K+1),
  ORACLE_OP_XAUT=ORACLE_OP_XRHO+(N+K+3),
  ORACLE_OP_XRI=ORACLE_OP_XAUT+(N+K+3),
  ORACLE_OP_XRB=ORACLE_OP_XRI+(N+K+1),
  ORACLE_OP_ROWS=ORACLE_OP_XRB+(N_HAT+K_HAT)
};
_Static_assert(ORACLE_OP_ROWS == 118, "rejection operation row inventory");

int lattica_matrict_rejection_oracle(const uint8_t private_seed[32],
    uint32_t kind, const uint64_t *inputs, size_t input_words,
    uint64_t *result_words, size_t result_count) {
  size_t rows=kind==0?2*(N_SPENT+1):(kind==1?2*(N_BAR+K):
      (kind==2?ORACLE_OP_ROWS:0));
  if(!private_seed || !inputs || !result_words || result_count!=3 ||
      !rows || input_words!=rows*D)return 0;
  wipe(result_words,result_count*sizeof(*result_words));
  POLY_R *p=calloc(rows,sizeof *p);
  if(!p)return -1;
  memcpy(p,inputs,input_words*sizeof(*inputs));
  int result=-1;
  uint64_t decision=0;
  native_failure_armed=1;
  if(setjmp(native_failure))goto done;
  fastrandombytes_setseed_prv(private_seed);
  if(kind==0)decision=rej_f(p,p+(N_SPENT+1));
  else if(kind==1)decision=rej_z(p,p+(N_BAR+K));
  else decision=rej_op(
      (const POLY_R (*)[N+K+1])(p+ORACLE_OP_ZOUT),
      p+ORACLE_OP_Z1,p+ORACLE_OP_Z2,p+ORACLE_OP_Z0,p+ORACLE_OP_ZB,
      (const POLY_R (*)[N+K+1])(p+ORACLE_OP_XROUT),
      p+ORACLE_OP_XRHO,p+ORACLE_OP_XAUT,p+ORACLE_OP_XRI,p+ORACLE_OP_XRB);
  if(decision>1)goto done;
  result_words[0]=decision;
  result_words[1]=fastrandombytes_oracle_private_blocks();
  result_words[2]=fastrandombytes_oracle_private_calls();
  result=1;
done:
  native_failure_armed=0;
  fastrandombytes_clear_private_state();
  wipe(&decision,sizeof decision);
  wipe(p,rows*sizeof *p);free(p);
  if(result!=1)wipe(result_words,result_count*sizeof(*result_words));
  return result;
}
#endif
