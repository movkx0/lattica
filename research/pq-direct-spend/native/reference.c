/* Differential test oracle only. Calls the unchanged vendored keygen/mint;
 * does not generate, inspect, or recursively prove a MatRiCT spend proof. */
#include <stdint.h>
#include <string.h>
#include "fastrandombytes.h"
#include "sammat.h"
#include "keygen.h"
#include "mint.h"

void direct_spend_reference(const uint8_t seed[32], const uint8_t private_seed[32],
                            uint64_t value, uint64_t *pk_out, int64_t *sk_out,
                            uint8_t serial_out[32], uint64_t *cn_out, int64_t *ck_out) {
    POLY_Q mat1[K + 3][N], mat2[K][3], pk[N_BAR], cn[N + 1];
    POLY_R sk[N_BAR + K], ck[N + K + 1];
    uint64_t bits[R];
    fastrandombytes_setseed_pub(seed);
    fastrandombytes_setseed_prv(private_seed);
    sample_mat1(mat1);
    sample_mat2(mat2);
    keygen(pk, sk, serial_out, mat1);
    mint(cn, ck, bits, value, mat1, mat2);
    memcpy(pk_out, pk, sizeof(pk));
    memcpy(sk_out, sk, sizeof(sk));
    memcpy(cn_out, cn, sizeof(cn));
    memcpy(ck_out, ck, sizeof(ck));
    /* All seed/key material here is public deterministic test data. */
    fastrandombytes_clear_private_state();
}
