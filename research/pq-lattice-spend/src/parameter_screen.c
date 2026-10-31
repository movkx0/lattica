/* Public parameter feasibility only: no witness, proof, or acceptance path. */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "labrados_python.h"
#ifndef SCREEN_REVISION
#error "Build with a pinned research profile"
#endif

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: parameter_screen BINARY_POLYNOMIALS\n");
        return 2;
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || value < 64 || value > 4096) {
        fprintf(stderr, "binary polynomial count outside [64,4096]\n");
        return 2;
    }
    size_t lengths[1] = {(size_t)value};
    /* Match the upstream Python wrapper: BIN also needs its trivial positive
       squared norm bound. A zero bound is not a valid backend input. */
    uint64_t norms[1] = {(uint64_t)value * N}, required_norms[1] = {0};
    normtype types[1] = {BIN};
    statement st;
    dch_pack_params params;
    size_t estimated_bits = 0;
    py_init_statement(st, 1, lengths, norms, required_norms, types, 0, 0, 0);
    const int status = dch_pack_params_gen(params, &estimated_bits, st, 1);
    if (status != 0) {
        printf("{\"schema\":\"lattice-parameter-screen-v2\",\"binary_polynomials\":%lu,"
               "\"backend_status\":%d,\"proof_generated\":false,\"full_ringct_relation\":false}\n",
               value, status);
        statement_free(st);
        return 1;
    }
    const int has_zk = params->pp_pack->zkp != NULL;
    printf("{\"schema\":\"lattice-parameter-screen-v2\",\"binary_polynomials\":%lu,"
           "\"backend_revision\":\"" SCREEN_REVISION "\","
           "\"degree\":%d,\"modulus\":%" PRIu64 ",\"backend_status\":0,"
           "\"zero_knowledge_requested\":true,\"zero_knowledge_stage_selected\":%s,"
           "\"reduction_rounds\":%zu,\"estimated_proof_bits\":%zu,"
           "\"estimated_proof_bytes_ceil\":%zu,\"proof_generated\":false,"
           "\"serialized_bytes_measured\":false,\"full_ringct_relation\":false,"
           "\"security_equivalence_established\":false}\n",
           value, N, (uint64_t)PS_Q, has_zk ? "true" : "false",
           params->pp_pack->np, estimated_bits, (estimated_bits + 7) / 8);
    dch_pack_params_free(params);
    statement_free(st);
    return has_zk ? 0 : 1;
}
