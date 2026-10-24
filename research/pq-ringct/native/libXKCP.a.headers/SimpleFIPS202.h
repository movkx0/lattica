#ifndef LATTICA_SIMPLE_FIPS202_H
#define LATTICA_SIMPLE_FIPS202_H
#include <stddef.h>
#include <stdint.h>
/* Implemented by the Rust sha3 crate; same return convention as XKCP. */
int SHAKE256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#endif
