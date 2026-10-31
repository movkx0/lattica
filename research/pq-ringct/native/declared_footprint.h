#ifndef LATTICA_DECLARED_FOOTPRINT_H
#define LATTICA_DECLARED_FOOTPRINT_H
#include <stddef.h>
#include <stdint.h>
#define LATTICA_MATRICT_DECLARED_FOOTPRINT_WORDS 8
/* Output words:
 * 0 ABI version (1), 1 feature flags (bit 0 native-spend-oracle),
 * 2 one entry's fixed calloc(state) requested backing,
 * 3 whole linked C library declared static payload, charged once,
 * 4 fixture reachable automatic-object payload sum,
 * 5 fixture reachable by-value parameter payload sum,
 * 6 public verify reachable automatic-object payload sum,
 * 7 public verify reachable by-value parameter payload sum.
 * Parameter pointers count only their pointer object, not borrowed pointees.
 * Caller supplies eight u64 words; returns 1 iff pointer/length are valid.
 * No physical stack/RSS claim. No Rust/libc/allocator/driver census here.
 */
int lattica_matrict_declared_footprint_v1(uint64_t *out, size_t words);
#endif
