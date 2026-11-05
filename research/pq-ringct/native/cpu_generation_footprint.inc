/* Reviewed automatic objects and parameters in spend.c, gaussian_avx.c,
 * fastrandombytes.c and cpu_generation.inc, including clear paths. Each
 * nonrecursive function/scope is counted once, even when paths do not overlap.
 * Static objects are charged separately. This is a declaration inventory,
 * not a compiler stack/RSS bound. See tools/cpu_generation_census.py. */
uint64_t lattica_cpu_generation_frame_bytes(void) {
  return
    2 * sizeof(CK_OUT *) +
    2 * sizeof(CN_OUT *) +
    6 * sizeof(POLY_R *) +
    2 * sizeof(SN_OUT *) +
    2 * sizeof(SPEND_OUT *) +
    4 * sizeof(__m128d) +
    9 * sizeof(__m128i) +
    11 * sizeof(__m128i *) +
    1 * sizeof(__m128i[8]) +
    4 * sizeof(__m256d) +
    24 * sizeof(__m256i) +
    6 * sizeof(__m256i *) +
    2 * sizeof(const ACT (*)[2]) +
    2 * sizeof(const ASK *) +
    2 * sizeof(const PK_OUT *) +
    2 * sizeof(const POLY_Q (*)[3]) +
    2 * sizeof(const POLY_Q (*)[4]) +
    2 * sizeof(const POLY_QHAT (*)[5]) +
    2 * sizeof(const POLY_R (*)[9]) +
    14 * sizeof(const POLY_R *) +
    4 * sizeof(const __m128d) +
    3 * sizeof(const __m256d) +
    2 * sizeof(const __m256i) +
    1 * sizeof(const uint32_t) +
    7 * sizeof(const uint64_t) +
    2 * sizeof(const uint64_t *) +
    2 * sizeof(const uint8_t *) +
    11 * sizeof(const unsigned char *) +
    1 * sizeof(int) +
    1 * sizeof(int64_t *) +
    5 * sizeof(lattica_cpu_generation *) +
    1 * sizeof(lattica_cpu_generation_limits) +
    3 * sizeof(lattica_cpu_generation_stats *) +
    62 * sizeof(size_t) +
    2 * sizeof(state *) +
    1 * sizeof(struct timespec) +
    9 * sizeof(uint32_t) +
    39 * sizeof(uint64_t) +
    1 * sizeof(uint64_t *) +
    1 * sizeof(uint64_t[2]) +
    5 * sizeof(uint64_t[8]) +
    2 * sizeof(uint8_t *) +
    1 * sizeof(uint8_t[32]) +
    11 * sizeof(unsigned char *) +
    1 * sizeof(unsigned char[16]) +
    1 * sizeof(unsigned char[311]) +
    2 * sizeof(unsigned char[9]) +
    9 * sizeof(unsigned int) +
    7 * sizeof(unsigned long long) +
    2 * sizeof(void (*)(const unsigned char *, __m256i *, __m256i *)) +
    1 * sizeof(void *) +
    1 * sizeof(volatile __m128i *) +
    57 * sizeof(volatile unsigned char *);
}
