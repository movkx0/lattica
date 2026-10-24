# MatRiCT+ research source

Upstream: <https://gitlab.com/raykzhao/matrict_plus>, commit
`b24f3176d2db15ca55d91c8c9cbe1cef201c5d2d`, retrieved 2026-10-19.
The author repository accompanies Esgin, Steinfeld and Zhao, *MatRiCT+: More
Efficient Post-Quantum Private Blockchain Payments*, IEEE S&P 2022,
<https://eprint.iacr.org/2021/545>. The repository's BSD Zero Clause license is
preserved in `LICENSE`.

Only the `n10` implementation is included: two inputs, two outputs, ten candidate
pairs, degree-256 polynomial rings. Selection hides one pair index among ten
pairs. It does not provide two independent selections among ten candidates.
The upstream benchmark, cycle timer, `/dev/urandom` retry loop, Makefile, other
parameter variants, and parameter-estimation scripts are omitted. The native
adapter supplies operating-system entropy and a Rust `sha3` SHAKE256 callback
instead of XKCP. `SOURCE.json` records original and vendored file SHA-256 hashes;
`PATCHES.diff` records every source change.

## Changes to the upstream cryptographic source

1. **Challenge PRG seeding.** Upstream `fastrandombytes_setseed_ch` wrote
   `round_key_tmp`, while `fastrandombytes_ch` read `round_key_ch`. The latter was
   left zero-initialized. A standalone compilation of the original file produced
   identical 64-byte challenge streams for two distinct 32-byte seeds. The
   vendored version writes `round_key_ch`; the adapter's
   `lattica_matrict_challenge_selftest` checks distinct seeds produce different
   streams and reseeding reproduces the stream. This changes the actual
   transcript challenge expansion and is essential; the original code is not
   a valid security baseline.
2. **Parameter digest.** `setup` encoded `Q` in the field intended for `QHAT`.
   The vendored version encodes `QHAT`. This changes the public-parameter digest.
3. **Bounded rejection reads.** Public matrix, serial-image, challenge-expansion,
   hash-to-challenge, and private Gaussian uniform samplers used fixed oversized random buffers without
   bounds checks while rejecting samples. Bounds checks now fail the adapter
   call before reading beyond a buffer. They leave accepted samples unchanged.
   A rare buffer exhaustion is an explicit native failure, not a successful
   proof or silent read from adjacent memory.
4. **SHAKE failure handling.** A nonzero SHAKE256 return aborts the adapter call.
5. **Scalar rejection-sampler C arithmetic.** A potentially unaligned,
   alias-violating 64-bit load is replaced by `memcpy`; shifts use unsigned
   operands and the variable shift count is checked before use.
6. **Canonical negative-carry coefficient.** The prover's outer `v1` reduction
   receives values below `7Q`, while the original one-correction reducer can
   leave a wrapped negative coefficient. For example, `7Q-4` returned `-4`
   represented as `uint64_t`, rather than `Q-4`. A scoped reducer adds the
   second conditional correction before `v1` enters the Fiat-Shamir hash.
   Its folded intermediate lies in `(-2Q,Q)`, so the result is canonical.
   The original native verifier can accept noncanonical representatives, but
   the existing compact codec correctly rejects them. This correction changes
   neither that codec nor the verifier's accepted compact-packet language;
   previously emitted canonical packets retain their profile and semantics.
   A deterministic arithmetic self-test and real negative-carry proof tests
   cover the correction. The discovered failure is recorded in
   `../../data/negative-carry-reduction.json`.

The fail path is a C `setjmp`/`longjmp` entirely inside the native adapter. No
active Rust callback frame is crossed. Heap state is wiped and released on
return. All calls, including the challenge self-test, must run under the same
process-wide mutex: upstream public matrices, PRG state and prover/verifier
scratch storage are global/static. Upstream static secret scratch is not fully
zeroized; this remains a research implementation.

These changes do not amount to an audit of the upstream implementation or a
security proof of the integration. This fork's source and transcript differ
from unmodified upstream benchmarks; results must identify the patched profile.
