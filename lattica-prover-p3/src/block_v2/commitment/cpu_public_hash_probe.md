# Isolated CPU public hashing comparison

The source is deliberately unhooked. The coordinator may add
`#[cfg(test)] mod cpu_public_hash_probe;` to `commitment.rs` and run the two
focused tests and the one ignored component test under its serial CPU guard.
This file changes no manifests, production CLI, registration, GPU execution
policy, identity receipt, or cryptographic parameter.

Both inputs use domain `0x4c42563210` and the exact frozen A005 generator:
`((i * 0x9e3779b97f4a7c15) mod 2^64) mod 0xffffffff00000001`.
Input identity is SHA3-256 of the ASCII bytes `lattica-redux-sum-input-v1`, then
the domain, field count, and each canonical field as little-endian u64 values.
The SHA3 pass uses a 32 KiB stack batch. Hashing uses the unchanged scalar
`commitment::stream::hash_fields`, with no full payload vector. Its permutation
state and library initialization retain their existing bounded storage; the
probe does not claim a complete heap, allocator, process, or thread-stack bound.
The enclosing guard remains responsible for process memory and thread limits.

The small input contains 1,048,577 fields (8,388,616 canonical bytes and 262,145
sponge permutations). Its SHA3 and Poseidon2 output are pinned to the independent
CPU slice oracle and equal GPU outputs from A005. This is an exact input match
to that standalone component, although separate CPU and GPU runs do not form
a matched alternating performance experiment.

The large input contains 50,764,992 fields (406,119,936 canonical bytes and
12,691,248 sponge permutations). That field count matches the measured research
registration, but its values are synthetic. No actual registration metadata
stream was captured. Its first scalar execution supplies only a repeat-check
digest, not an independent full-input oracle. Source tests compare the existing
slice and stream implementations on small inputs across sponge and SHA3 batch
boundaries. The emitted large input SHA3 can bind a future exact-input GPU
comparison; the existing real-registration GPU timings are not such a match.

The ignored test creates each input identity and reference once, then makes
three scalar hash calls per input in small/large, large/small, small/large order.
Each call includes on-demand field generation, canonical checks, permutation
initialization and sponge execution. Input SHA3, reference calls and JSON output
are outside the measured component calls; reference and SHA3 times are reported
separately. No prepared public state is retained across calls. There is one
scalar sponge and one distinct input per call; CPU target flags do not turn
these into multiple independent transactions or packed work.

No GPU work, proof generation, recursive graph, independent large-input GPU
verification, or complete workflow is measured. All GPU-required preprocessing,
GPU receipt, production selector, fresh-proof and faithful RingCT performance
claims are explicitly false. Even a large measured CPU advantage requires a
separate execution-policy/report decision before any registration substitution.

Coordinator checks to run (not executed by the author):

- `cpu_public_hash_fixture_stream_matches_slice_boundaries`
- `cpu_public_hash_fixture_geometry_and_iterator_termination_are_fixed`
- `cpu_public_hash_exact_small_and_registration_count_timing` with `--ignored`

Record the exact build, selected test, source hashes, CPU resource envelope,
complete emitted sequence and terminal cleanup. Preserve any failure or
inconclusive measurement without changing production defaults.
