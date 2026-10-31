# Registration reuse screening, 2026-10-24

The component screen does not justify promoting 512 metadata entries or a
larger prepared-state cache to full-workflow benchmarking. The default remains
256 metadata entries and one prepared program. Prepared reuse is disabled;
there are no new prepared-state admission tokens or retained host/device owners.
The opt-in 512-entry metadata setting and bounded telemetry remain available for
future workloads, inside the existing 64 MiB combined public allowance and
1 MiB identity-receipt sublimit.

This is a screening rejection, not a measured complete-workflow comparison or
a hard latency bound. The accepted historical run did not record a complete
exact-identity access sequence, so no observed cache-hit improvement is claimed.

## CPU constructor measurements

The feature-gated `pq-ringct-registration-metadata-screen` binary measures the
production CPU `RegisteredVerifier` constructor. No verifier, key, cap, proof,
or acceptance function escapes its backend API. It generates and verifies no
proofs and performs no GPU operations. Its fixed synthetic caps and identities
are reconstructed public inputs, not authenticated transaction artifacts.

The screen covers all 12 combinations of heights 4,096 / 65,536 / 131,072 /
262,144 and public widths 25 (batch), 28 (graph), 46 (component). At capacities
256 and 512, each configuration has three alternating constructor/lookup
batches: 32 actual constructor calls and 4,096 synthetic lookups per batch.
All 24 configurations were admitted, totaling 2,304 timed constructions and
294,912 lookups. The largest retained verifier payload was 133,928 bytes.

The lookup model is an isolated `VecDeque`, not the research registry. Its
synthetic entries share one verifier while conservatively charging that payload
per entry. Cyclic exact-hit accesses find the current oldest LRU entry, then
validate the cap and promote the shared owner. These timings do not measure
observed reuse distances, actual misses, or a 256-versus-512 workload hit rate.

The slowest observed 32-call batch averaged **0.00433864453125 seconds per
constructor**. Multiplying that sampled mean by all 2,670 historical identity
hint hits projects 11.5841808984 seconds, or **0.02891%** of the historical
40,067.428264729-second complete workflow. This deliberately optimistic
projection assumes every such hit avoids construction and has no reuse cost.
It is far below the 5% promotion threshold of 2,003.37141323645 seconds.

The screen preflights its fixed requested payload reservations: 257 MiB for
one independent constructor lifecycle, 64 MiB for public cache state, 64 KiB
for caps, and 1 MiB for reports, within a caller allowance at most 1 GiB.
Constructor outputs drop between samples; destruction is outside constructor
timing. Output serialization is bounded to 512 KiB inside the report allowance.
The enclosing CPU guard had an 8 GiB process limit, zero swap, and a
1,238,913,024-byte cgroup peak **including Cargo compilation and the screen**.
That is not an isolated component peak or a new RingCT workflow limit.

## Prepared-state necessary condition

For the accepted wide, hiding, device-only preprocessing path, two simultaneously
retained device allocations alone require:

```
preprocessing prefix = 2 * trace_rows * 200 * 8
Merkle tree          = (2 * (2 * trace_rows * 16) - 1) * 4 * 8
combined lower bound = 5248 * trace_rows - 32 bytes
```

The derivation is independent of measured allocation peaks:

- [`program.rs`](../../lattica-prover-p3/src/block_v2/machine/program.rs) fixes
  wide `LANES=23`, `EXT_LANES=7`; [`air.rs`](../../lattica-prover-p3/src/block_v2/machine/air.rs)
  sets preprocessing width `8*LANES + 2*EXT_LANES + 2 = 200`.
- [`gpu_hiding.rs`](../../lattica-prover-p3/src/gpu_hiding.rs)
  `TraceCommitShape::preprocessing` doubles trace height while retaining width.
- [`lde_execute.rs`](../../lattica-prover-p3/src/block_v2/gpu_hash/engine/lde_execute.rs)
  captures the effective degree-sized prefix; [`storage.rs`](../../lattica-prover-p3/src/block_v2/gpu_hash/engine/device/storage.rs)
  `capture_specs` retains that complete matrix.
- [`engine.rs`](../../lattica-prover-p3/src/block_v2/gpu_hash/engine.rs)
  `retained_layout` allocates all `2*LDE_height-1` nodes, each four 8-byte fields;
  [`profile.rs`](../../lattica-prover-p3/src/block_v2/profile.rs) fixes blowup 16.
- [`salt_data.rs`](../../lattica-prover-p3/src/block_v2/gpu_hash/salt_data.rs)
  `finish_salted_commit` stores the prefixes and full tree together in
  `ProverData::DeviceOnly`.

| Trace rows | Observed registrations | Device lower bound, bytes | 512 MiB idle eligibility |
| ---: | ---: | ---: | --- |
| 4,096 | 28 | 21,495,776 | Not ruled out |
| 65,536 | 21 | 343,932,896 | Not ruled out |
| 131,072 | 1,358 | 687,865,824 | Ruled out |
| 262,144 | 1,713 | 1,375,731,680 | Ruled out |

Thus 3,071 of 3,120 registrations cannot fit the idle device cap. This lower
bound excludes public salts, compiled source/schedules, all host storage,
driver/context memory, and active/temporary work. The 49 small registrations
remain **unadmitted**; no full prepared footprint or phase-overlap bound exists.

The audit tool pairs each successful preprocessing receipt with its following
`bounded_cached_prover_metadata` line. All 3,120 receipts pair exactly. The
small states consumed 47.284374840 seconds of core preprocessing receipts.
Assigning the entire 0.089646977-second aggregate core-timer discrepancy to
those states gives a **recorded core-only ceiling of 47.374021817 seconds**.
Legacy core timing excludes subsequent verifier-metadata construction.

Adding 49 times the slowest sampled constructor batch mean projects
47.586615399 seconds, or **0.11877%** of the workflow. The core portion is an
accounting ceiling; the added constructor portion is a sample-based projection,
not a hard time bound. Combined with the missing exact-identity and full-memory
admission prerequisites, this supports leaving the prepared-cache experiment
disabled at this screen. It does not establish measured cache savings.

## Verification and evidence

The coordinator serialized the CPU build/screen and focused Rust test. The
screen and corrected admission test passed with unchanged source inputs and all
subprocesses terminal and reaped. Six prepared-condition Python tests and ten
registration-replay Python tests passed. The earlier registration work also
passed 24 focused Rust checks and a real CPU fresh-witness/randomness test.
Peer review found no blocker; a lookup-order wording clarification was applied
after the measured screen. That change only expands the report string, and the
recorded timings belong to the original measured source hash below.

Artifacts are retained in the agent worktree's ignored `.tools` directory; they
are evidence, not source files to force-add. Paths below are relative to that
worktree unless absolute.

| Artifact | SHA-256 |
| --- | --- |
| `.tools/pq-opencl-opt/runs/concurrent-a-metadata-constructor-screen-1.json` | `2407e429ecbe77b630b3944f214fc0cebf5bb3a5caea70e15ecb943eb81d9d0f` |
| `.tools/pq-opencl-opt/runs/concurrent-a-metadata-constructor-screen-1.log` | `55c85854f7d5f09d28621a4260b3d3598c4a3d4a345f4a5924ac26e580a53db2` |
| `.tools/pq-opencl-opt/runs/concurrent-a-metadata-admission-tests-2.json` | `26fc2113eeeeb8a6cc95ad45ad6f4608c9bcffb4f227c5c020a7f32525a54769` |
| `.tools/pq-opencl-opt/runs/concurrent-a-metadata-admission-tests-2.log` | `eea689c130d6933751ccaff81b86601b152612736a2e2d4859da465814f4b28b` |
| `.tools/registration-metadata-component-screen-accepted.json` (extracted measurements) | `81a3e7d3a7a0859021910b82f2d276e82b012969511bc1c14fccd84a0d7133ed` |
| `.tools/prepared-reuse-ceiling-accepted.json` | `f6703da391556b5ad51580e1ed1848f1d7ff9a83158d2235412f14362f31278d` |
| `.tools/registration-screening-projection.json` | `8f0c8e8d31c597ebc31de0755346377c976860889a3d3220e6736c508cda6d2a` |
| Measured `backend/metadata_screen.rs` source | `4a43573fe3b12a8071532b26935468143163aa07df4844a770dc4a41d7dfd8fe` |

The first admission-test harness attempt used an incomplete `--exact` filter,
ran zero tests, and was correctly rejected by the guard. It is unaccepted
harness evidence, not a code test failure. Its JSON/log hashes are respectively
`9e80cb3da0428657300ac14fbf9e2161d46c67d6f6d0674547ea32479cfa3c91` and
`692972b5148da1a7eec119afc304cd9db3648372fe0cb2aa8ad94b67b0321528`.

The accepted historical evidence root is
`/home/access/code/lattica/.tools/worktrees/pq-opencl-gpu-preparation/.tools/pq-opencl-opt`.
Its `multipass-r4-new-5-benchmark-artifacts/result.json` has SHA-256
`395117e765a08d29952ed6660837eafd31a12ad600b0c31a9aae00c50b6ba09d`;
`runs/multipass-r4-new-5-benchmark.log` has SHA-256
`198e0746c3370d57b4862920d056367f8cc0847d8de6d1d74db1d3f47b22202b`.

Reproduce only through the coordinator's serialized resource guard:

```
cargo run --release --locked --offline --manifest-path research/pq-ringct/Cargo.toml --features metadata-screen --bin pq-ringct-registration-metadata-screen -- --host-bytes 1073741824
cargo test --release --locked --offline --manifest-path lattica-prover-p3/Cargo.toml --no-default-features --features verifier-metadata-screen --lib block_v2::machine::backend::metadata_screen::tests::request_and_model_budgets_reject_before_construction -- --exact --test-threads=1
```

The lightweight Python checks run from `research/pq-ringct/tools` with
`python3 -m unittest test_registration_replay test_prepared_reuse_ceiling`.
`prepared_reuse_ceiling.py REPORT LOG --output OUTPUT` reproduces the necessary
condition; it explicitly records the accepted wide-source assumption because
receipt heights alone do not authenticate lane layout.
