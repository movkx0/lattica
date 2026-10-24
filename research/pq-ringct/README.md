# Compact post-quantum RingCT research

This isolated crate generates and independently verifies private MatRiCT+
spend fixtures using the authors' permissively licensed reference implementation,
with documented local corrections. It provides a concrete native benchmark for
deciding whether to pursue a compact post-quantum transaction design in Lattica.
It does **not** yet implement a wallet, consensus transaction, or recursive
MatRiCT+ verifier.

The work lives on `pq-ringct-research`, based on
`efff6ec2d526ed8701e6de96e2ab255a3a219089`, in a separate Git worktree. The research
crate is a standalone Cargo workspace. It does not alter the original checkout's
CUDA kernels or production dependencies.

## What works

- Native private proofs and public verification for two inputs, two outputs and
  a hidden selection among ten **pairs** of input accounts.
- Fixed canonical coefficient encoding: **53,600 bytes per proof**. A standalone
  public statement is **202,848 bytes**, including **184,320 bytes of ring
  accounts**. These are verifier artifacts, not a complete on-chain transaction.
- A versioned public packet with an explicit scheme profile and caller-supplied
  expected context. The context is bound into the proof transcript.
- A separate, protocol-neutral transaction-body codec and body-binding digest.
  Its opaque fields are scaffolding; it is not wired to the MatRiCT+ relation.
- A benchmark CLI with fresh public contexts, mutation checks and verification
  in a separate process; a cost comparison gate that refuses incompatible
  measurement scopes and security requirements.

See [scheme and security scope](SCHEME.md), [source provenance and corrections](
vendor/matrict-plus/PROVENANCE.md), [packet format](docs/NATIVE_PACKET.md),
[native benchmark](docs/BENCHMARK.md),
[cost gate](docs/COST_GATE.md), and [recursive verifier investigation](
docs/RECURSION_FEASIBILITY.md).

## Build and check

The default build has no native backend. Enabling `native-matrict` requires Linux
x86_64, AVX2, AES-NI, FMA, a C compiler and an archiver. All native calls share one
mutex because the reference implementation has mutable global state.

From this worktree's root, using the isolated toolchain and caches:

```sh
export PATH=/home/access/code/lattica/.tools/rust-1.96.0/bin:$PATH
export CARGO_HOME=/tmp/lattica-pq-ringct-cargo
export CARGO_TARGET_DIR=/tmp/lattica-pq-ringct-target
cargo test --manifest-path research/pq-ringct/Cargo.toml --offline -j 2
cargo test --manifest-path research/pq-ringct/Cargo.toml --offline -j 2 \
  --features native-matrict -- --test-threads=1
```

The local cache has the pinned dependencies. On another machine, populate a
dedicated Cargo cache before using `--offline`. Benchmark generation and public
packet verification commands are in [BENCHMARK.md](docs/BENCHMARK.md).

Validation on the available Linux AVX2/AES/FMA host passed 20 default tests and
31 tests with the native feature enabled. Three native unit regressions and
seven native integration tests also passed with the C sources instrumented by AddressSanitizer and
UndefinedBehaviorSanitizer. LeakSanitizer cannot operate under this environment's
ptrace configuration and was disabled for that successful run. See
[validation evidence](data/validation-2026-10-19.json) for scope and commands.

## What the measurements mean

Compact native proofs can substantially reduce wallet proving work and the
material submitted to an aggregator. Native generation and verification timings
do not measure recursive proving. A recursive implementation must constrain the
actual verifier, including arithmetic under two lattice moduli, SHAKE, AES,
coefficient bounds and the authenticated public statement. The current outer
aggregator's shared padded trace height can also limit gains from a cheaper leaf.

At 128 transactions, these proofs alone occupy **6,860,800 bytes**, exceeding
the current **2 MiB aggregate-proof allowance**. Recursive aggregation therefore
remains relevant if that capacity and allowance are retained. It does not remove
the public data required to update and reconstruct ledger state. Replacing ring
account bytes with authenticated ledger references is separate integration work.

Lattica's existing STARK proofs use a transparent setup while hiding transaction
values. That meaning of “transparent” should not be confused with public-value
post-quantum transactions. Existing proof-size evidence and its exact scope are
recorded in [data/baselines.json](data/baselines.json).

## Remaining implementation gates

1. Select and review the security parameters and paired-ring privacy model.
2. Implement persistent wallet keys, output recovery and recipient delivery;
   authenticate ring accounts against ledger state and enforce spent serials.
3. Define the full transaction relation, including fees and required Lattica
   features, and bind every public field to the proof.
4. Implement and measure a real constrained verifier, then a matched recursive
   wrapper and full-block benchmark. Native acceptance cannot stand in for an
   in-circuit proof of acceptance.

The upstream challenge-seeding and negative-carry reduction defects, plus local bounds fixes, are
recorded in the provenance manifest. Positive proofs, negative tests and
sanitizers do not establish cryptographic soundness or side-channel safety.
This remains an experimental reference integration requiring independent review.
