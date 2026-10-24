# Direct-spend research profiles

This isolated crate contains two explicitly different research profiles. It does
not change production transaction acceptance or generate an adoptable protocol.
Both fix two inputs, two outputs and 52-bit values. Neither permits unrestricted
splitting, minting or fees in this initial comparison.

| Profile | Implemented | Unfinished / qualification boundary |
| --- | --- | --- |
| `ring-direct-v1` | Direct host relation and an optional bounded constrained-program compiler: one hidden choice among ten ordered account pairs; ternary lattice secrets; exact original NTT/Montgomery equations; input/output commitment openings; integer ranges/balance; AES-derived public serial linkage | Current inline compiler refused the fixed 256 MiB program allowance during ownership constraints. No registered proof/proving orchestration, independent verifier reconstruction, recursive closure or artifact format. `ring::prove` always returns `IncompleteProofCoverage`. Host checks are **not** proofs. |
| `private-note-direct-v1` | Existing join-split AIR, unchanged: ownership, depth-32 authenticated membership, commitments, nullifiers, ranges and balance. Strict profile/context/canonical statement admission; fresh CPU proving; independent CPU verification; bounded artifact round trip | Different keys, anonymity and ledger semantics. No RingCT graph or aggregate. GPU execution, matched complete-workflow measurements and security adoption review remain absent. |

The ring compiler reuses the actual constrained arithmetic in
`pq-ringct::rust_verify::generic` and `ConstraintContext`; it bypasses the
delegating NTT/product hooks and emits inline constraints. It refuses any pending
cryptographic obligation. It never creates a MatRiCT spend proof or proves the
old MatRiCT verifier. The two differential host oracles are separately named and
cannot be passed to a proof verifier as evidence.

The current compiler representation is `inline-public-constant-bits-v1`. Exact
public/fixed constants use the existing canonical-from-bits gadget with known
Boolean constant wires, so constant folding eliminates redundant range hints.
All private residues and signed keys retain their original constrained input
paths. Production arithmetic modules are unchanged. This representation change
removed the initial public-constant bottleneck, but the measured compiler still
refused the same program allowance during private ownership constraints. It does
not permit a ring proof; see [validation](VALIDATION.md) for both representations'
preserved screening evidence.

## Public preprocessing and proof boundary

The MatRiCT serial gamma is public in the transaction statement. The exact
AES-256 counter stream and original bounded rejection sampler derive G(gamma).
The setup matrices are also public AES-derived data from the fixed setup seed.
The proposed verifier must recompute these values from the expected public
statement and rebuild/authenticate the registered program, rather than accept a
prover-supplied program, matrix, G value or digest. The program constrains
`selected_pk = NTT(sk[0..4]) + Mat1 * NTT(sk[4..8]) + G(gamma)` and the original
mint equations with ternary openings. A public canonical statement digest binds
the context, profile, setup seed, ordered ring, ordered recipients, output coins
and serials. This digest is a public identity, **not** a replacement for any
private relation constraint. Until verifier reconstruction and proving are
implemented and reviewed, no ring proof can be produced or accepted by this crate.

The compiler has a fixed 400 MiB logical reservation: 256 MiB builder allowance,
128 MiB preallocated witness allowance and 16 MiB auxiliary allowance. Every
witness-producing generic primitive checks space before execution; builder
failure aborts immediately without retries. This is heap-request accounting, not
measured RSS. The 8 GiB managed GPU / 4 GiB context / 32 GiB worker host / 24 GiB
native / 47 GiB process / zero-swap campaign envelope remains unchanged. No GPU
is initialized by these crate features. Compiler admission does not authorize a
proof allocation; ring proving remains disabled.

Private-note artifacts use a fixed version tag and exact expected public inputs.
The unchanged AIR binds the research profile and context through `tx_binding`
observed by Fiat-Shamir. The wrapper independently rejects duplicate nullifiers,
noncanonical public fields/keys, nonzero fee/mint, and mismatched expected
statements. Ledger anchor authorization and spent-nullifier checks still belong
to the ledger; this research wrapper cannot establish them by itself.

## Reproducible checks

Builds and CPU/GPU validation must hold the coordinator's serialized validation
slot. Run from this directory using the campaign's pinned Rust 1.96 toolchain.

```sh
cargo test --features ring-circuit,native-reference -- --test-threads=1
cargo test --release --features ring-circuit,native-reference \
  note_real_proof_roundtrip_and_cryptographic_statement_mutations \
  -- --ignored --exact --nocapture --test-threads=1
cargo run --release --features ring-circuit -- ring-direct --compile
cargo run --release -- private-note --prove
```

`native-reference` is Linux x86_64 only and requires AVX2/AES/FMA. It calls the
unchanged vendored C keygen/mint implementation, then compares its sampled secrets,
public keys, serials and commitments to the direct Rust equations at values zero,
one and `2^52 - 1`. It never generates a native spend proof. Fixed-seed fixtures
and all fixture keys are public test data, unsuitable for real funds.

The note proof test checks the real verifier against root, nullifier and output
commitment mutations after editing both the artifact envelope and expected
statement, then corrupts proof bytes and checks artifact bounds. Relation tests
cover ownership, selection/membership, openings, duplicate spends, noncanonical
arithmetic, overflow/ranges, balance, profiles and contexts. Compiler tests cover
public statement order and preallocation/first-failure admission. These are
engineering checks, not an independent cryptographic audit.

## Measurement interpretation

Reports distinguish native/recursive proof counts, active/padded rows, combined
setup/proving time, independent CPU verification and artifact round trips.
Unknown setup-only and host/GPU peak measurements remain `null`. The measured
note interval is `profile_prove_verify_roundtrip_ns`; `complete_workflow_ns` is
`null` because wallet generation, ledger processing and the matched aggregation
workflow are not measured. No result here establishes a 2x complete-workflow
improvement, RingCT compatibility, GPU throughput or adoption readiness.

Required continuation: qualify ring compiler fit; finish independently registered
full proving and verifier reconstruction within existing limits; add complete
fresh graph/aggregation/artifact/mutation/cleanup screening for each profile;
measure matched complete workflows; obtain qualified cryptographic review. Keep
both profiles separate from protocol-preserving speedup claims.

See [semantic comparison](SEMANTICS.md) for migration and security differences.
