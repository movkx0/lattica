# Native SHAKE CPU verification memory prerequisite

This opt-in prerequisite does not change the transaction factory or enable
paired SHAKE dispatch. It admits the pinned release x86_64 native SHAKE verifier
before configuration construction or numerical verification. The default
verification configuration and cryptographic parameters remain unchanged.

The planner checks physical type layouts, the hiding profile, AIR geometry,
degree, proof lengths, and every owned proof/public vector and Merkle-cap
capacity. It reserves a separate 64 MiB `IndependentVerifier` component from the
shared worker ledger and requires a same-ledger `NativeProof` reservation for
the backing. The token borrows the inputs and producer reservation and owns its
temporary reservation through configuration teardown. Errors use an inline,
bounded UTF-8 diagnostic rather than retaining a heap string after release.

The enclosing producer must still bind its reservation to the actual proof
storage from generation through destruction. A generic category reservation
does not establish that ownership mapping. The existing factory is untouched;
producer ownership, complete phase admission, and recursive closure remain
separate prerequisites for paired dispatch.

The bound sums Rust allocation requests, including replacement buffers and all
42 periodic interpolations. It is not an RSS or complete-worker bound. Runtime
thread pools/stacks, allocator overhead, OS entropy internals, callbacks,
caller reports and enclosing worker storage require separate accounting.
Production type/profile checks refuse unsupported configurations.

Two producer capacity cases are handled explicitly: hiding PCS drains four
elements from random/quotient openings of original length seven, and FRI
truncates its final blowup-sized vector of length sixteen before IDFT. Their
logical lengths remain three and one. The audit charges their actual retained
capacity within source-derived limits; it does not infer a bound from samples.

## Serialized qualification on 2026-10-24

The coordinator ran Rust 1.96 release tests with feature
`native-verification-allocation-audit`, without the dependency's conflicting
`stream` global allocator, using one test thread and the existing resource guard.
Each accepted run ended successfully, was reaped, and had unchanged source and
executable audit hashes.

| Check | Result |
| --- | --- |
| Focused geometry, capacity, admission, ownership/drop, diagnostics | 5 passed |
| Allocation observations, including zero-allocation admission/refusal | 3 passed |
| Fresh native CPU proof, independent verification, public/proof mutations and cleanup | 1 passed |

The fresh single-segment verification requested **3,180,216 bytes in 35,262
allocation calls**, below the **17,027,224-byte** source-derived cumulative bound
and the fixed 64 MiB component reservation. The admission/refusal observation
requested zero bytes in zero calls. These are CPU verification measurements,
not fresh GPU work or complete-workflow performance evidence.

The test commands, from this crate with the coordinator's toolchain and guard,
were:

```text
cargo test --release --features native-verification-allocation-audit --lib component_tree::shake_verification_memory::tests:: -- --test-threads=1
cargo test --release --features native-verification-allocation-audit --lib component_tree::shake_verification_memory::tests::observation:: -- --ignored --test-threads=1 --nocapture
cargo test --release --features native-verification-allocation-audit --lib component_tree::shake_verification_memory::tests::fresh_native_proof_verifies_and_statement_mutation_releases_reservation -- --ignored --exact --test-threads=1 --nocapture
```

Coordinator artifact SHA-256 values:

| Run | JSON | Log |
| --- | --- | --- |
| `tests4` | `0ac0fa065f1b836c1e453b810cb444e7db0077fd69e43d153a1a81fa79118938` | `a70c33f0a6f2abf4012a422b835efec5873ef9fad678147feaf138821aabd211` |
| `allocations2` | `900c22dc9f2bbdc04aa9637ab4ad4a004c91a7074bc29772548b03239bdd9f53` | `22c819fce31668496872a0f22f093877b0af5de5332dda85cf19d978913e7cd5` |
| `fresh2` | `f5d31380e8bf008a7de40f34cf8b9124aaf09097d5aba754b289531f5bdd618b` | `529e96a01da62be90dc2711684309f369873273df3a4bf2af67fbaa7dcae01fb` |

Earlier failed attempts remain in the coordinator's evidence archive. They
identified a non-cloneable test fixture, an incorrect coset layout guard
(the pinned type stores a cached inverse), and the retained producer capacities
described above. No failed run is counted as qualification or a speedup.

## Ownership and pre-reserved verifier prerequisite

`NativeProductionPlan` binds an immutable request borrow and exact segment
index before claiming a same-ledger, exact-category, exact-size `NativeProof`
reservation. Its source bound includes the corrected producer capacities,
temporary public-vector backing and both ownership headers. The fixed 64 MiB
output reservation remains inside the shared worker allowance. Moves preserve
the charge, and payload destruction precedes reservation release.

The pending owner cannot accept an arbitrary artifact. Its private production
method requires an uninhabited dispatch permit, so no current production path
can create a `ReservedNativeChild`. Tests use explicitly invalid fixtures only
after reserving storage. This is lifetime accounting groundwork; it confers no
dispatch permission, fresh-proof receipt or production acceptance.

`Plan::admit_pre_reserved` consumes an exact 64 MiB `IndependentVerifier` token
split from a same-ledger whole-phase reservation. It audits the same immutable
inputs as ordinary admission and does not charge the verifier twice. Foreign,
mixed-category, incorrectly sized and invalid-input claims fail before numeric
verification and release their consumed token.

The coordinator repeated serialized qualification after applying the complete
qualified SHAKE prerequisite chain through `d30fa57` (local ancestry `2e2ba87`).
The four accepted runs passed terminal, subprocess reaping, source-input and
executable immutability audits; their recorded raw-log hashes were checked.

| Check | Result |
| --- | --- |
| Verifier geometry, capacity and token-transfer tests | 7 passed |
| Exact request identity, token refusal, ownership/drop and unwind | 4 passed |
| Allocation observations and pre-reserved admission/refusal | 3 passed |
| Fresh CPU proof, both verification routes, mutations and cleanup | 1 passed |

The fresh test took 6.55 seconds with a guarded memory peak of 837,341,184 bytes. Ordinary
and pre-reserved verification requested 3,180,888 and 3,170,632 bytes respectively,
each below the unchanged 17,027,224-byte source-derived bound. Admission/refusal
requested zero allocation bytes. These are prerequisite checks, not GPU proving
or complete-workflow throughput results.

The test commands were the three above plus:

```text
cargo test --release --features native-verification-allocation-audit --lib graph_crypto::retention::owned::tests:: -- --test-threads=1
```

Artifacts are retained under the C worktree's `.tools/pq-opencl-opt/runs/`.
The basenames below have prefix `concurrent-c-native-` and `.json`/`.log` suffixes.

| Run | JSON SHA-256 | Log SHA-256 |
| --- | --- | --- |
| `verifier-tests-5` | `68d5545bc20244a6b50588ba422acd37d993bfb6da1efa933974863f6290da71` | `f8be4c02b5cbc4cff730c93ec2e8d489594d530c5eadb95c95095930540fc237` |
| `owner-tests-1` | `a1f50ee854975d0f3da11a9f4ef0cf90f1c5ecc59be87d0df2a120e11e10854b` | `7feb5d76b0ff467f7eeebfbbdd26914d9d0d582b1412714001804657fb2dd49d` |
| `verifier-allocations-3` | `72af00fece2f009d9d99e2fb676847d71b123084998bd10896c36c4f76d2797a` | `289ec9f9a8df6caff7781a0d24988033d83fd099d1884ff2c2af91215cacd477` |
| `verifier-fresh-proof-3` | `24cbe7a006b726acf33a06eaa12ded5e67e81174ccc58cc0fbac9a4c600aab23` | `1a78a9395f9d93fe2bcd817fde9136dfb019f681fe7d0b261931b62fd687d7ff` |
