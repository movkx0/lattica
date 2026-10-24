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
