# Original source graph payload ownership

The existing `lower_unproved_on_gpu` now inspects raw n10 dimensions before
entering `with_witness_preparation`. It imports through that immutable checked
view. Previously `import_statement`/`import_proof` allocated nodes and could
panic on malformed dimensions before the shared relation checked lengths.
Valid inputs use the same relation, native operations and cryptographic profile.

The `owned` module is **test-only**. It implements actual construction and
ownership of decoded native inputs, the graph's returned vector payloads, and
[symbolic container/memo/dependency scratch](SYMBOLIC.md) and
[raw native adapter storage](RAW_ADAPTERS.md).
It is not a declaration that the whole constructor is admitted. There is no
non-test owner-based lowering entry, production dispatch change or PairedV1
enablement in this increment.

## Construction and transfer

`Construction::new` accepts exact encoded statement/proof slices, context,
setup seed and the real shared ledger. It first rejects wrong packet lengths,
derives the fixed payload plan and atomically reserves every category. Only
then does it invoke the existing decoders. Borrowed encoded packet storage
belongs to the enclosing caller; this layer neither copies nor retains it.

New decoded inputs are owned, immutable and cannot escape without their token.
The source-bound decoder requests cover every retained inner and outer Vec,
the inline `Statement`/`Proof`, and the four temporary single-polynomial Vecs
used for c/v1/v2/x. After decoding, an allocation-free capacity check detects
source drift; it is additional to the prior bound, not admission of an
arbitrarily preallocated object. The shared raw view's `retained_bytes` counts
every actual capacity, including spare capacity, for qualification purposes.

Only the fixed lowering implementation can produce `PendingGraph`. It creates
`CommittedBackend`, imports the original decoded inputs and executes the same
`verify_relation`. It accepts no arbitrary callback, byte declaration or
already-created graph. A native failure leaves the backend poisoned and cannot
produce a graph. Generic imported containers and backend memo maps retire
before the pending output escapes.

`PendingGraph` carries the original graph reservation, owned decoded inputs and
growth and symbolic-scratch reservation through the native callback. The test-only GPU wrapper
waits for `with_witness_preparation` to return successfully and destroys its
report before releasing growth. A failed completion destroys the pending
output with the graph before its reservations. `OwnedGraph` then retains the
graph and original decoded inputs until destruction. It exposes borrowed views
only; moving it preserves the exact allocations and same-ledger tokens.

Field order is intentional: graph before decoded inputs, each decoded payload
before its own token, and the graph token last. Neither owner is Clone or Send
(the ledger reservation contains Rc). The original ledger handle may retire
without releasing any still-owned charge.

## Bounds and scope

`bounds.rs` is the former B013 `Ceilings` implementation, moved without changing
any formulas. The old census now imports it, avoiding a second graph bound.
It charges twice the logical ceiling for retained graph vector backing and
three times for old/new growth coexistence, using pinned Rust 1.96 behavior.
The retained and growth portions are separate tokens whose sum is that same
three-times ceiling, plus explicitly charged inline owners. No deduplication
or witness-value credit is used.

These are graph-payload and decoder allocation requests. The following remain
outside this increment and must be closed before the test-only constructor
can become a real paired producer:

- runtime/context owners;
- complete error/report, allocator, stack, driver and asynchronous cleanup
  lifetimes; and
- downstream coexistence, authenticated source keys/context and the complete
  recursive transaction and aggregation graph.

The context and setup seed retained here are inputs, not authenticated claims.
A successful unproved graph is neither native proof acceptance nor a recursive
proof. No host/GPU allowance is increased, and no CPU witness fallback is added
to a GPU entry.

## Coordinator hook and validation

The coordinator installs `pub(crate) mod source_graph;` alongside `mod import;`
in `committed_backend.rs` for its sealed test-only execution boundary.
That shared parent hook is intentionally left to the coordinator. The existing
CPU `lower_unproved` need not change for this GPU-focused increment. The census
uses the same checked raw view and bounds after this hook is present.

Authored focused tests cover all nested decoded capacities, exact reservation
admission/refusal, malformed and noncanonical decoding, duplicate serials,
moves, original-ledger retirement, poisoned native failure and the live GPU
entry's refusal before its native callback. Existing census tests still cover
all 17 raw dimensions. Two ignored CPU qualifications cover zero-allocation
refusal and a genuine native fixture lowered to a complete graph, checking
shape/commitments/manifest, pointer-preserving moves, callback growth retention
and terminal zero charges.

The private GPU wrapper is compiled for tests so its move/drop boundary can be
reviewed. **Do not schedule full graph GPU proving from this increment**: its
constructor/runtime gaps above are still open. There is no new runnable GPU
test or benchmark here. The author ran formatting and source/diff checks only;
the coordinator owns all builds and test execution.

B021/B023/B024 focused coordinator qualification passed before the raw-adapter
extension, including the genuine CPU graph and zero-allocation refusal checks.
B025 raw-adapter coverage and remaining qualification are recorded in
[RAW_ADAPTERS.md](RAW_ADAPTERS.md); they do not establish a complete GPU workflow.
