# Raw constructor adapters

`RawAdapterPlan` is part of `PayloadPlan.growth`. `Construction::new` admits
that combined request before decoding either packet, importing symbolic inputs,
or invoking native operations. Its original reservation survives in
`PendingGraph` until the coordinator's sealed callback/report boundary finishes.
There is no post-construction numeric admission or caller-supplied allowance.

The plan covers these fixed source containers:

- All 11 byte-producing crypto calls, including the simultaneously live u64
  readback and byte conversion. The u64 readback retains its extra status-word
  capacity after `pop`; every call is summed, even when lifetimes do not overlap.
- All eight uniform/sparse outputs, including their extra readback word. In
  particular, the mat2 iterator retains its original word allocation through
  construction of mat3.
- 185 final raw matrix polynomials, 173 regrouping copies, ten sample/alpha
  polynomials, and 40 nested row descriptors. The source `RawPoly` allocation
  is charged when `backend.rs` collects into `PolyId`; counting the resulting
  ID length would be wrong. Pinned Rust 1.96's same-alignment, divisible-layout
  in-place collect preserves that backing without shrinking. A separate small
  ID allocation is also charged for a non-specialized collector.
- Setup/binding framing and both complete transcript byte vectors. The alpha
  transcript has 225 polynomials and three byte nodes (230,496 bytes); x has 16
  polynomials and one byte node (16,416 bytes).
- One sequential arithmetic operation: both schedule-vector bounds, the NTT
  metadata maximum, serialized input, output, status, shaped result, and source
  inline containers. A factor of three covers old/new vector backing on these
  fixed empty/exact/borrowed collectors. It is not applied to arbitrary caller
  vector capacities.
- Core-private `SecretAllocation` Arc payloads, data-plan vectors, staging and
  wrapper layouts derived beside their definitions by
  `RawGraphOperationStorage`. Actual runtime/kernel owners are separate.

The fixed operation API allowance is 3,060,528 host bytes, determined by mat3
AES. It is smaller than the complete host adapter charge and is not a complete
constructor bound. The maximum raw GPU backing is 1,844,280 bytes for hash
alpha's input, geometry, scratch and output/status buffers. This device amount
is reserved on the same ledger before the first operation; the core engine
also keeps its independent live-allocation enforcement. Sequential calls scrub
and finish before their raw allocations retire. No raw device allocation is
retained between calls.

`Construction`, `PendingGraph` and `OwnedGraph` are opaque crate-visible types
under `cfg(test)` for the coordinator's sealed operation boundary. The only
added accessors check all original ledger identities and expose the derived
fixed operation allowance. There is no mutable graph accessor, Clone, arbitrary
callback, numeric admission parameter or newly enabled PairedV1 dispatch.

This patch does not supply a runtime, report/error or compiled-stack bound.
Those owners remain separate integration requirements. The authored checks
have not been executed by this agent: core wrapper/layout/metadata checks,
research source-capacity and zero-allocation checks, and host/device admission
failure-before-decode checks are queued for coordinator execution. Existing
B021/B023/B024 focused qualification passed before this extension; it is not
full GPU graph qualification.
