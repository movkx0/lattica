# Host diagnostic without trace materialization

`Program::check_host_constraints(public, witness)` calls the existing private
`Program::evaluate(public, witness)` and drops its result. The method executes
the same ordered operation list as `MachineAir::trace`, without constructing
the trace matrix. It is an opt-in diagnostic primitive. It does not evaluate the
AIR independently, prove anything, verify a proof, or alter proving defaults.

## Equivalence boundary

The claim concerns programs returned successfully by `ProgramBuilder::finish`,
optionally followed by successful `Program::pad_to`, whose immutable contents
have not been changed. It is equality of the two host diagnostic outcomes,
subject to successful allocation, not equality with independent AIR acceptance.
Arbitrary corruption of crate-private `Program` fields is outside this claim.

For a program in this domain:

1. Both diagnostics invoke the exact same evaluator. It first rejects a public
   input count mismatch, then a witness count mismatch. It allocates one field
   value per wire and executes operations in their original order. It returns
   `Unsatisfied` for failed equality, Booleanity, scalar/cubic nonzero inverse,
   or selection-bit checks. These checks and their error priority are shared,
   rather than reimplemented in the new method.
2. `finish` validates each read against an earlier defined wire, ensures writes
   have valid unique destinations, and checks selection-hint arity and bit
   indices. Input indices come from the builder's monotonic witness counter.
   The builder rejects invalid public counts. Consequently every indexed value
   read during evaluation and serialization exists.
3. `finish` creates every row directly from a valid operation index. Scalar
   operations occupy at most `LANES` slots, cubic operations occupy at most
   `EXT_LANES` slots, and a Poseidon row references a Poseidon operation. Public
   banks are constructed in order. These invariants rule out the trace path's
   later `InvalidWire` and unreachable operation-kind branches.
4. Finalization requires a supported power-of-two height at least as large as
   the active rows and the minimum height. Successful `pad_to` checks the same
   height restrictions and changes only padding. The row slices and lane
   columns therefore fit the trace. This holds for both narrow and wide machine
   layouts; those layouts change packing, not operation evaluation.
5. After evaluation, `MachineAir::trace` only copies the resulting values into
   row columns and recomputes Poseidon checkpoints. It performs no additional
   predicate on the public values or witness for a finalized program. The
   constraints-only path returns the same success or input-related error.

This argument does not justify bypassing trace construction during proving,
replacing independent verification, accepting malformed internal programs, or
claiming that unconstrained hints are sound. Those are separate properties.

## Allocation and lifetime

The primitive has no admission authority. Callers must admit all live storage
before calling it. Its primary temporary allocation is
`program.wire_count() * size_of::<Val>()`; all values are dropped on success or
error. The immutable program and borrowed public/witness inputs remain live
during this allocation. No `Arc<Program>` or trace matrix is constructed by the
new primitive. The pinned Goldilocks Poseidon2 helper has a maximum 688-byte
heap transient, `(2 * 4 * 8 + 22) * size_of::<Val>()`, and fixed local state.

The research caller's sealed `EvaluationPlan` admits retained program capacity,
the unchanged 128 MiB witness and 16 MiB auxiliary allowances, and wire values.
The auxiliary allowance covers that fixed permutation transient and closed
error formatting. It conservatively keeps the retained-program query's future
Arc charge even though this backend creates no Arc. It omits only the
`height * WIDTH * size_of::<Val>()` trace allocation. Compiler wire and row
ceilings, the selected program ceiling, and the 32 GiB worker host maximum are
unchanged. These are requested-storage bounds, not measured allocator/RSS peaks;
the enclosing process and fixture storage require separate accounting.

## Focused validation contract

The `block_v2::machine::program::host_evaluation::tests` filter contains five
tests intended for both supported machine layouts. They cover every current
operation variant, full and partial cubic rows, public bank boundaries, empty
programs, minimum and expanded padding, input-count error precedence, every
input-related rejection branch, and a valid/invalid/valid sequence using the
same immutable owner. They also check finalized row invariants and refusal of
malformed wire/hint geometry or invalid padding before this domain exists.
An exhaustive operation match makes future variants require test maintenance.

These tests support the source argument and do not replace cryptographic
review, independent AIR tests, or a complete workflow measurement. These tests
alone do not establish a measured speedup or cryptographic qualification.

## Guarded validation and host measurement, 2026-10-25 UTC

The coordinator ran this five-test filter successfully in both narrow and wide
layouts and completed terminal/source/executable audits. Combined research
correctness passed 90 tests, including the ten evaluation-admission tests and
six independent range audits, with five optional tests ignored.

Three matched alternating evaluation-only pairs retained the identical
8,012,253-wire, 2,097,152-padded-row program. The median host diagnostic changed
from 0.180931132 seconds with trace to 0.040281352 seconds without trace. The
complete compiler diagnostic, including fixture construction, planning and
destruction, changed from 2.299231888 to 2.155173436 seconds (6.27% lower).
Requested evaluation storage changed from 2,722,791,416 to 1,145,733,112 bytes,
exactly removing the 1,577,058,304-byte trace term. Existing limits remained.

Agent A independently verified these six receipts/logs and another six for the
combined range-reuse experiment, including their digests, 1,309 unchanged source
inputs, recorded executable digest, command selections, timing/geometry events,
alternating order, zero swap, and terminal cleanup. Detailed medians, resource
scope and evidence labels are in
[`ring_circuit_evaluation/BOUNDS.md`](../../../../../../research/pq-direct-spend/src/ring_circuit_evaluation/BOUNDS.md).
All measurements are CPU host/compiler diagnostics; no GPU proof, independent
proof verification, recursive graph, or complete RingCT workflow was measured.
Trace remains the default and this diagnostic remains opt-in.
