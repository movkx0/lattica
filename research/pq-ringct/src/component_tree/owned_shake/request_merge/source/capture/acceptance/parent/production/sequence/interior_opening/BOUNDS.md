# One interior Leaf0 opening action

This source-only experiment is gated by test, owned-native-shake, release,
Linux and x86_64. Default Attempt construction stores None. It does not change
production transaction acceptance, cryptographic parameters or B051's
Result<Infallible, RefusedRequest> closure. No execution or speed claim follows
from this source review or its fixed synthetic fixtures.

The closed constructor admits the complete added caller first, validates the
original source/request/Ledger, then independently admits CpuEnvelope::source()
over all 18 heights plus RegisteredVerifier::classified_call_extra_bytes(). It
uses the already retained key.verifier directly. Its included 64 MiB proof cap
is not subtracted; released acceptance scratch supplies no credit. Both claims
exist before the original Attempt constructor can allocate PendingNative.
The shared baseline caller additionally charges all optional forwarding frames,
including its None/default path, via common_forwarding_host_bytes.

The sole action runs after State::check_next(Parent(0)) and take_children(0),
with the same owned left Leaf0 and right Leaf1 that compile_parent consumes.
The exact spans are Leaf0=(0,32,0), Leaf1=(32,32,0), Parent0=(0,64,1).
check_original validates both children. Saved Leaf0 acceptance and compilation
are checked against State's own Leaf0 records. Current opaque originals are at
Leaf1; only Leaf1 retirement is compared to that current retirement. No
historical/current retirement equivalence is inferred.

The action binds its original source, request, Ledger, retained output address,
key/spec/header, cap and height. It provides no raw getter, callback, clone or
reconstructed verifier. A separate sealed leaf adapter accepts only Leaf; the
existing root action continues to refuse Leaf. The actual retained verifier
checks the original numerically, then checks the first local permutation
opening changed by exactly Challenge::ONE. A private shape-preserving guard
restores the saved word before the result is classified, on every returned
outcome and on unwind. Only RegisteredVerificationFailure::RelationRejected
is negative credit; admission/configuration/allocation failures and unexpected
success are refusals. A second numerical check verifies the restored original.

The original is borrowed in place in State, never taken into a fallible probe
local. State's last field owns it, so remaining output/bank owners drop first.
Attempt::run carries its complete reservations through Component on success and
Failure on error. Their actual output/error fields die before the retained
original, which dies before the original Attempt caller. Fixed measurements
are borrowed under Component and never detached. Parent0 consumption is marked
only after successful parent acceptance and compiler-bank reclamation. The
same graph then completes all ten native and nine recursive proofs; any error
ends the attempt without fallback or retry.

The provisional scope occurs between stage receipts14 and15 (14/action/14).
The action is contained in component preparation, never added to preparation
again. Positive+mutation <= action; the external strict guard checks serialized
28 receipt/compiler/source-verification time + action <= preparation <=
complete-through-destruction == terminal <= external observation.

The only asserted mutation scope is
single-interior-parent0-left-leaf0-first-local-permutation-opening.
parent_boundary_mutation_checks_complete, interior_mutation_checks_complete,
whole_graph_mutation_checks_complete, raw/global mutation, transaction context,
artifact/disk roundtrip and complete RingCT workflow remain false. Restored
child continuation is not a parent-boundary mutation test. Physical-memory,
GPU, process/engine/device cleanup and performance require coordinator evidence.
