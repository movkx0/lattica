# Original report reservation reclamation

This is a consuming storage cleanup operation. It is not bank/source lineage,
proof success, backend retirement, dispatch authority or permission to proceed
following a failed phase. The production default and complete-request refusal
remain unchanged. A caller may reclaim bounded failure evidence for terminal
cleanup, but must still stop the bank path after any earlier execution failure.

## Original ownership and refusal

`PhaseReportOwner::reclaim_original(self, expected, caller, ledger)` checks:

1. The report reservation and the borrowed caller claim both belong to the
   supplied original ledger.
2. The report reservation exactly equals `PhaseReportOwner::requirements()`.
3. The caller claim contains at least
   `PhaseReportOwner::reclamation_caller_host_bytes()` host bytes in
   `Category::PhaseScratch`.
4. The retained payload identity equals `expected` in every field.

Every refusal occurs before moving a payload field, writing storage, freeing
backing or changing a reservation. It returns `(Error, Self)` containing the
entire unchanged owner, including its original payload, encoding and token.
The caller keeps its borrowed claim. A different category or device bytes
cannot substitute for the required host scratch. A caller claim may additionally
cover its enclosing operation; excess host bytes and other categories do not
convey source lineage or expand this helper's authority.

On success the method moves the actual boxed payload, actual fixed encoding and
actual private report reservation into `Retiring<Box<Payload>, Encoding>`.
`finish` destroys the payload, then the encoding Vec, then returns that same
reservation. It performs no reserve/admit/split/reunite, allocation, clone of an
Rc, counter update, replacement token construction or reconstruction from a
numeric receipt. Current and historical peak counters therefore remain exactly
unchanged until the caller later moves or drops the returned original. There
is no report data extraction API.

`Retiring` has its two storage fields before its reservation. Its fields are
Options so each actual destruction removes that field first. If a destructor
unwinds, the remaining encoding is destroyed before the original reservation
is released. The actual payload and encoding types have no user destructors;
the private generic helper supports focused destructor-probe tests without
altering their production layouts or permitting a public callback.

## Added caller storage before entry

The report's existing backing requirement and `PhaseReportOwner` layout are
unchanged. The new call storage must be part of the original bank admission
before native execution, and remain retained through the whole consuming call.
The helper returns a constant byte census derived from eight copies of every
following fixed-size source term:

- `PhaseReportOwner`, owning success/refusal Result, owning refusal tuple;
- `Retiring<Box<Payload>, Encoding>`, Box and Option<Box> owners, Encoding and
  Option<Encoding>, Vec header;
- Reservation, PhaseIdentity, Requirements, Bytes, Error and Option<Error>;
- references to receiver, caller reservation and ledger, one bool and eight
  usize scalar slots.

The eight complete sets conservatively cover the caller, wrapper, check,
destructure, retirement, destruction, return and refusal move slots even though
those full sets are not all simultaneously needed. This source requested-stack
census is not a compiler stack-frame/RSS measurement. The existing enclosing
stack/allocator/process allowances remain necessary. It charges no new copy
of the boxed payload or encoding allocation because neither backing is copied.
The helper allocates no failure String or variable-sized result.

The bank must add its own receiver, result, source/lineage checks, retained
PhaseIdentity, compiler remainder and eventual `Reservation::reunite` frames.
The helper's census cannot substitute for those separate terms. The bank's
claim must be established before constructing call arguments; the method's
check is defensive and does not retroactively admit caller storage. Any
reclamation refusal terminates that bank operation with its returned owner
retained until ordinary cleanup.

## Bank lineage and phase failure obligations

The bank authenticates the expected report and its original source separately;
matching public numeric identity and matching ledger are not bank lineage. A
successful reclamation only yields the same private token after the matching
storage died. The bank must not use it as proof that a phase succeeded or that
the next child/parent belongs to the required sequence. B owns that policy.

Reunification uses the existing inverse-split primitive
`Reservation::reunite`, after each real corresponding owner has been destroyed.
Do not release tokens and then re-admit matching numbers. Verifier retention
must likewise use the retaining-original API, and compiler remainder must stay
owned rather than being dropped. Those operations are outside this report
helper and are not implemented or authorized by this capsule.

## Focused test source and qualification status

Seven authored tests cover successful cleanup at a completely occupied
allowance, all identity fields, foreign supplied ledger, foreign caller,
one-byte-short/wrong-category/device-only caller claims, a defensive inexact
report token, exact retained payload/encoding on refusal, original current and
historical category counters, destruction order and unwind cleanup. Success
uses a storage-only receipt with bounded failure evidence, demonstrating that
reclamation is cleanup rather than proof-success authorization.

The destructor probes use real reservations. They inspect the full unchanged
ledger while each probe is destroyed, then verify terminal category cleanup.
No runtime, backend, session or proof owner is fabricated for these tests.
Tests and builds have not been executed by Agent A. Rustfmt/source review and
capsule hashing are the only A-side validation; coordinator execution and peer
review remain separate evidence. This change makes no workflow, speedup,
physical-fit or cryptographic-adoption claim.
