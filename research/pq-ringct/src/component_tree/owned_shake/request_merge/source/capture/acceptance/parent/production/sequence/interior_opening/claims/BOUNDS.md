# Interior accepted-child opening caller and verifier claims

This census targets the immutable B070 source/type contract at
`/tmp/ringct-b-interior-opening-source-contract-20261025-070`. The selected
research action belongs to the original private HashX `Attempt`: it probes
the left Leaf0 returned by `take_children(0)`, before the same Parent0 compiler
consumes it. These claims do not enable a production path or qualify a complete
transaction, parent-boundary mutation, artifact round trip, or speedup.

## Independent all-height verifier claim

`verifier_requirement` accepts only the private `CpuEnvelope::source()` shape:
all 18 supported heights and a nonzero maximum. Its host claim is exactly the
checked sum of that complete maximum and
`RegisteredVerifier::classified_call_extra_bytes()`. It belongs solely to
`IndependentVerifier`; its device charge is zero. It subtracts neither the
included 64 MiB proof cap nor destroyed acceptance-verifier scratch. All source,
retained output/key/verifier metadata, compiler, native, worker and device
claims remain independently additive.

B070 calls `key.verifier.verify_classified` directly. It does not call the
`NodeKey` forwarding method, so there is no uncharged `NodeKey` forwarding
increment. Original positive, changed opening, and restored positive calls are
sequential. The changed proof guard restores its saved word before the typed
outcome is classified; the outcome and its sole diagnostic are consumed before
the second positive call. Only `RelationRejected` earns negative-probe credit.

## Complete selected caller

`caller_requirement` is independent host-only `PhaseScratch`. It adds the full
common forwarding census and complete action/owner/borrow/result/error/drop
layouts, using checked arithmetic throughout. The source layouts cover:

- The whole preissue and retained owner; their optional, returned and borrowed
  forms; plan and measurement reports; grown State, Attempt, Component and
  Failure; both success and returned-error ownership transfers.
- The exact selected and sibling accepted children, saved Leaf0 and Leaf1
  acceptance records, compilation summaries, current Leaf1 retirement,
  authenticated output/key/proof borrows and fixed cap/address identity.
- Mutation guard/result/shared proof borrow/saved extension-field word,
  classified verifier outcome and error handling, all timers and checked
  counters, header/spec/context/descriptor hashing and source validation.
- All-height shape helpers, opaque retirement return layouts inferred from
  maintained function items, fixed formatting/iteration/arithmetic frames and
  ordinary destruction. Function items are sized but never invoked.

Every listed layout, census backing array and control frame is counted eight
times. This explicitly covers forwarding, temporaries and return/drop overlap
without relying on inlining, move elision, exclusive branches or stack-slot
reuse. Fixed source helpers include the maintained bounded Poseidon constants,
four source-parent recursion levels, diagnostic/formatting/error controls and
the 4096-byte scope output allowance. They are independently additive even
where the verifier's existing call plan also includes bounded diagnostics.
This is a source census, not a measurement of process or GPU memory.

## Default paths and pre-owner frames

The B070 `sequence::claims::attempt_requirement` adds
`common_forwarding_host_bytes()` under the same release/Linux/x86_64/test/
owned-native gate as the new fields and hooks. The common helper does not
inspect a live State, require an existing preissue, or admit any reservation.
Its complete optional-owner, Result, borrowed-report, child, error, return,
conversion and ordinary-drop frames are charged even when State's optional
interior owner is `None`. Existing enclosing `size_of` measurements also grow;
no baseline bytes or categories are removed.

The selected caller adds that common amount again. The complete outer driver
census separately covers pre-owner constructor frames and is admitted before
guard/source construction and the closed interior Attempt constructor. Thus
neither shared default paths nor the interval before the new preissued caller
exists depends on a future reservation for storage credit.

## Original lifetime and destruction

The closed constructor reserves the complete extra caller, derives and reserves
the all-height verifier requirement, then constructs the ordinary Attempt.
Both extra claims exist before `PendingNative` assigns PCS capacity. The whole
owner is installed in State; the Parent0 probe borrows it in place and never
takes it into a local that could be released before an error destroys children.

State declares the interior original last. Success and returned failure move
the whole retained original to Component or Failure before destroying remaining
State payloads. Component declares root/originals/support/reports before that
original; Failure declares its compiler/production cause before it. Both declare
the enclosing caller last. The retained owner declares measurement and CPU
shape before its verifier and caller reservations. Workload payloads and final
borrowed diagnostics therefore finish before either extra claim is released.
No ownership move creates a fresh admission or recycles released credit.

## Focused checks and remaining qualification

Five authored tests cover the exact all-height-plus-classified increment;
missing-height, zero and overflow refusal; category/default forwarding coverage;
exact and one-byte-short combined admission with ledger identity, atomic refusal
and zero release; and checked arithmetic overflow. Agent A did not compile,
format, execute these tests, dispatch a proof or integrate this capsule.

The coordinator must check exact B070 and C field-contract pins, run the focused
tests and unchanged default-path regressions, and audit terminal cleanup under
the original process/device guard. Source accounting and CPU quota projections
do not establish actual proof rejection, physical fit, asynchronous failure
cleanup, whole-graph security or complete-workflow performance.
