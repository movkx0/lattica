# Immutable final-root public recheck (B065)

This is a test-only component qualification source, compiled only for Linux
x86_64 release tests with `owned-native-shake`. It adds no production dispatcher,
acceptance authority, proof/key getter, detached continuation, protocol change or
default selection. B051's `Result<Infallible, RefusedRequest>` stays closed.

`PreissuedRootRecheck` is private to the existing sequence subtree. The driver
constructs it from the actual immutable ParentSourceBound and ledger before
constructing Attempt, therefore before pending native quota or native dispatch.
Its original reservation owns the complete 18-height CPU-verifier envelope,
`RegisteredVerifier::classified_call_extra_bytes()`, and a separate census of
complete action/Component/accepted-child/source/header/result/report/helper
frames. Verification storage stays in IndependentVerifier; additive callers stay
in PhaseScratch. Source/output/proof/key/original-runtime claims remain separate.
No budget, row/thread limit or security parameter changes.

The source header uses fixed arrays: four descriptor fields are committed with
the maintained contract domain, and profile/context/statement/input/output and
span metadata are copied into the exact 38-field header. A differential source
test compares it with the maintained `component_tree::header`; it is not a proof
test. The original reservation precedes source Spec/header/hash construction.
The fixed 64 KiB additive helper census also covers the existing width-eight
Poseidon constants: two four-by-eight external-round arrays and 22 internal
constants (688 scalar bytes on x86_64), their constructors/iterators and complete
permutation value. The full native verifier lifecycle and typed-call extras are
additional, not charged against that fixed helper allowance.

Only a consuming method on the private Component reaches numerical rechecking.
It checks that Component's actual Parent3 original and retirement, caller ledger,
completed counts and accepted root report, then moves its own root into the
existing AcceptedChild::Parent local. It accepts neither an external root nor an
external retirement owner. Source equality is not used to combine two attempts.
No AcceptedParent field, constructor, getter or visibility is changed.

A sealed RootPublicRecheckAction borrows that local child and the preissued
recheck. Its fields and construction remain private. Only the action and its
fixed diagnostic report are reexported through the existing module chain so an
immutable output adapter can call the action with its own borrowed key/proof.
Before any numerical verification, the action checks exact output-pointer,
source/request/ledger, source Spec, actual accepted height/cap/capacity, public
length and fixed source header. It cannot receive a substitute proof through a
public constructor or return any proof/key/runtime/acceptance object.

The actual original output is verified first with its own registered verifier.
Every index in `0..46` is then independently increased by Val::ONE in a fixed
copy freshly made from that original public vector. No retained public field or
proof body is changed or cloned. Each changed copy goes directly to the actual
`verify_classified` call; it is not rejected by a source-header comparison. Only
RelationRejected increments the negative count. Acceptance, admission,
configuration, allocation or a panic cannot earn a negative result. The local
copy is restored before returned-result classification; retained data also stay
unchanged on unwind. The same original proof/public are verified again after all
46 successful negative probes. These sequential calls share the fully preissued
scratch, while every caller/result/public-copy frame remains explicitly charged.

The 46 fields are profile `[0,8)`, context `[8,16)`, statement `[16,20)`, expected
input `[20,24)`, expected output `[24,28)`, kind 28, request 29, first 30, count 31,
total 32, level 33, descriptor `[34,38)`, initial endpoint `[38,42)` and final
endpoint `[42,46)`. Val::ONE produces a different canonical field value; this is
not a noncanonical-arithmetic test. Unmodified endpoint values are authenticated
by the first real positive proof verification before any endpoint probes.

On success and returned errors, the local action and child die before the
preissued verifier reservation and remaining Component fields. Its actual
originals/support/caller remain held through those locals. Typed numerical
diagnostics are consumed while the verifier claim is live; only a fixed report
or static ParentCompileError returns. The separately preadmitted driver caller
backs that returned report after Component consumption. Its provisional timing
diagnostic is consumed inside exercise; no RootPublicRecheckReport survives the
driver caller. All source/closure/group/request/caller owners are then destroyed.
Only successful exercise return plus zero current totals in every category can
emit the final root-public-complete marker. Process/engine/device cleanup remains
a separate coordinator audit, explicitly false in the source marker.

Two separately ignored selectors are added under the existing qualification
prefix:

- `cpu_original_hashx_sequence_root_public_capacity` requires the ordinary source
  guard plus `LATTICA_OWNED_HASHX_ROOT_PUBLIC_SOURCE_QUALIFICATION=1`. It adds the
  actual recheck claim before the full original quota projection, rejects wrong
  request/ledger projection and destroys everything. It performs zero proofs,
  numerical root verifications or mutations; `component_success=false`.
- `gpu_original_hashx_sequence_root_public_recheck` requires the ordinary
  component GPU guard plus `LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION=1` and
  the coordinator's immutable source/binary/environment/process/exclusive-device
  guard. It builds the actual ten native/five leaf/four parent component,
  reclaims all nine compilers, then consumes that Component in the numerical
  root recheck. All 28 actual stage reports remain required. No fallback exists.

No coordinator selector is enabled by this capsule. The original capacity guard
does not qualify the new root-capacity case; it needs an exact separate parser
and another current-source quota run. The normal component, preissue and B064
returned-refusal modes do not acquire a root-recheck claim or run its probes.
Their complete enclosing driver frame census nevertheless changes, requiring
current-source checks before reusing earlier capacity evidence.

The narrow completed coverage is final-root public binding: 46 numerical
rejections and two unchanged positives. It does not establish proof-body
corruption detection, interior-child/order/boundary constraint coverage,
transaction-context authentication, artifact round trips or full RingCT closure.
All global mutation/artifact/workflow flags stay false; raw-proof and interior
mutation flags are explicitly false. Source/header/classifier/quota tests are
authored evidence only until executed and never count as actual root mutations.
This capsule has only been parsed with rustfmt and source-reviewed; no build,
GPU execution, physical fit, measured performance or adoption follows.
