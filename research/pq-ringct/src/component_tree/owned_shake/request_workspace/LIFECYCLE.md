# Correlated compiler workspace: implementation draft

This is an interface proposal, not an implemented admission or
execution path. It changes no default, proof predicate, resource limit, source
partition, or production acceptance. The companion `request_merge` module
implements only a bounded source-metadata owner and enforced refusal; none of
the compiler transitions proposed here is implemented. A036-r2 is a necessary native phase screen. Even
`admitted=10 refused=0 phase_feasibility=true` does not admit the workspace or
the complete request described here.

The first scope is the original active-policy HashX request: input 16,416 bytes,
output 137 bytes, ten native segments with counts `[16,16,16,16,16,16,16,8,1,1]`,
and five consecutive PairedV1 groups. A035 supplies the exact immutable request
owner. B050 supplies the independently admitted source shape for each group.
Each bound must match that original request, ledger, layout, ordinal, span,
contract, endpoint context, and fixed compiler profile. HashAlpha batch 2/4
tails and complete transaction context authentication remain separate work.

## Original components and their lifetimes

The request planner computes all components before the first native attempt.
It preserves the 32 GiB worker host, 8 GiB managed device, 4 GiB context reserve,
24 GiB native allowance, host trees inside the worker allowance, process,
thread, row, and zero-swap constraints. It must recalculate the first native
PCS capacity after every native, leaf, parent, report, and metadata preclaim;
the larger A036 source-screen capacity cannot be reused as dispatch authority.

| Component | Before native proving | Across completed groups |
| --- | --- | --- |
| Compiler program and enclosing owners | One source-derived maximum across all admitted phases, retaining the existing 2 GiB program ceiling | Original token transfers only after its complete prior program payload is destroyed |
| Compiler inputs, public values, input headers | One maximum of complete existing input requirements | Transfer after witness/public payload destruction; no observed-capacity shrink |
| Symbolic workspace, retained symbolic graph, helper buffers | One maximum from the complete closed compiler source census | Remains charged during compilation, verification, errors, and cleanup |
| Native child independent verification | Two original 64 MiB components for a pair | Each returns from its actual borrowed verifier; both reunite before succession |
| Compiler report | Five separately preissued report owners | Each completed report stays attached to its own retained group result |
| Recursive proof, registered key, outer verifier scratch, recheck/report owners | Separate original claims for every simultaneously retained node and phase | Follow actual ownership; never borrowed from the reusable compiler claim |
| Request identity, complete result/tuple/array/carry owners, diagnostics, serialization | Exact checked source census before source or PCS construction | Remains charged until the final owner or terminal failure is destroyed |

Category-wise maxima are valid only for components whose preceding payload is
actually destroyed before the successor starts. Simultaneous owners are summed.
In particular, keeping all five `OwnedCompiledShake` values alive cannot use a
single program/input reservation. Copyable `Requirements`, timings, or observed
peaks do not establish disjoint lifetimes. Preserve full source-derived claims;
do not enlarge the original PCS assignment after another owner is released.

The two compiler verifier components are separate from A's shared native
production verifier workspace. Sharing those as well would require an explicit
typed transfer and a revised complete census; it is not implicit here.

A's scratch lifecycle produces all ten original native proofs first. The
compiler accepts those only through the source-preissued segment attachment
that yields `ReservedNativeChild`; it accepts no detached proof or verification
receipt. A's `NativeSegmentCompletion` correlates the actual verified segment,
retired core owners, original preparation and B049 verifier component. Its
successor transition is separate from the compiler lifecycle below. Neither
transition may use a summary match as original-attempt provenance.

## Proposed opaque state transitions

These names specify the future API contract; none is a callable API today.
Constructors and fields remain private to the closed request implementation.

```text
RequestCompilerPlan
  -- exact source/ledger/whole-request admission before native0 -->
PreissuedCompilerRequest + five ordered FutureCompilerGroup owners

PreissuedCompilerRequest + group0 + exact verified native children
  -- bounded compilation --> LiveCompiledGroup

LiveCompiledGroup
  -- issue its one original outer-input ticket -->
BoundOuterCompilerInput (borrows the genuine compiled payload)
  -- actual fresh outer production, CPU verification, runtime retirement -->
CompletedCompilerGroup (opaque correlated output + originals + ticket)

LiveCompiledGroup + CompletedCompilerGroup
  -- destroy compiler payload, reunite original components -->
RetainedGroupResult + BetweenCompilerGroups

BetweenCompilerGroups + exact preissued successor + exact next children
  -- bounded compilation --> next LiveCompiledGroup
```

`PreissuedCompilerRequest` owns a private request-attempt identity allocated
and charged before native construction. This identity is distinct even for two
otherwise identical requests or two workspaces borrowing the same request.
Private equality must establish the actual original identity, for example an
opaque allocation identity, rather than a caller-supplied number or hash alone.
Every identity header, reference, allocation, return variant, and error owner
is part of the complete caller census. No public Clone/Deserialize/raw-token
constructor is provided for a group or completion ticket.

Each `FutureCompilerGroup` fixes ordinal, source bound, contract, context, and
span before native dispatch. The request owns one such capability per group.
It cannot mint another after an attempt. A private group state moves once from
unattempted to compiling, then compiled, then outer-input-issued. Any attempted
compilation or outer production failure makes that request terminal. Invalid
pre-dispatch identity handoffs may return their intact original owners, but
must not consume the attempt or invent a later admission.

The input ticket binds the private request-attempt identity and exact group to
the actual borrowed `OwnedCompiledShake` passed into the consuming producer.
The producer owns that ticket while its input borrow is live. It can return a
`CompletedCompilerGroup` only after actual independent output verification and
exact original runtime retirement. After the producer returns, its compiled
borrow ends, so the caller can safely consume `LiveCompiledGroup`. This avoids
a self-referential owner and avoids moving a compiled object while borrowed.

The completed owner retains the produced key/proof, original sealed runtime
and PCS ownership, and original input ticket together. It has no general
`into_parts` method before compiler retirement. The current
`ContinuedOuter::into_parts` and a matching `Summary` are insufficient evidence
for this new transition: those can separate correlation, and a summary does
not identify the original compiler attempt. A separate narrow producer entry
must create the correlated owner; existing B047/B048 entries stay unchanged.

Retirement checks the original attempt identity, exact source and group,
successful output state, original ledger/categories, and actual runtime
retirement. It consumes the live compiler, then explicitly destroys the
program/public/witness payload while the entire program/input/scratch claim is
still live. The output key's complete metadata/referents must remain charged by
its separate retained-key owner even if an Arc shares program backing. Compiler
quota cannot be reclaimed while an uncharged alias survives. The compiler
report moves to its own preissued result owner.

Only then can program, input, temporary, and both verifier originals be reunited
using the category-preserving ledger operation. Complete snapshots must stay
unchanged across the transfer. The result fixes the only allowed next ordinal
and exact adjacent native/unit span. Final-group retirement yields an exhausted
compiler owner, not another group capability or a request-acceptance receipt.

## Required child-verifier extension

A's `ReservedNativeChild` needs a separate closed retaining verification entry,
preserving the existing entry as default. It must verify original request,
index, source key, native shape and proof-backing ownership before invoking
B049's real `verify_retaining_original`. Success returns the exact component
after configuration/verifier temporaries die. The request adds B049's full
caller-frame helper and all adapter/result/diagnostic frames before native
construction. No arbitrary proof/AIR/verifier callback is accepted.

A failure conveys cleanup ownership only. The typed workspace records a bounded
failure while its report and necessary scratch still exist, destroys all live
payloads before their claims, and offers no successor method. If actual runtime
cleanup is uncertain, follow the existing poisoned/abort boundary; do not issue
a success ticket or release backing on an observed numeric receipt alone.

## Parent integration and qualification

The source closure and separate resource interface in
`../request_merge/RESOURCE_INTERFACE.md` are required before a complete request
can dispatch. Leaf source bounds or a compiler-memory saving cannot substitute
for bounded parent compilation and request/transaction/final height closure.

Focused qualification should cover foreign attempt identities despite equal
metadata; skipped/reordered/duplicated groups; wrong source/context; reused
completion tickets; shortage in each original category; native verifier error;
compiler/outer/retirement failure; report preservation; and zero terminal quota.
A live-payload drop observer should establish destruction before original
quota transfer. Genuine proof fixtures must compare results against the current
singleton/paired semantics, retain actual receipts, reject boundary mutations,
and test distinct witnesses without reusing proofs. All execution remains in
the coordinator's serialized slot.
