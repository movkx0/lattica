# Original-owner singleton native producer

This release Linux/x86_64 research child is selected only through
`owned-native-shake`. It does not change production acceptance or the default
transaction path. It selects an existing actual `ShakeSegmentAir::Single`
inside the original `ReservedShakeRequest`; batches and invalid indices are
refused before environment inspection. This first producer supports one native
4096-by-517 singleton component, not a complete request/transaction graph.

The pure source plan combines exact requirements for the existing A021
preparation, B037 native proof and report, the existing 64 MiB independent CPU
verifier, and this child's bookkeeping. The original shared-ledger admission is
split once into those exact categories. An equal-but-distinct request, changed
index, foreign ledger, mixed category, short claim or non-8-GiB device envelope
cannot substitute. The caller's original raw request remains borrowed and is
neither copied nor recharged.

Bookkeeping adds the actual source/claimed/prepared/verified owner types,
verification diagnostic/receipt and retirement types, ledger/requirements/error
headers and one exact 216-element public Vec. Existing embedded ownership
headers are deliberately counted again instead of relying on move elision or
overlap credits. This claim is separate from B's fixed 64 MiB `NativeProof`
ceiling; it cannot enlarge that proof ceiling. No raw proof is copied into a
second representation.

Before startup, `PendingRuntime` reserves its original device-profile startup
claim. The successful immutable-environment idle preflight remains held while
B's `NativeShakePhase::new` checks the original preparation/runtime/verifier
tokens and takes complete source-derived PCS/OpenCL claims in the same ledger.
The operation allowance is chosen only by that core planner from actual
remaining storage, capped at the original 24 GiB native allowance. A caller
cannot supply an allowance, AIR callback, policy, configuration or generator.
If any source/model/admission requirement is unavailable, creation refuses
before runtime startup and before proof execution. There is no fallback.

The attempted proof rechecks original request and token identities, starts the
exact pending runtime, borrows that same concrete runtime and token, records the
actual source using A021's exclusive preparation borrow, and invokes B's sole
fixed-kernel consumer with bytes borrowed directly from the original request.
Every error is reduced to an inline error while all original phase owners stay
live. The attempt cannot be retried inside this consuming research owner.

The inner operation scope must finish first, releasing core/runtime and
recording borrows. `Session::finish_reserved` then retires the exact original
engine on both success and failure while phase and preparation claims are
still held. Zero managed/live-tree bytes and lease release are required before
those claims can drop. Uncertain cleanup aborts, matching core retirement's
existing rule. A successful returned peak must be positive and at most 8 GiB;
it is the Engine managed peak, not total process device memory.

After retirement, the existing independent CPU verifier borrows B's immutable
artifact and original proof reservation. Its original verifier token preceded
all production. The sole public Vec is allocated only under the bookkeeping
claim, checked for exact capacity, and destroyed before that claim can release.
Verifier errors remain inline or are destroyed before returning. A successful
`VerifiedNativeSingleton` retains the opaque B proof/report owner, original
request/index and inline verification/retirement receipts. It exposes borrowed
artifact/report views only; there is no supplied-proof attachment or token
extraction. Future recursive graph integration must keep this owner intact.

Five CPU tests are authored for singleton selection, exact original category
splits, identity refusal, admission boundaries, moves and terminal retirement
conditions. One ignored GPU test is authored for two different original input
witnesses, fresh required GPU proofs, independent CPU verification, public
mutation rejection and exact terminal cleanup. The test serializes the actual
borrowed native report under its still-retained original Report claim. Its
component interval explicitly includes mutation checks and is not workflow
throughput. The exact coordinator guard sets
`LATTICA_OWNED_NATIVE_SHAKE_QUALIFICATION=1` and
`LATTICA_PROVING_POLICY=gpu-required` under its fixed startup environment;
the test requires both before constructing any owner. No test or proof has
been executed by Agent A.

Complete transaction coverage, recursive closure, artifact codec round trips,
seven-transaction N3/N4 screening, matched workflow repetitions and promotion
remain separate qualification work. This child reports no complete RingCT
workflow or speedup. The shared opening planner must explicitly support the
native device-tree profile before the core phase can pass predispatch admission;
changing the runtime to a host-tree fallback is not authorized by this child.
