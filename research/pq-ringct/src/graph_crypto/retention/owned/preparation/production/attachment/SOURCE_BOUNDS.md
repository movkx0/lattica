# Original verified singleton as compiler child

The sole production conversion consumes `VerifiedNativeSingleton` intact into
a private `ReservedNativeChild` payload variant. The original core proof/report
owners, their original reservations, request identity, independent verification
and runtime retirement receipts remain inside that variant. There is no raw
artifact, key or token attachment API and no second `NativeProof` claim.

The adapter first validates the original singleton request/index without
constructing a key. It then reserves an exact, additive `PhaseScratch` host
claim in the same ledger. Only after that admission can the existing source
shape and cache-key helpers run. The claim includes the source/pending/metadata
and final child headers, both original and destination producer headers, enum
and wrapper headers, descriptor Vec, two SHA3 states including first-use source
fingerprinting, fixed digest/descriptor arrays, bounded source-error Strings,
and one exact public Vec for final verification. Device bytes are zero. No
move-elision, output-storage overlap or smaller observed capacity is credited.

Attachment rechecks the actual immutable producer identity and audits its
existing nested proof capacities against the source-derived retention shape.
The private payload stores the complete produced owner first and the adapter
reservation last. Compiler moves and destruction preserve that ordering.
Errors are reduced to inline enums while all relevant owners remain live.

`ReservedNativeChild::shake_artifact` returns only a borrowed `LaneShakeProof`.
The source planner and both closed constructors already require SHAKE; no
transient `SegmentArtifact` wrapper or proof clone is needed. CPU fixture
construction remains separately gated under the existing release test cfg.
Its original proof reservation and independent verification semantics remain
unchanged. The compiler's exact request/index checks remain unchanged.

Final compiler admission still independently verifies every native child under
the supplied original 64 MiB verifier claim. A produced child's cache key is
recomputed under the retained adapter claim and its exact public Vec also lives
under that claim. Verification borrows the original opaque core proof token;
it does not extract it. Compiler inputs own all copied values before the full
child owner drops, preserving the existing overlap accounting.

Five pure CPU tests cover additive categories, source refusal, exact identities,
pre-key admission boundaries, and metadata moves/cleanup. The existing guarded
two-witness singleton qualification is extended to consume each produced owner
into a child, assert unchanged NativeProof/Report usage, and perform final
independent re-verification before terminal cleanup. No Agent A execution.

This is runtime-free graph attachment, not complete graph dispatch. The native
device-tree profile and the existing outer host-tree profile need an explicitly
reviewed transition after exact native runtime retirement before a combined
fresh native-to-outer qualification. This adapter does not mutate environment,
authorize that transition, establish recursive closure, or claim throughput.
