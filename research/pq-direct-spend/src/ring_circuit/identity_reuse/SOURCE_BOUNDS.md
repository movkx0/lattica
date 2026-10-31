# Direct-ring identity receipt transfer v1

This isolated research profile reuses only a GPU-computed public program
identity. It neither retains a prepared program nor reuses a witness, proof,
preprocessing cap, verifier, GPU allocation, runtime or session. Production
acceptance and default experiment selection are unchanged. The compile feature
is `gpu-identity-reuse-experiment`; its Cargo hook belongs to the coordinator.

The seven-statement baseline showed metadata/PCS backing alone of
1,073,747,616 host bytes, program source above 656 million host bytes, and
witness instructions above 1.49 billion device bytes. Complete idle state
therefore cannot fit either 512 MiB idle limit and is rejected. The opaque
`RegisteredIdentityReceipt` is 112 inline bytes on the qualified target, has
no heap or device allocation and is exposed only after successful GPU
registration. The complete source-derived transfer/move/report/hasher bound
uses actual Rust sizes, including overlapping receipt copies; its entire
charge fits the existing 1 MiB receipt sublimit within 64 MiB metadata.

The conservative sum includes six bare Transfer move slots, eight full owning
Option<Transfer> slots, and four full Result<Transfer, Error> slots across the
constructor, workflow, verifier forwarding, independent registration and finish
chain. It separately includes eight bare ReuseReport slots, eight full optional
reports and four full report-result slots. Full Rust enum sizes include both
payload and discriminant; no niche optimization or generic orchestration spare
is assumed. Four standalone receipt slots and four optional receipt slots cover
clone/core-return/drop temporaries beyond the receipt already inline in each
Transfer owner. Four complete expected-key results, four receipt-reference
results, and four device-digest results cover helper forwarding returns. These
are additive bounds for all named nonrecursive source sites, including moves
that a compiler may elide; overlap is deliberately not subtracted.
The completion policy separately adds four telemetry payload slots, four full
optional telemetry slots, four option-reference slots and four full telemetry
result slots. This covers source/fresh arguments and forwarding through the
private generic policy; its production payload is PublicHashExecution.

The same storage is also charged inside the existing 1 MiB registered caller
envelope, separately from its 32 KiB orchestration slice. These independent
limits are intersected, never added. Both prover and verifier caller census
include the new charge before GPU startup. The transfer constructor runs the
complete prover caller admission before constructing the owner. Fixed enclosing
screen owners are source-bounded before path/fixture allocation. The 1 MiB
caller envelope remains subtracted from codec and verifier-compiler allowances;
single-case compiler overlap is independently checked against 32 GiB. New
forwarding self/results are counted in both default caller paths. There is no
new complete shared-ledger receipt: direct-ring reports retain that limitation.

A non-Clone transfer binds the independently expected context, statement
binding and artifact/profile version. Its captured actual program descriptor
binds manifest SHA3-256, active/padded rows, wires and witness input count.
Those are supplemental checks: the core SHA3-512 fingerprint of the complete
canonical identity stream, including protocol parameters, program constraints
and actual newly computed preprocessing-cap roots, remains mandatory on every
lookup. A matching receipt skips the repeated GPU protocol-identity hash. The
core's additional SHA3-512 collision-resistance assumption remains explicit.
No serialized receipt, numeric ID or artifact claim can mint authority.

Receipt capture occurs only after successful cold registration. It becomes
eligible only after the consuming fresh proof completes and the actual original
GPU session has drained/closed. A refused prover clears its receipt and marks
the transfer permanently refused. Verification consumes the owner, reconstructs
the program from expected public inputs, checks the actual reconstructed
manifest/geometry before session startup, and creates a fresh GPU session/cap.
A domain-separated SHA3-512 device binding covers actual UUID, OpenCL index,
name, PCI identity, driver and memory limits with length/tagged bounded fields.
A mismatch or non-ready phase refuses use; the transfer is one-shot.

The verifier borrows the receipt only for registration. A hit must be reported
by the real RegisteredProgram and yield the same validated ID. A core miss may
perform the original hash, but this profile rejects it and never reports a warm
success or retries. The original receipt and the registration's internal copy
are destroyed before independent CPU verification. All paths preserve actual
session retirement before returning an error/success.

Successful receipt completion requires fresh public-hash execution to be null:
every present observation is rejected, including metadata equal to the source.
The new engine begins without telemetry; matching kernel/capability fields do
not make a fresh observation stale. The absence policy runs before producing
any reuse report. Cached provenance is separate in `identity_reuse` and
names the prior real public-hash observation. Baseline JSON still emits its
ordinary object and omits identity_reuse. Native stage receipts retain actual
device counts/timing and must not invent a skipped identity dispatch. New
verification/workflow schemas explicitly mark reused public preprocessing;
fresh cap, fresh proof and CPU proof acceptance retain separate boundaries.

The first exact component screen uses only case 0 from the existing seven-ring
fixture recipe, with context 0x73, fused-ternary-ranges-v1 and unchanged compiler,
row/thread/cryptographic parameters. Baseline and receipt-v1 use the same binary,
fixture, fresh proof, artifact round trip, two independent public mutations and
two retired GPU sessions. This is not a different-witness cache test, a complete
faithful RingCT graph, N3/N4, asynchronous-failure qualification, seven-case
candidate diversity qualification, security review, or a 2x redesign result.
GPU work/builds/tests/auditor execution remain coordinator-only.
