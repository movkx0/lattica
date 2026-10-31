# Native SHAKE preparation census

This data-only module describes the existing singleton lane AIR (crypto kind 2)
and homogeneous batch lane AIR (kind 3). It does not reserve bytes, open a device,
read the environment, obtain entropy, evaluate an AIR, construct configuration,
or authorize dispatch. It adds no cache, protocol change or performance claim.
Source/layout assumptions apply to the pinned Linux x86_64 Rust 1.96 release
build with `gpu-bounded-info`, `stream` and the unchanged cubic profile. The
coordinator applies the parent hooks and runs all builds/tests/GPU work.

`ShakePreparationPlan::{singleton,batch}(ShakeTraceSpec)` returns immutable
geometry, host preparation, trace-device, owned-configuration and original
planner censuses. Copies of these numeric facts are never ownership tokens.
`host().required_host_bytes()` already includes configuration and planner
claims; do not add those two claims again. Its whole value must be reserved on
the caller's original shared worker ledger before preparation begins. No new
ledger, receipt-derived allowance or numeric constructor can substitute for it.

The exact geometry preserves native segmentation: one singleton covers one
permutation; a batch has a positive power-of-two permutation count and lies
entirely in complete absorption blocks or complete squeezing blocks. Padding,
the last absorption permutation and partial output transitions remain singleton.
Zero output is accepted exactly as in the existing descriptor and core kernel
planner. Checked arithmetic rejects invalid endpoints, lengths above u32 and
rows above the unchanged campaign cap of 2^20. Supported geometry alone is not
device-phase feasibility; an enclosing planner must reject all other memory
limits before starting any proof.

The trace census names all five simultaneous device buffers. For P permutations
and input length I, trace rows are 4096P and width is 517 or 518. The buffers are
`rows * width * 8`, `216 * 8`, `max(I,1) * 8`, `(133P+216) * 8` and `12 * 8`
bytes for trace, public, raw source, private scratch and geometry. Source and
scratch are scrubbed and drained before their owners drop. Source, scratch and
geometry retire after generation; public retires after checked readback. The
trace remains owned by the later prover. No startup, random-stream, transcript,
periodic device expansion or PCS buffers are included in this five-buffer sum.

The compiler partition is the existing 192 MiB symbolic allowance plus the
unchanged periodic staging formula: 42 columns of 128 Goldilocks values, three
overlapping scalar representations, two outer vector arrays, captured lengths,
and 84 metadata words. This totals 132,048 periodic bytes. The entire symbolic
and periodic partition must remain reserved through normalization and PCS:
recorded graphs, compiled programs and source tables outlive their construction.
`host().prepared_partition_bytes()` reports the exact partition that `Prepared`
subtracts from its operation allowance. It must not be lent to a later phase.

The AIRs themselves allocate four vectors outside the recorder's quota: cloned
public variables (216), periodic expressions (42), counter expressions (5), and
four four-expression update tuples. Their exact element types are taken from
`symbolic::Builder`. Expression-node backing is already in the recorder quota;
these vector arrays are additive. Both AIRs use fixed inline Poseidon constants,
and borrowed periodic-column filling creates no owned schedule table. The
source census also names public readback/conversion, 2048 upload staging words,
12 geometry words, the five matrix allocation wrappers and explicit owners.
It describes source-owned payload, not compiler-selected stack frames or RSS.

Configuration accounting applies specifically to coordinator R004's
`profile::make_gpu_proving_config_from_owned_seeds`, called with three fresh
independent OS-generated seeds under an original reservation. The constructor
keeps the exact existing profile, activation checks, host-budget checks and
constructor flags. The legacy `Prepared::config`/`make_gpu_proving_config` path
uses `rand::rng()` and leaves a TLS owner after proof retirement; that path is
outside this census. No TLS release is inferred from dropping a returned RNG
handle. The producer must hold both original seed and configuration owners
through destruction and must not expose deterministic proof seed selection.

The owned configuration includes seven permutation vector families, three CPU
MMCS Arcs, five shared RNG owners, six initially empty DFT-cache Arcs, resident
state and failure flag, four device RNG wrapper owners, the maintained opening
runtime host partition, seed transfers, expanded ChaCha20 RNGs and configuration
headers. The opening runtime partition overlaps parts of the enclosing runtime
in actual execution, but this census takes no overlap credit. These are host
claims; stream/transcript device buffers still belong to the device-phase plan.
No arbitrary driver or compiler allowance is used as configuration accounting.

Worker-policy file parsing is excluded only under the original A013 runtime
preflight: its bounded environment captures and refuses both
`LATTICA_V2_WORKER_BUDGET` and `LATTICA_WALLET_WORKER_BUDGET`, then rechecks the
sealed environment before and after activation and before reserved operations.
The guarded process cannot mutate that environment or install a worker policy.
This pure module does not itself establish absence. A caller outside the exact
original runtime owner must establish a separate trustworthy bound or refuse.

The existing `reserve_wallet_proof_capacity` uses `WalletDevicePlan::new` and
the legacy JSON report. A separate planner claim therefore remains necessary
before these calls, even though the symbolic quota is already held. The minimal
crate-visible reexport exposes only maintained `PlannerResources` metadata.
The census charges four times that bounded helper for the ordinary seven
push-grown vectors and temporary planners. Rust 1.96 doubles capacity from four;
all seven fixed maximum lengths are at least four, so their cumulative backing
requests are less than four times their exact maximum lengths. Applying the
factor to inline/temporary/failure storage also overcharges those owners.

The JSON census separately covers the original `Plan::report`: record maxima
76/5/15/43/50/11/10 with 3/4/7/9/8/7/6 fields, plus 26 root fields. Each map node
is charged at the larger Rust 1.96 internal BTree node size with conservative
padding; entries plus objects bounds node allocations. Every field key and
scalar value is overcharged as a 64-byte string, exceeding all fixed names and
schema labels. Exact root array backing and headers are included, plus eleven
nested three-value arrays and headers for commitment `allocation_bytes`.
Those nested arrays are charged explicitly, without map/string overlap credit.
Two complete trees
cover the existing `json!(collected_vec)` serialization copy while its source
is still live. Display streams this value without a whole JSON String. The
report sink's buffering is an enclosing obligation. This does not claim that
the original path has switched to the newer streaming planner.

Before dispatch, the combined owner still needs actual raw input capacity,
original runtime/startup ownership, physical maximum-allocation/phase checks,
native kernel/Program wrapper storage, Run/capability/report ownership, compiled
GPU program storage, all later PCS/opening/FRI/randomness payload, retained proof
and independent-verifier scratch. SHAKE trace and Poseidon-row kernels have nine
arguments; A013's raw-operation kernel wrapper bound cannot be reused for them.
The device startup charge remains 64 MiB + 752 bytes, with mapped staging also
charged to host, and the 4 GiB context reserve remains separate. The full fixed
8 GiB managed / 32 GiB worker host / 24 GiB native / 47 GiB process / zero-swap
envelope and existing thread/row limits are unchanged.

Five CPU-only tests are authored for transition coverage, zero/exact-rate and
row/overflow boundaries, additive owner accounting, report-literal bounds and
explicit commitment-array storage in the two JSON copies.
They do not construct a configuration or touch the device. Coordinator execution
and guarded allocation/profile tests in the final producer remain required.
