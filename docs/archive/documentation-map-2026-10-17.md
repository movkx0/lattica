# Lattica documentation

[Bounded execution engine and GPU hashing](bounded-execution-engine-2026-10-17.md): completed
four-transaction/two-level recursive proofs, five matched retention off/on pairs
(**19.627 / 17.642 minutes median**), root-only CPU replay after shared-fixture
pruning, measured resources and the remaining grouped/full-block/security gates.
The [grouped integration record](../evidence/block-v2-grouped-integration-2026-10-01.json)
records the completed eight-wallet/seven-proof CPU chain: **33.133 minutes**,
a **1,914,091-byte** root and fresh CPU replay after pruning 14 inner artifacts.
The [comparison-control record](../evidence/block-v2-eight-comparison-2026-10-01.json)
documents the validated single-wallet control and exact shared public inputs.
The subsequent [same-eight CPU pilot](../evidence/block-v2-eight-matched-pilot-2026-10-01.json)
completed in **69.941 minutes single / 33.552 minutes grouped**: a **52.028%**
reduction in one pair, but a slower grouped final merge (**287.332 vs 264.760 s**).
Both roots passed recorded CPU audits after local inner-artifact pruning.
Repeated comparison, post-shared-fixture-pruning replay, full-depth performance
and security gates remain open.

The separate [quotient-fusion ledger](../evidence/block-v2-quotient-fusion-2026-10-01.json)
records component validation, **204 passing CPU library tests**, and exact
full-size reproduction of all three original grouped preprocessing caps. The fused
eight-wallet root passed preserved CPU verification after local inner pruning:
**28.983 minutes**, **1,913,701 bytes**, with a **252.026-second** final merge.
The [same-binary matched comparison](../evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
completed in **32.198 minutes off / 28.983 minutes on**: **9.983%** lower total
time in one pair, with a **270.047 / 252.026-second** final merge. Both roots
passed additional CPU-only replay; memory and retained geometry did not improve.
Fusion stays opt-in and is not repeat-, depth-six- or production-qualified.
The [original five-pair single/grouped series](../evidence/block-v2-eight-repeated-series-2026-10-01.json)
has started separately with its original non-fused binaries. Final shared and
registration-fixture pruning/replay remains required.
See its [controls and reproduction gates](bounded-execution-engine-2026-10-17.md#quotient-transform-fusion-experimental-implementation-and-gates).

This index is the canonical map of the repository documentation. Documents are grouped by authority so that current requirements are not confused with research notes or historical audit snapshots.

## Current project guides

- [External audit handoff](../AUDITORS.md) — reviewed surface, trust model, reproduction, and exclusions.
- [Audit-readiness status](../audit-readiness-status.md) — frozen baseline and current development posture.
- [Incremental recursive block proving v2](block-proving-v2-2026-10-17.md) — authoritative architecture and milestones; **candidate/inactive**. A four-transaction/two-level recursive proof is demonstrated; profiling and bounded preprocessing reuse support further performance work. The 64-transaction feasibility, security and live-network gates remain open.
- [Remediation status](../remediation-status.md) — disposition of implementation findings.
- [Soundness budget](../soundness-budget.md) — frozen v1 proof-family parameter accounting; v2 requires separate complete-tree analysis.
- [Wire format](../wire-format.md) — normative legacy prover/node byte encodings and an explicitly inactive v2 boundary.
- [Protocol v1 decisions](../protocol-v1-decisions.md) — resolved protocol-level design choices.
- [Post-quantum zero-knowledge stack](../../POST_QUANTUM_ZERO_KNOWLEDGE_STACK.md) — explanatory cryptographic overview.

## Protocol and implementation assurance

- [Plonky3 audit scope](../audit-scope-p3.md)
- [Join-split constraint audit](../joinsplit-constraint-audit.md)
- [HTLC constraint audit](../htlc-constraint-audit.md)
- [Batch constraint audit](../batch-constraint-audit.md)
- [Soundness budget](../soundness-budget.md)
- [Hash-function analysis](../hash-function-analysis.md)
- [Implementation audit](../lattica-implementation-audit.md)
- [Full-node integration requirements](../full-node-security-integration.md)

## Apple hardware acceleration

`main` is the canonical integration branch for committed Apple Silicon/Metal
code, benchmark tools and shared prover/pool changes. Start from the
[current-source Mac recipe](../../lattica-prover-p3/scripts/apple-current-benchmark-README.txt).
The `codex/mac-metal` and `v3` histories are retained in the merge; their measured
results keep their original source and binary hashes.

The pending Mac source was captured in checkpoint `1604392` and integrated into
`main` at `9733a24`. All six previously omitted Rust/Metal modules, the changed
source/configuration files, benchmark helpers and Apple reports are now tracked.
The [integration report](../apple-main-integration-2026-10-06.html) records focused
correctness checks and a minimal two-job, 18-thread comparison of the combined code.
The shared Linux pool and native delivery source remain unchanged from `e9e3506`;
their Linux runtime tests cannot execute on macOS.

Historical evidence remains at
`/Users/access/code/lattica/benchmark-results/apple-priorities-20261004/run-01`.
Its source archive SHA-256 remains
`f3dbb3598556a52677c95cbab13e0c11bd7d81adc09188e9028136e46f75e323`.
The [source-completeness checker](../../lattica-prover-p3/scripts/check-apple-source-commit.py)
still detects omitted modules, unstaged source edits and new benchmark helpers;
it is not an automatic Git hook or a substitute for correctness tests.

- [Next acceleration priorities](../apple-acceleration-next-priorities-2026-10-04.html) — start here for exact Metal squaring, shared-buffer reuse, quotient temporary reuse, fair SME comparisons, targeted scheduling, and native Zig hashing. Each priority includes source locations, evidence, and correctness gates.
- [Completed optimization comparison](../apple-priorities-implementation-2026-10-04.html) — the supporting 18-thread research comparison: 254.03s to 204.57s, or 19.5% lower latency in one matched pair, with independent CPU audits.

These historical reports are standalone HTML with embedded evidence. Their original
source hashes identify the implementation measured at that time; the new integration
report pins the committed combined source. The implementation remains experimental
and is not production-activated. Future validation starts with focused checks and
uses a minimal matched comparison when a full-job measurement is needed.

## Architecture and roadmap

- [Proving pool architecture](../proving-pool-architecture.md) — proof jobs and final aggregation, continuous scheduling and cadence, hostile workers, and reuse across competing pools; separates local implementation and measurements from proposed distributed services.
- [Solving benchmark report](../benchmarks/index.html) — offline throughput, latency, resource telemetry and P0–P5 milestone evidence; [export and portable Apple-silicon imports](../benchmarks/README.md).

- [CISO/CTO cryptocurrency deployment assessment](../recursive-proving-performance-analysis.md) — four-user-transactions-per-minute launch requirement, security and performance gates, finality options, hardware and worker-pool economics, and supporting engineering evidence.
- [Execution DAG and GPU implementation plan](dag-gpu-implementation-2026-10-17.md) — current source review and plan to move all wallet/recursive proving arithmetic onto GPU, extending the implemented local pool and partial GPU pipeline. Includes remaining CPU stages, device memory ownership, OpenCL/Metal coverage, implementation order and qualification gates; full GPU proving is not implemented or activated.
- [Throughput engineering analysis and project plan](high-throughput-proving-plan.md) — proposed subtree locality, quantified transfer model, execution DAG, exact indexes/Bloom hints, capability-aware pool, worker hardware and 512/4,096-capacity three-minute research profiles. Includes feasibility, cost and acceptance gates; not implemented or activated.
- [Distributed proving and throughput roadmap](../distributed-proving.md) — proposed public-only worker service, CPU/multi-GPU scheduling, verified results, recovery and measured scaling gates. Distinguishes the current 64-per-12-minute ceiling from separately reviewed 100/1,000-user-tx/min capacity experiments; not implemented or activated.
- [Framework decision](../framework-decision.md)
- [Block-production and incentive design](../block-production-consensus.md)
- [Multi-asset, exchange, and issuance architecture](../multi-asset-exchanges-issuance-cto.md)
- [GPU proving](gpu-acceleration-2026-10-17.md)
- [Resident binary FRI checkpoint](dag-gpu-implementation-2026-10-17.md#915-resident-binary-fri-integration--2026-10-07) — GPU opening-to-FRI handoff, retained layers, folds, mixing and final-proof gathers; exact proof bytes and original CPU-PCS verification pass. Complete GPU proving remains in progress.
- [Owned initial PCS queries](dag-gpu-implementation-2026-10-17.md#916-owned-initial-pcs-query-reconstruction--2026-10-07) — GPU queries reuse retained prefixes without host LDE access; the following storage checkpoint removes redundant commitment-time copies.
- [Device-only PCS storage](dag-gpu-implementation-2026-10-17.md#917-device-only-pcs-storage--2026-10-07) — opt-in polynomial storage skips all host LDE allocation/readback/reorder; 93 Rust and 36 resource tests pass, including exact proofs and preprocessing reuse. Witness, transcript and random expansion remain on CPU; full-size memory and throughput are unqualified.
- [GPU witness and preprocessing primitives](dag-gpu-implementation-2026-10-17.md#918-gpu-witness-and-preprocessing-primitives--2026-10-07) — all recursive opcodes and both AIR layouts match CPU columns; 103 Rust cases pass. The following checkpoint connects these primitives to complete batch proofs.
- [GPU witness-to-proof handoff](dag-gpu-implementation-2026-10-17.md#919-gpu-witness-to-proof-handoff--2026-10-07) — device witnesses and deterministic preprocessing feed complete proofs with exact CPU bytes; 119 Rust cases pass across both layouts and debug audits. Registered selection follows in the next checkpoint.
- [Registered GPU witness and worker reservations](dag-gpu-implementation-2026-10-17.md#920-registered-gpu-witness-selection-and-worker-reservations--2026-10-07) — explicit immutable selection connects device witnesses to registered proving with unchanged identity and CPU verification; 64 Rust cases and 40 resource tests pass. Worker reservations remain additive; randomness, transcript/grinding, wallet arithmetic and full-size qualification remain open.
- [GPU random streams and hiding-buffer handoff](dag-gpu-implementation-2026-10-17.md#921-gpu-random-streams-and-hiding-buffer-handoff--2026-10-07) — exact ChaCha20/Goldilocks sampling and private device inputs match CPU hiding commitments; 28 Rust cases pass, including 22 native checks.
- [GPU randomization polynomials and retained salts](dag-gpu-implementation-2026-10-17.md#922-gpu-randomization-polynomials-and-retained-salts--2026-10-07) — private device matrices feed randomization LDEs and trace/lookup/quotient/FRI salts, with final query rows matching CPU proofs; 34 Rust cases pass, including 28 native checks.
- [Trusted public GPU salts and RNG snapshots](dag-gpu-implementation-2026-10-17.md#923-trusted-public-gpu-salts-and-rng-snapshots--2026-10-07) — public salts and preprocessing keys survive setup sessions, with explicit construction snapshots distinct from shared active streams; 49 Rust cases pass, including 29 native checks. Registered selection and worker reservations remain pending; private stream integration follows in the next checkpoint.
- [Private GPU randomness in complete proofs](dag-gpu-implementation-2026-10-17.md#924-private-gpu-randomness-in-complete-proofs--2026-10-07) — all four private streams feed device consumers, with shared failure retirement across the full proof; 72 Rust cases pass, including 36 native checks. Registered integration follows in the next checkpoint.
- [Registered GPU randomness and worker admission](dag-gpu-implementation-2026-10-17.md#925-registered-gpu-randomness-and-worker-admission--2026-10-07) — immutable runtime selection, additive worker reservations and measured sampler reports; 101 Rust cases, 48 native GPU checks and 44 Python resource cases pass. Transcript/grinding and full-size pool qualification remain pending.
- [GPU transcript and grinding primitives](dag-gpu-implementation-2026-10-17.md#926-gpu-transcript-and-grinding-primitives--2026-10-07) — device-owned challenges, query indices and deterministic bounded grinding match the CPU oracle; 48 Rust cases and 27 native GPU checks pass. Complete-proof integration, registered selection and worker reservations are next.
- [GPU transcripts in complete owned proofs](dag-gpu-implementation-2026-10-17.md#927-gpu-transcripts-in-complete-owned-proofs--2026-10-07) — 18 full/compact GPU-transcript proofs match CPU bytes and verify after GPU shutdown; 81 Rust cases and 41 native checks pass. Derived scalar arithmetic, registered selection, stage reporting and worker reservations remain.
- [GPU scalar arithmetic and owned domain metadata](dag-gpu-implementation-2026-10-17.md#928-gpu-scalar-arithmetic-and-owned-domain-metadata--2026-10-07) — lookup prefixes, coset calculations and opening points run on GPU without CPU domain inversions in the selected owned path; 102 Rust cases and 56 native checks pass. Registered activation, worker reservations, remaining proving routes and hardware/throughput qualification are next.
- [Registered GPU transcripts, reporting and worker reservations](dag-gpu-implementation-2026-10-17.md#929-registered-gpu-transcripts-reporting-and-worker-reservations--2026-10-07) — explicit selection connects bounded transcripts to registered proofs with actual transcript/grinding/scalar reports and additive worker reservations; 84 Rust and 135 Python cases pass, including 45 native GPU checks. Setup/public-value arithmetic, wallet routes, strict GPU coverage and hardware/throughput qualification remain.
- [GPU setup domains and registered identity hashing](dag-gpu-implementation-2026-10-17.md#930-gpu-setup-domains-and-registered-identity-hashing--2026-10-07) — GPU witness setup uses metadata-only domains and bounded GPU program-identity hashing; 76 Rust and 135 Python cases pass, including 41 native GPU checks. Forty-two registered proofs preserve CPU identities and verification. Public statement/root arithmetic and complete stage coverage are next.
- [GPU statement derivation in recursive sessions](dag-gpu-implementation-2026-10-17.md#931-gpu-statement-derivation-in-recursive-sessions--2026-10-07) — proving-side leaf, empty, merge and finalizer hashing uses the selected GPU backend while CPU verification stays independent; 75 Rust and 135 Python cases pass, including 32 recursive empty proofs. Compiler registry hashing and complete stage coverage are next.
- [GPU compiler registry fingerprints](dag-gpu-implementation-2026-10-17.md#932-gpu-compiler-registry-fingerprints--2026-10-07) — proving-session compilation and five registration APIs use selected-backend AIR fingerprint hashing with unchanged CPU identities; 90 Rust and 135 Python cases pass, including 35 native checks and 47 successful registry-compilation reports. Compiler constant arithmetic and complete stage coverage remain open.
- [GPU public compiler constant helpers](dag-gpu-implementation-2026-10-17.md#933-gpu-public-compiler-constant-helpers--2026-10-07) — explicit inverses, interpolation and quotient constants use bounded GPU kernels; 108 Rust and 135 Python cases pass, including 44 native checks. Tiled interpolation covers periods through 65,536 without a new scratch reservation. Constant folding follows in the next checkpoint; complete stage coverage remains open.
- [GPU compiler constant folding](dag-gpu-implementation-2026-10-17.md#934-gpu-compiler-constant-folding--2026-10-07) — scoped GPU base/cubic folding preserves program identity, caches bounded public results and rejects failed builders. 150 Rust and 135 Python cases pass, including 50 native checks. Symbolic AIR arithmetic and complete stage coverage remain open.
- [GPU symbolic AIR compilation](dag-gpu-implementation-2026-10-17.md#935-gpu-symbolic-air-compilation--2026-10-07) — explicit-backend constraints, lookup packing and registration templates preserve CPU fingerprints and degrees. The following checkpoint extends this to proving setup and quotient compilation.
- [GPU symbolic setup and quotient compilation](dag-gpu-implementation-2026-10-17.md#936-gpu-symbolic-setup-and-quotient-compilation--2026-10-08) — registered analysis and identities reuse GPU-normalized constraints; quotient compilation emits bounded immutable IR. 189 Rust and 135 Python cases pass, including 68 native checks. The shared compiler reservation is 192 MiB; strict stage coverage and hardware qualification remain open.
- [GPU execution receipts and stage coverage](dag-gpu-implementation-2026-10-17.md#937-gpu-execution-receipts-and-stage-coverage--2026-10-08) — explicit proof sessions record completed GPU operations separately from wall timing, retain work across failures and reject overlapping observation scopes. 198 Rust and 135 Python cases pass, including 71 native checks; 45 proof reports have receipts for all 15 selected stages. Strict admission remains disabled pending whole-request coverage and fallback enforcement.
- [Checked GPU completion and explicit CPU audits](dag-gpu-implementation-2026-10-17.md#938-checked-gpu-completion-and-explicit-cpu-audits--2026-10-08) — proof-return paths enforce completed GPU receipts for strict requests; debug CPU constraint audits are explicitly recorded and policy-guarded. 204 Rust and 135 Python cases pass, including 74 native checks and six completion rejections with output-buffer cleanup. Full GPU admission remains disabled pending whole-request coverage.
- [GPU coverage scopes and registered proofs](dag-gpu-implementation-2026-10-17.md#939-explicit-gpu-coverage-scopes-and-registered-proofs--2026-10-08) — release registered proofs support GPU-required execution with receipts for all 15 supplied-input arithmetic stages. Explicit scopes keep component coverage separate from whole-request admission; debug CPU audits reject strict private proving. 214 Rust and 135 Python cases pass, including 80 native checks and 12 GPU-required proofs CPU-verified after shutdown. Whole recursive requests, wallet/batch, AMD/Metal and sustained throughput remain open.
- [Recursive GPU request composition](dag-gpu-implementation-2026-10-17.md#940-recursive-request-receipt-composition--2026-10-08) — typed/untyped requests require five named components and all 16 arithmetic stages. Cached preprocessing records provenance without replaying device events. 238 Rust and 135 Python cases pass, including 80 native checks and 24 GPU-required recursive empty requests CPU-verified after shutdown. Full-size wrap/merge/finalizer workloads, legacy wallet/batch, AMD/Metal and sustained throughput remain open.
- [GPU wallet witness generation](dag-gpu-implementation-2026-10-17.md#941-gpu-join-split-witness-generation-and-explicit-host-prover-bridge--2026-10-08) — GPU-owned join-split trace/public values and an explicit host-prover bridge; 249 Rust cases, 85 native checks and 135 Python cases. The next checkpoint removes the private trace readback from release proving.
- [Owned GPU wallet proving](dag-gpu-implementation-2026-10-17.md#942-owned-single-air-wallet-proving-and-periodic-quotients--2026-10-08) — GPU periodic quotients and single-AIR proving preserve the cubic wallet encoding/verifier; eight GPU-required release proofs and four compatible debug proofs CPU-verify after shutdown. All 258 Rust cases, 91 native checks and 135 Python cases pass. Legacy quadratic/HTLC integration, private wallet workers and throughput qualification remain open.
- [Owned GPU HTLC proving](dag-gpu-implementation-2026-10-17.md#943-owned-htlc-witness-generation-and-typed-gpu-proving--2026-10-08) — GPU witness/public generation and typed proving cover plain, redeem, refund and two-input HTLC fixtures. Sixteen GPU-required release proofs and eight compatible debug proofs CPU-verify after shutdown; 270 Rust cases, 100 native checks and 135 Python cases pass. External preimage acceptance, private wallet workers, legacy quadratic/batch integration and hardware/throughput qualification remain separate or unfinished.
- [GPU issuance and wallet API routing](dag-gpu-implementation-2026-10-17.md#944-owned-issuance-proving-and-candidate-wallet-entrypoint-routing--2026-10-08) — maintained candidate wallet APIs select the complete configured GPU path; typed issuance preserves external mint authorization, and retired engines reject without CPU fallback. Forty-two additional wallet proofs CPU-verify after shutdown; 283 Rust cases, 109 native checks and 135 Python cases pass. Legacy quadratic/C ABI, batch, worker and hardware/throughput qualification remain open.
- [Generalized GPU FRI](dag-gpu-implementation-2026-10-17.md#945-generalized-gpu-fri-and-final-polynomial-interpolation--2026-10-08) — quadratic/cubic folds of arity 2–16 and nonconstant final-polynomial interpolation. Thirty-six component proofs match upstream bytes with independently checked PoW replay and CPU-verify after GPU shutdown; 295 Rust cases, 121 native checks and 135 Python cases pass. Legacy whole-STARK/PCS integration and throughput/hardware qualification remain open.
- [Owned quadratic/cubic PCS openings](dag-gpu-implementation-2026-10-17.md#946-quadraticcubic-owned-pcs-openings-and-gpu-input-queries--2026-10-08) — GPU evaluation, reduction and all input query openings; 36 complete PCS opening proofs CPU-verify after shutdown across full/compact storage and three build profiles. All 322 Rust cases, 139 native checks and 135 Python cases pass. Legacy hiding PCS/STARK and witness/quotient integration remain open.
- [Quadratic/cubic GPU quotients and hiding](dag-gpu-implementation-2026-10-17.md#947-quadraticcubic-gpu-quotients-hiding-commitments-and-scalar-points--2026-10-08) — compact extension-aware compilation, quotient evaluation, hiding commitments and next-row scalars. All 376 Rust cases, 163 native checks and 135 Python cases pass, including 96 quotient and 48 hiding-commitment comparisons. Legacy whole-proof configuration and delivery remain open.
- [Generic resident hiding PCS](dag-gpu-implementation-2026-10-17.md#948-generic-resident-hiding-pcs-for-quadratic-and-cubic-profiles--2026-10-08) — both pinned fields share the resident adapter; 36 hiding PCS proofs preserve upstream bytes and CPU-verify after GPU shutdown. All 400 Rust cases and 181 native checks pass. Complete legacy wallet GPU proving and delivery remain open.
- [Legacy GPU wallet proving and C ABI](dag-gpu-implementation-2026-10-17.md#949-legacy-quadratic-wallet-proving-and-native-abi-delivery-on-gpu--2026-10-08) — 72 complete quadratic wallet proofs verify through unchanged CPU APIs after GPU shutdown; release proving requires GPU completion. All 415 Rust cases and 193 native checks pass. Legacy batches, private worker admission, larger recursion and hardware/throughput qualification remain open.
- [Legacy GPU batch proving](dag-gpu-implementation-2026-10-17.md#950-legacy-batch-proving-gpu-periodic-setup-and-32-chunk-quotients--2026-10-08) — GPU padding/root assembly, periodic expansion and 32-chunk quotients preserve the existing Rust/C ABI formats. All 72 batch proofs CPU-verify after GPU shutdown; 433 Rust executions and 208 native checks pass. Trace assembly reaches 64 tiles; full-size proofs, native initialization, private workers and hardware/throughput qualification remain open.
- [Native GPU lifecycle and standalone C delivery](dag-gpu-implementation-2026-10-17.md#951-native-gpu-lifecycle-and-standalone-c-delivery--2026-10-09) — explicit initialization, drain and shutdown support native wallet proving without a Rust startup shim. All 30 standalone C proofs CPU-verify after shutdown; 442 Rust executions and 214 native GPU checks pass on the desktop RTX 5080. Application startup wiring, private workers, larger proofs and hardware/throughput qualification remain open.
- [Zig GPU startup, CLI and real node delivery](dag-gpu-implementation-2026-10-17.md#952-zig-gpu-startup-wallet-cli-and-real-node-delivery--2026-10-09) — shared lifecycle, strict CLI admission and real wallet/batch backend installation; 404 Zig executions and 64 GPU-required proofs pass across 43 bounded checks. Private workers, larger proofs and hardware/throughput qualification remain open.
- [Wallet-owned local GPU workers](dag-gpu-implementation-2026-10-17.md#953-wallet-owned-local-gpu-worker-admission--2026-10-09) — pinned resource assignments, bounded launcher and strict GPU policy across Rust/native calls; 50 checks and 31 complete GPU proofs pass on the desktop RTX 5080, including 17 assigned-worker proofs. Private witnesses remain local; throughput and larger recursion remain open.
- [Legacy tree GPU delivery](dag-gpu-implementation-2026-10-17.md#954-legacy-tree-gpu-delivery--2026-10-09) — existing `LJSTREE1` containers through 1,024 leaves in full and compact storage; 42 checks, 2,167 complete GPU proofs and 14 complete containers pass with unchanged CPU verification. Root-operation receipts are counted separately; recursive aggregation and sustained throughput remain open.
- [Quadratic GPU lookups and shared opening inversion](dag-gpu-implementation-2026-10-17.md#955-quadratic-gpu-lookups-and-shared-opening-inversion--2026-10-09) — both pinned extension fields now generate device-owned lookups; 68 CPU/GPU comparisons and full/compact proof regressions pass in 11 checks. Public recursive native delivery and owned multi-AIR commitments remain open.
- [Recursive aggregation status](recursion-aggregation-status.md)
- [Recursive aggregation parameters](recursion-aggregation-params.md)
- [Recursion design](../recursion-design.md) — historical design/build log; block-path roadmap superseded by v2.
- [Recursive verifier audit](../recursion-verifier-audit.md)

## Frozen and historical records

These documents preserve the claims and evidence associated with a particular development stage. Their dates and commit references are part of the record; consult the current guides above before applying them to the working tree.

- [v3 audit handoff](../v3-audit-handoff.md)
- [v3 batch audit handoff](../v3-batch-audit-handoff.md)
- [v3 external audit report](../v3-external-audit-report.md)
- [v3 internal audit rounds](../v3-internal-audit.md), [round 2](../v3-internal-audit-round2.md), and [round 3](../v3-internal-audit-round3.md)
- [v3 batch internal audit](../v3-batch-internal-audit.md)
- [Original transaction-stack audit](../transaction-stack-audit.md)
- [Earlier audit scope](../audit-scope.md)
- [Earlier production-readiness assessment](../production-readiness.md)
- [Earlier general soundness analysis](soundness.md)
- [Earlier parameter-selection rationale](parameters.md)
- [Plonky3 port plan](plonky3-port-plan.md)

## Authority rules

When documents disagree:

1. `SPEC.md` and `wire-format.md` control protocol and encoding requirements; their candidate/inactive v2 sections do not activate consensus changes.
2. `AUDITORS.md`, `audit-scope-p3.md`, and `audit-readiness-status.md` control current audit claims.
3. Circuit-specific audits control their named constraint surfaces.
4. `block-proving-v2.md` controls the approved new block-path architecture and milestones, not live consensus or security certification. In-block individual-proof containers and direct witness batches are excluded, not fallback paths.
5. `dag-gpu-implementation.md` selects the execution DAG and GPU pipeline implementation sequence. `distributed-proving.md` specifies the proposed worker service; `high-throughput-proving-plan.md` adds bandwidth/compute models and a three-minute research proposal. These plans do not override v2 construction/capacity, aggregate resource/security gates, protocol encodings or host activation requirements.
6. Research status documents describe experimental code only; older batch-as-interim, unchanged-root, and curve-wrap roadmap guidance is superseded by v2.
7. Dated audit reports remain evidence for their recorded revision and do not automatically describe later working-tree changes.
