# Lattica documentation

[Bounded execution engine and GPU hashing](bounded-execution-engine.md): completed
four-transaction/two-level recursive proofs, five matched retention off/on pairs
(**19.627 / 17.642 minutes median**), root-only CPU replay after shared-fixture
pruning, measured resources and the remaining grouped/full-block/security gates.
The [grouped integration record](evidence/block-v2-grouped-integration-2026-10-01.json)
records the completed eight-wallet/seven-proof CPU chain: **33.133 minutes**,
a **1,914,091-byte** root and fresh CPU replay after pruning 14 inner artifacts.
The [comparison-control record](evidence/block-v2-eight-comparison-2026-10-01.json)
documents the validated single-wallet control and exact shared public inputs.
The subsequent [same-eight CPU pilot](evidence/block-v2-eight-matched-pilot-2026-10-01.json)
completed in **69.941 minutes single / 33.552 minutes grouped**: a **52.028%**
reduction in one pair, but a slower grouped final merge (**287.332 vs 264.760 s**).
Both roots passed recorded CPU audits after local inner-artifact pruning.
Repeated comparison, post-shared-fixture-pruning replay, full-depth performance
and security gates remain open.

The separate [quotient-fusion ledger](evidence/block-v2-quotient-fusion-2026-10-01.json)
records component validation, **204 passing CPU library tests**, and exact
full-size reproduction of all three original grouped preprocessing caps. The fused
eight-wallet root passed preserved CPU verification after local inner pruning:
**28.983 minutes**, **1,913,701 bytes**, with a **252.026-second** final merge.
The [same-binary matched comparison](evidence/block-v2-quotient-fusion-matched-2026-10-01.json)
completed in **32.198 minutes off / 28.983 minutes on**: **9.983%** lower total
time in one pair, with a **270.047 / 252.026-second** final merge. Both roots
passed additional CPU-only replay; memory and retained geometry did not improve.
Fusion stays opt-in and is not repeat-, depth-six- or production-qualified.
The [original five-pair single/grouped series](evidence/block-v2-eight-repeated-series-2026-10-01.json)
has started separately with its original non-fused binaries. Final shared and
registration-fixture pruning/replay remains required.
See its [controls and reproduction gates](bounded-execution-engine.md#quotient-transform-fusion-experimental-implementation-and-gates).

This index is the canonical map of the repository documentation. Documents are grouped by authority so that current requirements are not confused with research notes or historical audit snapshots.

## Current project guides

- [External audit handoff](AUDITORS.md) — reviewed surface, trust model, reproduction, and exclusions.
- [Audit-readiness status](audit-readiness-status.md) — frozen baseline and current development posture.
- [Incremental recursive block proving v2](block-proving-v2.md) — authoritative architecture and milestones; **candidate/inactive**. A four-transaction/two-level recursive proof is demonstrated; profiling and bounded preprocessing reuse support further performance work. The 64-transaction feasibility, security and live-network gates remain open.
- [Remediation status](remediation-status.md) — disposition of implementation findings.
- [Soundness budget](soundness-budget.md) — frozen v1 proof-family parameter accounting; v2 requires separate complete-tree analysis.
- [Wire format](wire-format.md) — normative legacy prover/node byte encodings and an explicitly inactive v2 boundary.
- [Protocol v1 decisions](protocol-v1-decisions.md) — resolved protocol-level design choices.
- [Post-quantum zero-knowledge stack](../POST_QUANTUM_ZERO_KNOWLEDGE_STACK.md) — explanatory cryptographic overview.

## Protocol and implementation assurance

- [Plonky3 audit scope](audit-scope-p3.md)
- [Join-split constraint audit](joinsplit-constraint-audit.md)
- [HTLC constraint audit](htlc-constraint-audit.md)
- [Batch constraint audit](batch-constraint-audit.md)
- [Soundness budget](soundness-budget.md)
- [Hash-function analysis](hash-function-analysis.md)
- [Implementation audit](lattica-implementation-audit.md)
- [Full-node integration requirements](full-node-security-integration.md)

## Architecture and roadmap

- [Solving benchmark report](benchmarks/index.html) — offline throughput, latency, resource telemetry and P0–P5 milestone evidence; [export and portable Apple-silicon imports](benchmarks/README.md).

- [CISO/CTO cryptocurrency deployment assessment](recursive-proving-performance-analysis.md) — four-user-transactions-per-minute launch requirement, security and performance gates, finality options, hardware and worker-pool economics, and supporting engineering evidence.
- [Execution DAG and GPU implementation plan](dag-gpu-implementation.md) — selected implementation direction: local proof DAG and GPU transforms through commitments first, followed by quotient/opening/FRI work, multiple devices and remote subtrees. Includes module boundaries, job/device contracts, failure handling and measurable gates; not implemented or activated.
- [Throughput engineering analysis and project plan](high-throughput-proving-plan.md) — proposed subtree locality, quantified transfer model, execution DAG, exact indexes/Bloom hints, capability-aware pool, worker hardware and 512/4,096-capacity three-minute research profiles. Includes feasibility, cost and acceptance gates; not implemented or activated.
- [Distributed proving and throughput roadmap](distributed-proving.md) — proposed public-only worker service, CPU/multi-GPU scheduling, verified results, recovery and measured scaling gates. Distinguishes the current 64-per-12-minute ceiling from separately reviewed 100/1,000-user-tx/min capacity experiments; not implemented or activated.
- [Framework decision](framework-decision.md)
- [Block-production and incentive design](block-production-consensus.md)
- [Multi-asset, exchange, and issuance architecture](multi-asset-exchanges-issuance-cto.md)
- [GPU proving](gpu-acceleration.md)
- [Recursive aggregation status](recursion-aggregation-status.md)
- [Recursive aggregation parameters](recursion-aggregation-params.md)
- [Recursion design](recursion-design.md) — historical design/build log; block-path roadmap superseded by v2.
- [Recursive verifier audit](recursion-verifier-audit.md)

## Frozen and historical records

These documents preserve the claims and evidence associated with a particular development stage. Their dates and commit references are part of the record; consult the current guides above before applying them to the working tree.

- [v3 audit handoff](v3-audit-handoff.md)
- [v3 batch audit handoff](v3-batch-audit-handoff.md)
- [v3 external audit report](v3-external-audit-report.md)
- [v3 internal audit rounds](v3-internal-audit.md), [round 2](v3-internal-audit-round2.md), and [round 3](v3-internal-audit-round3.md)
- [v3 batch internal audit](v3-batch-internal-audit.md)
- [Original transaction-stack audit](transaction-stack-audit.md)
- [Earlier audit scope](audit-scope.md)
- [Earlier production-readiness assessment](production-readiness.md)
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
