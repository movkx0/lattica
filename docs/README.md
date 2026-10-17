# Documentation

Start with [GPU benchmarking](gpu-benchmarking.md) for current build and comparison commands. `main` contains the available Linux, Apple, pool, and feature-gated research work. A source merge does not extend an earlier audit or hardware qualification to the merged code.

## Current development

| Guide | Use it for |
|---|---|
| [GPU benchmarking](gpu-benchmarking.md) | Reproducible comparisons and throughput accounting |
| [GPU architecture](gpu-acceleration.md) | Backend selection, memory ownership, and CPU verification |
| [Block proving v2](block-proving-v2.md) | Candidate profiles, recursive aggregation, and security gates |
| [Bounded execution](bounded-execution-engine.md) | Resource admission, workers, artifacts, and recovery |
| [Execution DAG](dag-gpu-implementation.md) | Scheduling model and remaining performance work |
| [Pool architecture](proving-pool-architecture.md) | Persistent pool design and worker contracts |
| [Distributed proving](distributed-proving.md) | Proposed remote-worker architecture and trust boundaries |

## Apple hardware acceleration

The previously missing Apple source is integrated, including checkpoint `1604392`. Use the [current Mac recipe](../lattica-prover-p3/scripts/apple-current-benchmark-README.txt). The [Apple integration report](apple-main-integration-2026-10-06.html) records its original validation; new merged builds need their own Metal checks. The Linux systemd controller is a separate runtime.

## Protocol and security

- [Specification](../SPEC.md), [wire format](wire-format.md), [production parameters and soundness](soundness-budget.md), and [protocol decisions](protocol-v1-decisions.md).
- [Auditor handoff](AUDITORS.md), [Plonky3 audit scope](audit-scope-p3.md), [soundness budget](soundness-budget.md), and [transaction-stack audit](transaction-stack-audit.md).
- [JoinSplit constraints](joinsplit-constraint-audit.md), [HTLC constraints](htlc-constraint-audit.md), and [batch constraints](batch-constraint-audit.md).
- [Recursive verifier audit](recursion-verifier-audit.md), [historical aggregation parameters](archive/recursion-aggregation-params.md), and [recursive performance analysis](recursive-proving-performance-analysis.md).
- [Production readiness](production-readiness.md), [audit readiness](audit-readiness-status.md), and [remediation status](remediation-status.md). These have their own dates and scopes.

## Research and evidence

The [October 17 consolidation checks](evidence/main-consolidation-2026-10-17.json) record the integrated branch tips, focused tests, GPU parity checks, and validation limits.

[Tip5 design](deep-tree-tip5-design.md) and [wrap construction](wrap-construction-plan.md) describe optional research; their lean non-hiding configuration is not the private wallet proof configuration.

[Benchmark reports](benchmarks/README.md) explain retained measurements and portable imports. Files in `evidence/` keep source, hardware, workload, and qualification provenance. [Archived documentation](archive/README.md) holds superseded plans and long progress logs. Audit records and evidence remain in the repository.
