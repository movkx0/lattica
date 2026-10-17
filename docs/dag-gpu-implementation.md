# Execution DAG and GPU work

The integrated source uses dependency-driven proof jobs and explicit backend requests. Public wallet proofs enter typed leaf/pair jobs; merge jobs become ready when their inputs are verified and available. Root validation and durable host application are separate completion stages.

The [bounded engine](bounded-execution-engine.md) defines admission and recovery. The [pool architecture](proving-pool-architecture.md) describes persistent workers. The original detailed milestones and measurements remain in the [development log](archive/dag-gpu-implementation-2026-10-17.md).

## Current implementation

- CPU and GPU proving policies track which stages actually ran.
- OpenCL supports device-owned proving data and explicit buffer lifetimes.
- Metal retains its shared-memory prefixes, compact storage, and public preprocessing optimizations.
- The local pool schedules work with budgets, candidate identity, artifacts, and worker generations.
- Optional Linux phase coordination permits controlled concurrency; one worker per GPU remains the starting configuration.
- Tip5/lookup wrap research is behind explicit features and is separate from the default wallet proof configuration.

## Next performance work

1. Establish a fresh, commit-pinned baseline on each GPU using [the benchmark guide](gpu-benchmarking.md).
2. Measure stage times, host/GPU memory peaks, transfers, audits, and delivered transaction counts under the same workload.
3. Change one scheduling or storage setting at a time, retaining failed runs and independent CPU verification.
4. Qualify full-capacity, persistent-pool, restart, and native-delivery behavior before promoting an optimization.
5. Extend inventory and admission for other GPU vendors before claiming portable controller support; develop remote-worker transport against the existing job/artifact contracts.

Historical speedups and deadline checkpoints apply to their recorded sources. The consolidated head has no new throughput qualification merely because the branches were merged.
