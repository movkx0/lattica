# Bounded proving execution

The local execution engine schedules proof jobs under explicit host and GPU budgets. It provides a foundation for future distributed workers; a remote-worker service is still separate work. See [pool architecture](proving-pool-architecture.md), [distributed design](distributed-proving.md), and the [historical implementation log](archive/bounded-execution-engine-2026-10-17.md).

## Job lifecycle

1. Bind the request to a candidate, proof profile, public inputs, and immutable artifact identities.
2. Admit the job only when host memory, device allocations, scratch, worker slots, and deadlines fit.
3. Execute dependency-ready tasks on the selected worker, with backend completion accounting.
4. Publish proof artifacts and validate their identity and contents.
5. Independently verify the final root and public body, then apply the accepted result durably.

CPU preparation and audits run separately from GPU proving. Strict GPU requests cannot silently fall back. A worker exit, missing artifact, failed audit, exceeded budget, or invalid completion leaves the job failed or awaiting controlled recovery.

## Resource model

Linux controllers use a systemd user session and cgroup limits. Budgets include usable CPU capacity, host heap, retained data, pinned buffers, driver/context memory, managed GPU allocations, maximum buffer size, and scratch. Tmpfs scratch also consumes host RAM. GPU assignments bind UUID and runtime identity.

The optional phase controller uses OS-released file locks for heavy, late, and query phases. The owned path keeps its heavy permit until the proof finishes; the host-trace path can hand off after freeing large prefixes. Merely pausing a process does not release its memory.

Apple has separate Metal memory observations and admission settings. Do not reuse a Linux reservation as Mac qualification.

## Pool and recovery

Compatible public preprocessing can be cached in persistent workers. Cache keys, reservation ownership, and worker generations must match before reuse. Journals and immutable artifacts support interrupted work and continuation; they do not replace final proof verification or native host acceptance.

The implementation lives in [execution/](../lattica-prover-p3/src/block_v2/execution). Operational options are in the [pool runner guide](../lattica-prover-p3/scripts/block-v2-pool-README.txt). Begin hardware comparisons with the smaller [benchmark workflow](gpu-benchmarking.md), then qualify persistent pooling and recovery separately.
