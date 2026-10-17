# Block proving v2

Block-v2 is the candidate recursive aggregation family. Wallets create hiding proofs locally; workers consume those proofs and public transaction data. A proposed block carries one final aggregate proof plus the public body and encrypted outputs. It does not require users to disclose private witnesses to the producer.

The implementation is feature-gated. Existing wallet proof parameters and the frozen production ABI remain separate. The [historical design and qualification log](archive/block-proving-v2-2026-10-17.md) retains detailed rationale and prior measurements.

## Profiles

| Setting | Current value |
|---|---|
| Default candidate capacity | 64 entries, tree depth 6 |
| Optional capacity | 128 entries, tree depth 7, feature `block-v2-capacity-128` |
| Planned capacities | 256 and 512; no supported primary profile |
| Field / hash | Goldilocks / Poseidon2; cubic extension challenges |
| FRI | Binary, 128 queries, 16× blowup, cap height 6 |
| Hiding randomness | 4 random codewords; fresh CSPRNG randomness |
| Query proof of work | 16 bits |
| Aggregate proof limit | 2 MiB, excluding public body/ciphertexts |
| Candidate block interval | 12 minutes |

The authoritative definitions are in [profile.rs](../lattica-prover-p3/src/block_v2/profile.rs). Both binaries must report the same capacity. Changing capacity requires new keys, fixtures, and qualification. It is not a runtime throughput switch for an existing profile.

## Aggregation and execution

Typed leaves distinguish JoinSplit, HTLC redeem/refund, and issuance. Ordered commitments bind the public body to the root. Dependency-ready pair and merge tasks form an execution DAG. Persistent workers may reuse compatible public preprocessing under budget and identity checks.

The host boundary validates the root and body before durable application. A proof completed by a GPU worker is not yet a delivered transaction. Recovery and reuse must retain candidate identity, verification rules, and resource accounting. See [bounded execution](bounded-execution-engine.md).

## Performance measurement

Use the [GPU benchmark guide](gpu-benchmarking.md). Report both total entries and user transactions; issuance entries are not user payments. Distinguish proof generation, recursive aggregation, root audit, and durable delivery.

The retained October 17 RTX 5080 128-entry experiment had 96 user entries, 32 issuance entries, and 127 recursive proofs. Sequential aggregation took 602.367 seconds; two workers sharing the GPU took 732.593 seconds. This was one block per mode and excluded wallet generation, key preparation, and audits. It supports a one-worker starting point, not a production TPS claim. [Evidence](evidence/block-v2-parallel-aggregation-128-2026-10-17.json).

## Qualification and security

The target is at least the existing 100-bit soundness objective for the complete tree under documented assumptions. Account for all proof instances, composition losses, transcript/domain separation, and profile/verifier identity. Backend parity does not establish zero knowledge or recursive soundness.

Cold aggregation from already-valid wallet proofs, the reserved finalization window, maximum-size proofs, CPU verification, and durable delivery need separate tests. Previous gates apply only to their recorded sources and hardware. Follow [soundness budget](soundness-budget.md), [recursive verifier audit](recursion-verifier-audit.md), and [production readiness](production-readiness.md).
