# Seven-case research screen: source and lifetime bounds

This module is a private release/test/Linux/x86_64 child behind `gpu-proving`.
It reuses the existing full direct-ring relation, `FreshGpuProofInput`, artifact
codec and independent verifier. It creates no production acceptance entry point,
new cryptographic profile, native MatRiCT spend proof, recursive aggregate or
original quota token. Source payload admission is not measured host RSS, process
VRAM or an original-ledger reservation receipt. The existing process guard owns
process memory, thread and zero-swap enforcement.

The sole ignored selector is
`ring_screen::tests::gpu_seven_distinct_ring_workflows_verify_roundtrips_and_retire`.
The coordinator must run the exact selector with `--exact --ignored --nocapture
--test-threads=1`, in a fresh process, using the existing `direct-full` host-tree
profile. No environment is changed by the test. Bounded `getenv` reads require
exclusive environment access; the fresh serialized test process supplies that
condition. The exact guard requires `LATTICA_DIRECT_RING_SCREEN_QUALIFICATION=1`
and a new absolute UTF-8 `LATTICA_DIRECT_RING_SCREEN_OUTPUT_DIR` of at most 1024
bytes. Before fixtures or GPU dispatch the test also requires:

| Existing setting | Exact value |
| --- | --- |
| `LATTICA_PROVING_POLICY` | `gpu-required` |
| `LATTICA_PROVING_REPORT` | `1` |
| `LATTICA_V2_GPU_PUBLIC_HASH` | `baseline` |
| `LATTICA_V2_GPU_RETAINED_TREE_STORAGE` | `host` |
| `LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES` | `8589934592` |
| `LATTICA_V2_GPU_MANAGED_BYTES` | `8589934592` |
| `LATTICA_V2_GPU_CONTEXT_BYTES` | `4294967296` |
| `LATTICA_V2_HOST_OUTPUT_BYTES` | `34359738368` |
| `LATTICA_V2_GPU_LDE_WORKSPACE_BYTES` | `0` |

All existing native GPU execution switches and row/thread/process limits remain
the coordinator guard's responsibility. The `direct-full` process cap is below
the campaign's 47 GiB ceiling. The worker allowance remains 32 GiB, native
allowance 24 GiB, managed GPU allowance 8 GiB and context reserve 4 GiB. The
public-hash candidate runner remains separate; this initial screen accepts only
the baseline selection and checks the actual completed receipt from both sessions.

## Fixture staging

`bounds::Staging::new` runs before path retention or fixture generation. Its
typed inventory covers one fixture at a time, including fixed public reports:

| Payload | Source count |
| --- | --- |
| Ring heap | Exactly ten `[Account; 2]` entries, admitted before `try_reserve_exact`, with actual capacity checked |
| Native setup heap | Seven `[Poly; 4]` and four `[Poly; 3]` rows; actual retained capacities checked |
| Native AES streams | `7648*4`, `3366*4`, `1197*4` bytes, each rounded up to an AES block; all three summed even though serial-image work follows setup |
| Fixture locals and return destinations | Two `Statement`, two `Witness`, two account-pair arrays, separate one-account spending/opening arrays, local and returned recipient/output arrays |
| Native key/coin scratch | Eight key NTT polynomials, four key outputs, four serial-image polynomials, nine opening NTT polynomials, five commitment outputs; four-polynomial construction and four-polynomial inline NTT/product scratch, summed across sequential routines |
| Primitive state | Amount-bit array, serial arrays, Vec/parameter headers, two AES states and blocks, SHAKE state/reader, SHA3 identity state, ternary sampling input and output arrays |
| Fixed orchestration | Existing 32 KiB caller suballowance |

The sampler streams and native matrix dimensions are pinned by the focused source
canary and the capsule's exact native/generic dependencies. The generic NTT and
product operations operate on fixed arrays; they do not allocate polynomial
vectors. No post-allocation measured peak is used to invent admission. The typed
payload bound is checked against the existing worker limit; allocator/runtime
overhead and compiler-generated stack layout remain covered by the process guard,
not a claimed exact source-to-RSS identity.

`preflight` generates, checks and destroys each statement/witness sequentially.
Only seven optional fixed identity records remain: statement SHA3-256 digest,
case number and two public serials. It rejects equal statements and any serial
repetition across the complete manifest before the first proof. Each proof case
regenerates the exact fixture, checks its host relation and manifest, then compiles.
Both fixture-generation passes are included in the suite measurement. All twenty
accounts per case are genuine original key/coin equations. Serial test material,
ternary spending secrets and commitment openings use distinct SHAKE domains.
Context and setup seed stay fixed; seven different selected pairs and value sets
exercise zero, one and the 52-bit boundaries. These secrets are public test data.

## Compiler, prover, codec and independent verifier

During compilation, the complete fixed `2g`/`16m` compiler allowance is summed
with the actual ten-pair statement, native witness and fixed orchestration. It
must fit the unchanged worker allowance. Native setup arrays and AES streams have
already dropped. The native witness is destroyed before registered proving.

The unchanged registered prover admits program, witness, retained statement,
bounded native reports and all active/temporary GPU memory before setup. The
screen's state fits `verification::CALLER_ORCHESTRATION_BYTES` inside the existing
`REGISTERED_GPU_CALLER_HOST_BYTES` charge. `bounds::orchestration` counts two suite
headers/arrays, three per-case reports, two manifest arrays, path owners, two
staging reports, timer/hash state and the inherited 4 KiB streaming/error/scalar
allowance. It admits worst-case path lengths before allocation and rechecks the
actual retained path capacities before each case. The environment reader uses a
fixed stack array and never first copies an unbounded environment string.

The detailed proving report is streamed to a new file and destroyed before codec
work. Codec allowance is exactly `32 GiB - REGISTERED_GPU_CALLER_HOST_BYTES`.
Original proof, encoded packet, bounded disk input and decoded proof do not all
coexist: encode drops the original proof; write drops the packet; the reader
reserves the admitted exact byte length and rejects truncation/trailing bytes;
decode consumes that new packet under the existing codec bound. SHA3 and byte
length must match the written artifact.

The unchanged independent verifier reconstructs from the expected public statement
and a new GPU session, retires its GPU setup, then numerically verifies on CPU and
rejects the existing public-binding/opening mutations. The screen checks exact
descriptor/context/public binding, no reused prover state or evaluated synthetic
hints, two mutation checks, baseline public hash, positive native work counts,
unchanged allowances, and closed/drained prover/verifier receipts. Only the prover
receipt claims proof completion; independent reconstruction explicitly reports
`completion_claimed=false` because its GPU work is public setup.
The detailed verification report, decoded artifact and statement all drop before
the next case. Early `?` failures retain partial evidence, drop owned state and do
not retry or choose another kernel/profile.

## Reporting and validation boundary

Reports stream directly to create-new files with a 1 MiB serialized ceiling;
there is no JSON value tree or retained seven-statement/proof vector. Per-case
timers end after proof/statement destruction and before their scalar report is
serialized. The suite timer includes preflight, every case and per-case reports,
and ends before final summary serialization and process launch overhead. Actual
managed GPU peak is the maximum of completed session receipts; process host peak
is `null` in this module and must come from guard evidence.

The output is seven separate full relation proofs. Aggregate count is zero;
faithful RingCT, N3/N4 aggregate qualification, security review, protocol adoption
and protocol-redesign 2x claims remain false. Six authored CPU tests cover genuine
relations/regeneration, semantic mutations, manifest duplicate/coverage refusal,
memory/path boundaries, pinned native source geometry and the distinction between
proof completion and verifier public setup. One ignored test covers
the full GPU screen. Source formatting alone has been performed by Agent C;
coordinator builds, tests, GPU validation, terminal audits and peer review remain
required before any new measurement or qualification claim.
