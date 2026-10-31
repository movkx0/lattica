# SHAKE wrapper CPU recursive preflight

This is a release/x86_64 test-only inspection of an already owned compiled
wrapper. It creates no recursive registration, trace, proof, admission token or
runtime dispatch path. `PairedV1` remains disabled. Native fixture production
and wrapper compilation have already occurred when this inspection runs. This
does not establish transaction-wide early refusal or recursive graph closure.

The two outcomes are a refusal under existing ledger charges and an incomplete
full-phase bound. Fitting the partial bound never permits proving. The legacy
`CompiledNode::prepare(budget)` retained-LDE check is not full peak admission and
is not called.

## Exact source profile

The isolated `research/pq-ringct` manifest, with `recursive-wide` and without
`opencl`, selects the pinned CPU full-storage PCS. The allocation-audited heavy
test also requires `native-verification-allocation-audit`. Core feature changes
outside this manifest are outside this source qualification. `opencl` is refused
even if a caller intends to disable GPU execution: its core storage types differ.

`machine/program.rs` selects 23 lanes, seven cubic lanes, three opcode bits,
32 public values per row, and at most 64 public values. The wrapper has exactly
`HEADER + 8 = 46` public values. `machine/air.rs` fixes main width 94 and maximum
constraint degree eight. Its preprocessing offsets give
`(3 + 5) * 23 + 2 * 7 + 2 = 200` columns. Height must be a power of two between
eight and `2^20`; existing `MAX_WIRES = 2^26` is preserved.

The block-v2 profile remains cubic Goldilocks, blowup log four, four random
codewords, cap height six, 128 queries, 16 query PoW bits, 191 challenge bits,
127 hash collision bits, node codec two, and capacity 64. The inspection checks
these public constants and rejects a different profile.

## Lookup and LDE derivation

`machine/air.rs::eval` emits A/B/D reads and a C write for each lane, then the
public entries. These are 92 degree-one lane tuples; read multiplicity has
degree three and write multiplicity degree one. The 46 public tuples have
degree zero and degree-three multiplicity. All use the same wire bus.

The greedy packing in `vendor/p3-lookup/src/types.rs::pack_same_bus`, with the
degree in `logup.rs::constraint_degree` and its bounded equivalent
`machine/symbolic/lookup.rs::degree`, tests
`max(S + 1, max(count_i + S - tuple_i)) <= 8`. Six lane tuples fit, seven do
not. Fifteen full groups consume 90 lane tuples; the final two lane tuples and
all 46 zero-degree public tuples fit together. There are exactly 16 packed
lookups. The inspection repeats this fixed source-order recipe without a
symbolic graph or a heap allocation.

`machine/analysis.rs::analyze_geometry` gives permutation base width
`(16 + 1) * 3 = 51`, log quotient chunks three, and 16 hiding quotient chunks.
The pinned `p3-fri-0.6.1/src/hiding_pcs.rs` doubles each committed domain and
adds four random columns except to preprocessing. Retained full LDE columns:

| Round | Base columns including hiding |
| --- | ---: |
| Main | 94 + 4 = 98 |
| Preprocessing | 200 |
| Permutation | 51 + 4 = 55 |
| Quotient | 16 * (3 + 4) = 112 |
| Random | 3 + 4 = 7 |
| Total | 472 |

Each LDE has `height * 32` rows and each base-field element occupies eight bytes.

## Two unavoidable retained digest trees

`config.rs::ValMmcs` uses pinned `MerkleTreeHidingMmcs` with binary arity and
four base-field elements per digest. `p3-merkle-tree-0.6.1/src/merkle_tree.rs`
retains every digest layer down to a root. Selecting a cap does not remove
these stored layers. A tree with `L` LDE rows therefore retains at least
`(2 * L - 1) * 4 * 8` digest payload bytes.

Only the preprocessing and main trees are included. The other three commitment
trees, salts (`hiding_mmcs.rs` retains its horizontal pair), natural matrices,
transform workspaces, proof buffers, verifier scratch, and allocator/process
overhead are omitted. This is deliberately a partial lower bound.

The lifetime overlap is explicit in pinned `p3-batch-stark-0.6.1/src/prover.rs`
when opening rounds are assembled: preprocessed prover data, main data,
permutation data, quotient data, and random data are retained together. Thus
the complete five-round LDE payload overlaps these two trees. No equality with
total process memory is claimed.

| Padded height | Retained full LDE payload | Two trees | Partial lower bound |
| ---: | ---: | ---: | ---: |
| 131,072 | 15,837,691,904 | 536,870,848 | 16,374,562,752 |
| 262,144 | 31,675,383,808 | 1,073,741,760 | 32,749,125,568 |

The pair's partial bound is below 32 GiB in isolation. Its existing owner
retains a conservative 2 GiB program reservation, plus program headers, compiler
inputs, report, request and fixture charges in that same 32 GiB worker ledger.
The partial bound exceeds the remaining allowance with those owners live.
The physically retained program (previously observed around 223 MiB for this
pair) is reported separately and never substitutes for its charged reservation.
The refusal is under existing charged allowances, not a claim that the physical
process necessarily needs more than 32 GiB.

## Bounded analysis comparison

The ignored test builds a valid 137-byte input/output fixture and four fresh
native CPU proofs for singleton zero, pair zero, and the odd tail. It invokes
the actual owned compiler phase, then admits 256 MiB `PhaseScratch` in the same
ledger before creating an AIR or calling `analysis::analyze_bounded_cpu`.

The bounded core adapter caps simultaneously live symbolic graph storage at
192 MiB (`BOUNDED_CPU_ANALYSIS_GRAPH_BYTES`): recording, normalization, retained
lookups and packing follow `machine/symbolic/verifier.rs::Limits::workspace` and
`prepare_registry`. `Builder` windows share their recorded backing. The AIR
uses fixed arrays for all lane/cubic/Poseidon helpers and emits tuple arrays
directly to the recording builder. It makes no trace or preprocessing matrix.

The remaining 64 MiB bounds the fixed AIR/LogUp helper backing outside those
graph quotas. `vendor/p3-lookup/src/logup.rs::eval_fraction` and
`compute_combined_sum_terms` use two-element tuple vectors, multiplicities,
combined terms, and prefix/suffix vectors. The test's conservative helper
recipe counts all 16 fractions concurrently (only one is evaluated at a time),
all 138 unpacked tuples in each fraction, eight handle slots per tuple plus
64 fixed slots, vector headers, and old/new backing. Each symbolic expression
handle plus depth has a checked ceiling of 256 bytes. Four handles per frame
at the recording depth limit 512 and a further 1 MiB for scalar layouts,
diagnostics and reports are included. This recipe is below 64 MiB. Expression
Arc nodes themselves are already charged to the core recording quota.
Allocator metadata, OS/thread stacks and I/O remain covered by the enclosing
serialized process guard, not asserted to be measured by this logical ledger.

The comparison checks actual analysis height, main/preprocessed/permutation
widths, quotient count, degree eight, and retained LDE bytes against the fixed
recipe. The inspection runs only after analysis scratch is released, so its
reported remaining allowance does not contain the temporary audit charge.
The test reports source-bound program/input physical capacities while their
existing owners and the analysis scratch are live.

The allocation observer checks zero requested heap bytes for inspection,
wrong-ledger rejection and malformed-summary rejection. Full ledger snapshots
must remain unchanged. Exact remaining-byte and one-byte-short boundaries both
remain closed; the former is incomplete and the latter is refused. Owner moves
through a fixed stack queue and all failure cases preserve reservations; final
drop and context retirement must leave zero live charges.

`shake_outer_preflight` lines explicitly report `complete_footprint=false`,
`outer_registration_started=false`, `outer_trace_started=false`,
`outer_proof_started=false`, and `full_transaction_graph_closed=false`.
No CPU fixture result establishes GPU work, throughput, or authenticated
transaction context. Full transaction/final-aggregate closure and a complete
phase bound remain required before the paired runtime can be considered.

## Audited qualification outcome

The coordinator ran both checks serially on the frozen integration source.
`ternaryopt-integration-shake-tests-1` passed 49 tests with eight ignored;
guarded wall time was 66.200795504 seconds and process memory peak was
1,324,318,720 bytes. `ternaryopt-shake-outer-preflight-1` passed its one ignored
qualification test with four fresh native CPU proofs and three compiled
wrappers; guarded wall time was 28.129323221 seconds and process memory peak
was 840,290,304 bytes. These times include the guard's command scope and are
correctness evidence, not proving throughput comparisons.

All three actual bounded analyses matched the fixed geometry recipe. The
live worker charge was 2,164,491,644 bytes against a 34,359,738,368-byte
allowance, leaving 32,195,246,724 bytes. This included 2,147,485,296 charged
program bytes, 16,777,976 charged input bytes and 213,693 charged report bytes,
with the request and source fixture still live.

| Wrapper | Active rows | Padded rows | Physical program bytes | Physical input bytes | Inspection result |
| --- | ---: | ---: | ---: | ---: | --- |
| Singleton, ordinal 0 | 101,683 | 131,072 | 111,903,116 | 2,097,520 | Incomplete full-phase bound |
| PairedV1, ordinal 0 | 203,181 | 262,144 | 223,533,336 | 4,194,672 | Refused under existing ledger charges |
| PairedV1 odd tail, ordinal 1 | 101,600 | 131,072 | 111,772,796 | 2,097,520 | Incomplete full-phase bound |

The pair's 32,749,125,568-byte partial lower bound exceeds the remaining
allowance by 553,878,844 bytes. Singleton and tail each have the
16,374,562,752-byte partial lower bound; its fit remains insufficient for
admission. The allocation observer reported zero requested allocation for
inspection and rejection paths, including exact and one-byte-short boundaries.
Owner cleanup and context retirement completed with zero live ledger charges.

Both process receipts report exit status zero, unchanged source inputs and
executables, all subprocesses terminal and reaped, and zero-swap policy. The
8 GiB process guards bounded these compiler/analysis fixtures; no outer
registration, outer trace, outer proof, GPU work or complete transaction graph
was executed. `PairedV1` remains disabled and no runtime promotion follows.

Evidence is retained in the campaign integration worktree's
`.tools/pq-opencl-opt/runs/` directory:

- Heavy receipt `ternaryopt-shake-outer-preflight-1.json`, SHA-256
  `b14ae5574f542778be70dad80e015e665a3fec165eff1b24177529a7a0ce969d`.
- Heavy log `ternaryopt-shake-outer-preflight-1.log`, SHA-256
  `eb8e0c4b8a18f63564cd5709633f0edc93cebad7865fd7095340c72366507d76`.
- Focused log `ternaryopt-integration-shake-tests-1.log`, SHA-256
  `b0b5251d5edfc5d6a1f9e71763cabbc6f846e3b7713b7aac27f96e0f18b4e5d6`.

A and C independently reviewed the lower-bound derivation, fixed helper
reservation, owner lifetime and closed outcomes without finding an
implementation blocker. This does not replace qualified cryptographic review
or the still-missing full phase/graph qualification.
