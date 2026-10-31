# Source-bound SHAKE group geometry before native proving

`GroupCompilePlan::source_shape_plan` accepts only the original
`ReservedShakeRequest` and its original ledger. It preserves the selected
singleton/paired layout and span. Every selected native segment must already
contain one permutation. Batched segments are refused without changing native
segmentation. The fixed compiler limits remain 2 GiB program storage, 2^26
wires, 2^20 inputs and 2^20 padded rows.

The separately selected `source_shape_plan_existing_batches_v1` accepts exact
already-selected native singleton, batch 8, and batch 16 segments. It uses the
same source owner/ledger and fixed compiler profile. No caller can provide a
different native count, descriptor, width, or height. The common census checks
the immutable partition's first/count/width/height against its `SegmentInfo`
and the closed native planner, including public/periodic metadata. A native
descriptor always uses that segment's full count. Batches of 2, 4, or 32 and other shapes
remain unsupported in this version; refusal does not split them or reduce the
source policy. The original singleton-only entry keeps refusing all batches.

With A035's exact existing active opt-validator source policy (Estimated,
maximum AES 64/SHAKE 32, native 24 GiB estimate), HashX input 16,416/output 137 produces seven
batch 16 segments, one batch 8, then padding and squeeze-tail singletons. Their
five paired groups have native counts [16,16], [16,16], [16,16], [16,8], [1,1].
The ten original native proofs and all 122 permutation units remain unchanged.
The 24 GiB source estimate is not managed-device admission. Neither this source
constructor nor its 5-group schedule establishes native batch 16 feasibility
under the unchanged 8 GiB managed-device and 32 GiB worker limits.

The allocation-free census invokes the existing
`NativePlanningStorage::for_descriptor` for each exact SHAKE descriptor. Its
enforced program quota and source-derived template, symbolic, input, returned
wire, callback and periodic storage are charged before `inspect` can allocate.
The two native shape passes run sequentially; each private program, template,
input buffer and symbolic graph is destroyed before the next pass. The original
temporary claim remains live throughout both passes. Fixed source-plan, builder,
program, input, result and error headers are additive. The fixed enclosing
worker stack and allocator/process overhead remain outside these heap claims.
Four additional complete source-plan `Result` slots cover the common helper,
entry, return, and immediate caller; two explicit source-mode slots are also
counted. The mode is admission scope, not a protocol/verification change. These
inline owners are charged before any source shape compilation, without using
return-slot or move elision to enlarge available memory.

`inspect` requires exact category equality and the original ledger. It splits
only the fixed retained metadata reservation; no caller-chosen allowance or
callback is accepted. Failures release their original owners. After successful
planning, only the source identity, fixed counts and original metadata owner
remain. The native/outer runtime, compiler output, proof, verifier and report
claims still need separate complete workflow planning before any dispatch.

The existing closed `native_core_bound` compiles private invalid shape fixtures.
Their native public fields and all proof fields become fresh unknown witness
inputs. The placeholder values cannot become compiler constants or evaluate
synthetic hints. Native height, AIR phase, periodic columns and unchanged
cryptographic geometry determine the emitted verifier. No fixture, program,
key, proof or registration escapes the counts-only API. This work adds an exact
logical census of `SelectHint` entry and bit words to that same private program;
the pinned GPU layout uploads each as one u64. This census is still metadata,
not GPU allocation or dispatch authority.

For one or two native cores, add their scalar/cubic/Poseidon classes and the
existing audited `framing::shake_wrapper(arity)` envelope, then pack once at 46
public values. That framing includes both possible endpoint conditions even
when the selected span uses only one, all header operations, two endpoint hashes
and every interior equality. It adds no witness input or `SelectHint` backing.
The fresh native core input counts therefore sum exactly. Native wire counts
sum conservatively; add 46 outer public wires, at most one wire per framing
scalar and eight per framing Poseidon. Constant/hash sharing can remove these
operations but cannot add any under the pinned fresh-input verifier paths.

The resulting `GroupSourceBound` is move-only and retains the exact request,
layout, ordinal, span, contract, endpoint context and original metadata token.
Its copyable geometry is diagnostic. `is_for` checks the intended original
compiler plan and ledger. `check_compiled` checks the genuine owned result's
request/ledger/category owners, specification, context, exact fresh input count,
and operation/row/wire ceilings. This is conformance to a prior source bound;
it neither numerically verifies a proof nor authenticates transaction context.
The future GPU source-layout envelope must also compare the actual layout with
the prior hint/instruction/row/port census before consuming its original phase
owner. This module does not yet provide that envelope or enable outer dispatch.

Five focused source/admission/arithmetic tests are authored. A separate ignored
CPU qualifier obtains the bound before genuine native fixtures and compares the
singleton, pair and odd-tail compiler results with their respective bounds. It
also checks exact-context refusal and zero final ledger usage. It requires the
existing explicit owned SHAKE correctness guard. These CPU fixtures are not
fresh GPU RingCT workflow evidence. No tests or builds were run by Agent B.

Two further focused tests cover the active HashX exact ten-source/five-group
census, every existing first/count and native geometry, complete 122-unit
coverage, padding/squeeze indices, unchanged default batch refusal, original
owner/ledger/profile checks, and unsupported existing batch 2 refusal. A new
ignored CPU-only source planner test walks all five groups with their original
preissued claims, checks retained identity and fixed row/wire/input bounds,
and requires zero terminal quota. It requires the separate
`LATTICA_OWNED_SHAKE_BATCH_SOURCE_QUALIFICATION=1` guard and emits explicit zero
native/recursive proof counts. It produces no cryptographic proof and supplies
no complete request/transaction/final-aggregate closure or performance evidence.
