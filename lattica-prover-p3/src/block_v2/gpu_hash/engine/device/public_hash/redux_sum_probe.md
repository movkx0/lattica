# Standalone SM80 internal-sum probe

This is an unhooked test experiment. It adds no production selector, transcript
change, protocol parameter, registration path, proof reuse, or workflow claim.
The coordinator owns any `all(test, gpu, gpu-tuning)` module hook, serialized
build, GPU execution, resource audit, and terminal cleanup audit. No test or
benchmark has been executed by its implementation agent.

## Hypothesis and boundary

The current sixteen-lane pair kernel performs three dependent 64-bit
shuffle/add stages to sum eight words in each of 22 partial rounds. Each
64-bit shuffle is two `shfl.sync.idx.b32` instructions. The candidate replaces
only this sum with two `redux.sync.add.u32` instructions over bounded limbs,
one 64-bit pair exchange, and integer carry reconstruction. It keeps the
existing S-box, diagonal multiplication, external matrix, round constants,
round counts, four-word rate, framing, and final canonicalization.

This is source/ISA rationale, not generated-assembly evidence or a speedup
prediction. Extra limb selection, carry reconstruction, instruction latency,
register pressure, and the compiler can erase the dependency benefit. It is
distinct from the rejected fused partial-round schedule, diagonal constant
specialization, generic multiplication, and bank-layout experiments.

`redux.sync.add.u32` requires SM80 or newer, while the existing shuffle selector
allows SM70. The private host eligibility check therefore requires NVIDIA
vendor ID, reported capability major at least 8, reported minor, and warp size
32 before program creation. Missing capability, SM7, or another vendor fails
the standalone probe. It never falls back to another kernel. A probe-specific
source macro enables its entry points; the production source macro/selector
does not change.

## Thread participation

One exact sixteen-work-item workgroup occupies physical warp lanes 0 through
15. Logical word `i` has physical lanes `2*i` and `2*i+1`. Every lane executes
both reductions. Even lanes use member mask `0x5555`; odd lanes use `0xaaaa`.
Each mask names exactly eight live lanes, every caller belongs to its mask,
and all lanes named by a mask execute the same instruction with that mask.
There are no lane-dependent exits or conditional reductions. These are two
disjoint participating groups, not a mask that names inactive warp lanes.

The following pair exchange uses the existing full `0xffff` shuffle mask;
all sixteen lanes execute both halves and select their adjacent partner.
Both raw and sponge kernels require and are inspected for `[16,1,1]` geometry.
The baseline remains `[8,1,1]`. The existing 256-byte local and 4096-byte
per-lane private ceilings are inspected before any global buffer allocation.

## Exact integer reconstruction

Let `B=2^32`, `M=2^64`, and `p=M-B+1`. Input representatives may be any u64.
Each logical word is `low_i + B*high_i`, with both parts less than B.
Even lanes reduce the low parts and odd lanes the high parts. A 32-bit part is
split into two 16-bit limbs before reduction. Each limb total is at most
`8*(2^16-1)=524280`, so u32 reduction cannot wrap. Combining those two totals
in u64 gives each role's exact subtotal, at most `8*(B-1)=2^35-8`.

The pair exchange supplies both subtotals to both roles. Call them L and H.
The mathematical sum of the eight words is `S=L+B*H`. In unsigned OpenCL
arithmetic, `bottom=L+(H<<32)` gives `S mod M`. The one possible carry from this
addition is `bottom<L`. Thus `top=(H>>32)+(bottom<L)` is exactly `floor(S/M)`.
Since `S<=8*(M-1)`, `top<=7`. The final existing `gl_add(bottom,top*(B-1))`
is congruent to S modulo p because `M == B-1 (mod p)`. Its second argument
is at most `7*(B-1)` and cannot overflow u64.

## Raw representatives and subsequent operations

The candidate guarantees field equivalence to the previous shuffle-tree sum.
Exact raw identity with that tree is not required or claimed. The probe counts
raw differences, checks both results against a u128 modular oracle, and checks
exact equality between the two roles within each path. A zero observed raw
difference count alone would not prove raw identity for all inputs.

Combining the low half from one role with the high half from another requires
the two roles of each logical word to hold exactly equal raw representatives.
This stronger invariant follows from the source:

1. Both roles initially read the same state/input word and public constants.
2. Pair S-boxes finish with `gl_mul(x3,x4)` and `gl_mul(x4,x3)`. The existing
   multiplication constructs the same exact low/high product halves in either
   order and invokes the same reducer, so these raw outputs are identical.
3. Existing external layers operate on equal representatives from each role
   group. The candidate reductions reconstruct the same L/H in both roles.
   Diagonal products and final additions therefore preserve exact pair equality.
4. All sixteen lanes rejoin before each collective, including after the
   logical-word-zero selection in partial rounds.

The downstream operations are existing full-u64 `gl_add`, `gl_mul`, the
S-box built from them, the external/internal matrices, and final `gl_canon`.
Their modular semantics do not require canonical representatives. `gl_mul`
reduces the full u128 product; `gl_add` corrects unsigned carry modulo p;
`gl_canon` subtracts p at most once because every u64 is below 2*p. No state
word is used as an index or control-flow condition in these layers. Independent
CPU parity must still be executed; this source argument is not test evidence.

## Proposed checks and evidence

The ignored GPU test allocates the same 32800-byte workspace and 752-byte
constant buffers, with largest allocation 32768 bytes. Its raw kernel uses
only words 0 through 103 of the existing 4096-word scratch. Kernel objects are
created and inspected first, reused throughout, and dropped before their
buffer owners. Every dispatch completes its queue before results are consumed.
The largest host test-input Vec contains 1048577 u64s (8388616 requested
bytes), within the enclosing unchanged worker/process allowances; this is a
standalone test fixture, not a production retained-state allowance.

The raw oracle covers 608 fixed cases: uniform and rotated boundary words,
selected high/low limb corners, and deterministic full-u64 pseudorandom words,
each with four full-u64 constants. It checks the sum, complete internal layer,
and 22 partial rounds retaining each path's own raw representatives. Uniform
u64 maxima exercise all maximum limb totals and the top carry of seven.
Each case compares 48 candidate/reference word pairs and checks both against
u128 field arithmetic; noncanonical inputs are included.

Full sponge checks cover 36 domain/length cases per kernel, including zero,
four-word boundaries, the cooperative threshold, and 4096-word batch edges.
Three alternating component rounds use baseline/pair/redux,
redux/pair/baseline, then baseline/pair/redux on 1048577 fields. The generated
input is hashed outside timing with SHA3-256 using the exact encoding
`b"lattica-redux-sum-input-v1" || domain_u64_le || length_u64_le || fields_u64_le`.
Each timing emits this runtime digest, domain/count, expected/actual sponge
digest, actual capability/storage census, and false production/workflow flags.

The log order is four `REDUX_SUM_KERNEL_CENSUS` records (raw, baseline, pair,
redux), one `REDUX_SUM_COMPONENT_VALIDATION` record, and nine
`REDUX_SUM_COMPONENT_TIMING` records. These records remain dependent on exact
source/build identity, exact test selection, resource/terminal audits, and
independent parsing. Component timing cannot qualify fresh RingCT workflow
throughput. Failure, inconclusive performance, or a resource violation keeps
this probe isolated and disabled.
