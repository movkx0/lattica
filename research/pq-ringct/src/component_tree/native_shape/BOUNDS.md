# Closed native-core and framing bounds

`NativeDescriptor` has only the existing lane/batch SHAKE, Transcript and Sparse
variants. Geometry preflight is allocation-free. SHAKE constructors allocate
nothing. Transcript has at most256 parts and one event per class transition,
including its final inactive transition; its width is
`101 + 2*events + 3*POSEIDON_WIDTH`. Sparse has82 periodic columns. All metadata
comes from public descriptors, never proof contents or witness values.

The private core fixture has exactly the native hiding verifier's three PCS
rounds. All publics and proof fields become fresh unknown input wires, so zero
fixture values cannot specialize the compiler. AIR/periodic constants still
come from the exact descriptor. Only operation counts, wire/input counts and
planner storage observations return. No template, program, key, proof,
registration, execution callback or acceptance token escapes. The old
unbounded test-only invalid-template helper is used only as an independent
qualification reference.

## Prior storage admission

Before constructing owned AIRs, tables or templates, `NativePlanningStorage`
reserves both symbolic components (192 MiB workspace and64 MiB retained graph),
two complete native-template backing bounds, descriptor/table capacities and
growth overlap, AIR callback/helper storage, both ProofInputs buffers and
cumulative returned-wire payload. Program construction has its independent
enforced `ConstructionLimits`. No observed allocation can authorize work that
already happened. Actual template metadata is not numerical verification.

`NativeRetentionShape` supplies the three-round template reservation with
at most216 public inputs and32 quotient chunks. The pinned hiding PCS drains
four hiding fields without shrinking the main, quotient and random opening
vectors. Their producer capacities are therefore bounded from `width+4` and
`3+4`, while logical input counts remain `width` and3. FRI truncates the final
blowup-sized vector before its IDFT; final polynomial length1 can retain16
elements. Retained capacity auditing and prior heap formulas use these same
source lengths. This is a capacity correction, not changed cryptographic shape.

The template constructor uses exact iterators and repeated vector initialization;
twice its allowed retained backing covers construction overlap. The separate
three-element widths array owns at most34 usize entries. Callback Vec maxima
are SHAKE47 expressions and216 public variables, Transcript32 expressions
plus8 public/4 periodic variables, and Sparse104 expressions plus8 publics.
128 expressions and216 variables with a factor4 cover their backing and growth.
AIR expression children and windows are inside bounded symbolic quotas/shared
owners. Poseidon AIR constants and intermediate arrays use stack storage.
`main_next_row_columns` may allocate a width-sized usize vector. Large lowering
memo/scratch/hint arrays are already charged to ConstructionLimits.

The generic core helper itself has the same caller-reservation contract as
`verify_bounded`: arbitrary AIR callbacks are not admitted there. Only this
closed research wrapper supplies the audited complete planner preflight.
Requested capacities exclude allocator/RSS overhead, stack reserves, enclosing
worker state, proof production and independent numeric-verifier scratch.

## SourceBinding and adapter arithmetic

`framing.rs` keeps scalar/cubic/Poseidon classes separate. Every listed
framing operation is scalar or Poseidon; there are no extra cubic operations.
These formulas are bounds for the cited source, not acceptance authorities or
heap reservations.

- `bounded_bits(w,32)` costs at most162 scalar operations.
- `Byte::to_wire` costs at most25 scalar operations: one zero Constant and
  eight weight Constant/Mul/Add groups.
- A fresh byte input costs43 scalar operations: Input, eight Bit, eight Boolean,
  to_wire and Equal.
- A byte commitment of length n costs at most `4+25*n+2*floor(n/2)` scalar and
  `ceil(n/8)` Poseidon operations (`pq_bytes::poseidon_commit_bytes`).
- `SourceBinding::new` has N polynomial/byte roots:4N fresh Inputs,2N kind/index
  Constants,12 header Constants, three hash Constants and four root Equals.
  The context bridge costs `8*162 + 32*8 + 836 + 4 = 2392` scalar and four
  Poseidon operations. The fixed seed costs `32*8 + 836 + 4 = 1096` scalar and
  four Poseidon operations. Total: `3507+6N` scalar and
  `ceil((12+6N)/4)+8` Poseidon. The graph public header adds1320 scalar.
- SHAKE wrappers add1332 scalar header operations; first/final endpoint
  conditions add at most216 and8; both endpoint hashes add18 scalar and56
  Poseidon. Every interior join adds108 Equal operations. Both possible request
  endpoint conditions are charged even for a span that only uses one.
- The HashX producer header adds1324 scalar, its bundle-root equality adds4,
  and the component request adds28. These1356 scalar operations are separate
  from the native Transcript and registered component verifier cores.
- A Transcript source bundle uses four initial Constants and, per part, four
  metadata Constants, two zero Constants and two Poseidon calls. A HashX
  branch consumer adds24 context, four bundle and eight Sparse-root Equals.
- HashAlpha adds four input-root Inputs, eight serialization Equals, the
  dual-domain32-byte digest bridge and28 component request Equals. ParametersPp
  includes both fresh32-byte openings, the fixed prefix's bit Constants and all
  byte commitments. Literal prefix length is computed from the source string.

Equal instructions do not propagate known constants. Fresh native/registered
cores remain independent; shared constants and hashes can only remove work
under the restricted verifier paths. Add these per-class bounds before packing
with the actual outer public width.

This prerequisite does not yet traverse the exact complete transaction schedule,
reserve runtime owners or authorize PairedV1. Configured-domain closure must
still include every starting wrapper, actual consuming descriptor, graph leaf
and final aggregate, with all ownership and phase cleanup admission attached.
