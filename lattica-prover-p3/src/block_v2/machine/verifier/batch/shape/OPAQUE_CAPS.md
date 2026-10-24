# Restricted preprocessing-cap specialization bound

This argument is about `batch::shape::verifier_core_bound` and the pinned
machine compiler. It is not a claim that arbitrary constant specialization
reduces scalar, cubic, and Poseidon operation counts independently.

The planner owns invalid zero proof templates. Every child public value and
every proof field is an independent fresh witness wire, as in
`component_tree::merge_impl`, `NodeKey::compile_manifest_record`, and graph
`NodeKey::emit`. Every preprocessing-cap word is also a distinct fresh input
wire, even if two actual cap words or two actual child caps are equal. The API
returns only counts and requested-storage diagnostics. It cannot return a
program, proof, verification key, registered state or admission token.

Only trusted registered-machine geometry is accepted: one through four children,
at most 64 public values each, a power-of-two height from 8 through 2^24, and the
exact `2^min(log2(height)+1+LOG_BLOWUP,CAP_HEIGHT)` cap-root count. The shape program
is empty and fixed-height: `MachineAir::eval` depends on its public count, not its
instructions, and never constructs the preprocessing trace. Its 4*LANES+publics
width-two interactions bound the number of packed lookup columns before any
template allocation. No sample of caps determines an admission limit.

## Uses of cap words in the pinned source

`batch::verify_prepared` uses the preprocessing cap in precisely two places:

1. `observe_cap` passes each word to `Transcript::observe`. The duplex copies
   words only into rate slots 0 through 3. The length update adds a fixed count
   to state slot 4, which is zero initially or a previous Poseidon output; a raw
   cap word is never an operand of that addition. Before the preprocessing cap,
   the transcript has observed the independent witness main cap. Every duplex
   thereafter retains the preceding permutation's capacity slots. Hence cap
   substitution does not turn a transcript challenge into a known constant or
   merge previously different transcript chains. The number of absorptions and
   samples depends on dimensions, never cap contents.
2. The preprocessing PCS `Round` passes the cap to
   `authenticate_equal_height_mmcs`. In the upper cap tree, raw words enter only
   `compress`, and entries are copied into `select_hint_with`. A hint always
   emits a fresh unknown scalar wire even if every source word is constant or
   equal. Its selected contents are constrained by the hash path. The cap-tree
   root is used only by `assert_digest` (four Equal instructions). A one-root cap
   would use raw words only in those equalities; the qualified heights here
   always have 64 roots. Loop bounds and indices are derived from cap length and
   unknown query bits, never cap contents.

`ScopedProgramBuilder::poseidon` never evaluates a constant permutation and never
records its outputs in the known-constant map. It performs structural CSE only.
Substitution may identify cap-tree leaves and share more cap-only permutations.
It cannot split an existing shared expression or create more hash calls. The
transcript chain remains distinct from the cap-only tree because the former
contains fresh main-proof inputs and prior unknown capacity words.

Every arithmetic use of a cap-dependent value therefore occurs after an opaque
Poseidon output or a fresh hint input. Its known/unknown status is unchanged.
In particular no cap substitution can introduce a fully-known CubicMul or
CubicInverse, or change extension/base-field classification, so it cannot move
one cubic instruction into up to three newly emitted scalar constants. This is
the reason independent packing-class dominance is valid for this narrow path.
It would be invalid to infer the same result just from total operation counts.

Constant insertion replaces at most one Input with one Constant per cap word;
the actual constant interner can share more. Both occupy scalar lanes and write
one wire. A removed Equal or a Select with equal branches cannot increase scalar
count: the latter returns one branch and emits at most one Boolean in place of
one Select, with the existing Boolean set suppressing duplicates. Here the
selected path/hint wires and query bits are fresh/unknown in either version.
Cap-tree CSE outputs remain unknown and are used only for hashes, hints and
equalities; it cannot enable unrelated arithmetic lowering. Thus scalar, cubic
and Poseidon counts, wire count, and witness-value count do not exceed the
opaque-cap core. Shared actual caps across children only add opportunities to
remove cap constants and cap-tree hashes.

`ProgramBuilder::finish` packs exactly

```
ceil(outer_public_values / PUBLICS_PER_ROW)
  + poseidon
  + ceil(scalar / LANES)
  + ceil(cubic / EXT_LANES)
```

The planner returns these classes separately so a caller can add independently
derived binding operations before applying the two separate ceilings. It never
infers full transaction or final-aggregate closure from the core alone.

## Storage and qualification boundary

The planner checks every shape and all arithmetic before constructing a builder,
template or symbolic graph. `PlanningStorage` reserves one source-bounded batch
template at a time, template construction overlap, bounded symbolic workspace
and retained graphs, both ProofInputs value buffers, cumulative returned wire
payload, shape/AIR/helper allocations, and the caller's independently enforced
program-construction allowance. It audits the template's actual backing only
after this prior reservation as a drift check. Runtime allocator overhead,
stacks, tracing and enclosing worker storage remain outside requested capacities.

The observed opaque compiler requested-byte peak is **not** a bound for a
specialized compiler: Constant instructions populate different interning maps
from Input instructions. Actual compilers must use their own admitted
ConstructionLimits. Tests of zero, colliding and distinct caps are regression
evidence for the source argument, not the argument itself. Default unbounded
compilation remains the reference and its manifest must match the private bounded
preparation path for the same concrete cap.

This module does not account for endpoint/context binding, graph manifests,
component trees, final aggregation, prover/backend storage, retained real proofs,
or independent numerical verification. Those ownership and descendant closure
obligations must be established before PairedV1 can execute; its existing
pre-dispatch refusal remains in place.
