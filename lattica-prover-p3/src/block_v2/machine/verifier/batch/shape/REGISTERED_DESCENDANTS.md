# Registered-core rejection gate

`verifier_height_envelope` enumerates every power-of-two height from 8 through
the supplied maximum, for one fixed public width. Each compilation uses the
opaque-cap proof in OPAQUE_CAPS.md. The per-class maxima are taken over the
complete finite public domain, not sampled caps or heights. No monotonicity of
compiler output in log(height) is assumed. A later refused shape returns an
error and drops all partial results. The largest source-derived auxiliary
storage shape is admitted before the first compile; only one invalid template
and program exists at a time.

The accepted R4 benchmark's guard file is
`.tools/worktrees/pq-opencl-gpu-preparation/.tools/pq-opencl-opt/runs/multipass-r4-new-5-benchmark.json`.
Its command explicitly supplies `--max-rows 1048576`, host34359738368,
device8589934592 and native25769803776 bytes. The execution limit has no implicit
row default: `pq-ringct/src/opencl.rs::Limits::validate` accepts configured
power-of-two ceilings up to2^22. This screening test therefore requires the
explicit environment value `LATTICA_REGISTERED_CLOSURE_MAX_ROWS=1048576`; it does
not assert that2^20 is a protocol-wide constant or raise an existing limit.

Widths25,28,38,46 correspond respectively to ordered aggregate, graph,
producer-branch, and component public headers. At the R4 ceiling each has18
admissible heights, so the registered-core gate compiles exactly72 public shapes.

## Summing independent verifier cores

The core planner uses zero outer public values, but fresh child public/proof
inputs are allocated exactly as in the actual emit paths. Outer public wires
add no primitive instructions; changing their prefix offset only renames wires.
Two separate cores have independent witness inputs. Concatenating them in one
builder cannot split a shared expression or make a known scalar unknown; the
shared constant/geometry/hash interner can only remove operations. The only
new structural sharing is cap-only hashes or deterministic transcript prefixes,
which still return unknown wires. All challenged arithmetic includes fresh
proof inputs, so sharing cannot induce cubic-to-scalar constant lowering. This
is the same restricted argument as the opaque-cap specialization proof, not a
generic optimizer claim. Add per-class core bounds and separately derived
binding operations before packing once.

`pq_modular::bounded_bits(w,32)` emits at most162 scalar instructions: one zero
Constant,32*(Bit+Boolean+weight Constant+Mul+Add), and one Equal. Constant folding
and existing Boolean constraints may reduce this count. No cubic or Poseidon
instructions occur. A fixed public-field equality emits at most one Constant
and one Equal. `hash_fields(domain,n fields)` emits at most three scalar
Constants and ceil(n/4) Poseidon instructions, as its source calls `poseidon`
once per four-field chunk. No constant permutation is evaluated.

## Component and graph merges

Source: `research/pq-ringct/src/component_tree.rs::public_wires/bind_merge`.

- Component public header46: eight32-bit context decompositions cost1296 scalar
  ops. Eight profile words, six span/type/index fields and four descriptor-root
  words cost at most36 scalar ops. Header total1332.
- Merge: two equalities for each of HEADER38 except FIRST/COUNT/LEVEL cost70;
  first equality, adjacent Add+Equal and count Add+Equal cost5; three sets of four
  endpoint equalities cost12. Merge total87; combined overhead1419 scalar ops.

Source: `research/pq-ringct/src/graph_tree.rs::public_wires` and
`graph_tree/tree.rs::bind_merge`.

- Graph public header28: context decompositions1296 plus eight profile and four
  span words24 gives1320 scalar ops.
- Merge: two equalities for each of28 fields except FIRST/COUNT/LEVEL cost50,
  then the same first/adjacent/count constraints cost5. Total overhead1375.

Neither merge adds cubic or Poseidon instructions outside its child verifiers.

## Actual ordered N3/N4 aggregate topology

Source: `research/pq-ringct-batch/src/tree.rs::public_header`,
`constrain_interval`, `emit_child`, and `compile_merge_impl`.

Every merge is binary. N3 first merges two graph proofs, then merges that
aggregate with the odd graph tail. N4 merges two graph pairs, then merges their
aggregate proofs. There is no fan-in3/4 verifier in these paths.

- Base overhead:21 fixed public fields cost42 scalar ops. The outer interval
  check costs at most4 (remaining Constant,two Adds,Equal). Joining two children
  costs7 (five Equals,two Adds). Six node-metadata Constants, three hash setup
  Constants and four output Equals cost13. Base total66 scalar and four
  Poseidon operations (14-field node hash).
- Graph child beyond its28-public core: eight statement/manifest witness Inputs,
  sixteen context/statement/manifest Equals, three first/count/total Constants,
  one total Equal, three hash setup Constants, and four interval-check scalar
  ops. Total35 scalar and two Poseidon (six-field leaf hash).
- Aggregate child beyond its25-public core: sixteen shared-header Equals, five
  fixed metadata Constant+Equal pairs, one total Equal and four interval scalar
  ops. Total31 scalar; no additional Poseidon.

Thus graph+graph adds136 scalar/eight Poseidon, aggregate+graph132/six, and
aggregate+aggregate128/four. No branch adds a cubic instruction. Host diagnostic
prefix arrays and recursive-witness checks are not circuit operations; their
storage and evaluation still require independent admission.

## Boundary of this gate

Passing proves only that these registered binary descendants stay inside the
configured row ceiling **provided their children do**. It does not establish
that starting native SHAKE wrappers, consuming native Transcript/Sparse
verifiers or SourceBinding graph framing fit. Width38's producer child likewise
needs a closed consuming leaf. It provides no prepared-state, backend, proof,
report or numerical-verifier ownership admission and no GPU/workflow performance
result. PairedV1 must continue to refuse until those remaining requirements and
the full final N3/N4 graph are closed.
