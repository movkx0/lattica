# Closed planning for unchanged native families

`unchanged.rs` completes the counts-only source boundary for Statement, private
Proof, Affine, NTT, multiplication, G-bound, Permutation and LinearMap AIRs. The
only inputs are a fixed setup seed or an immutable `ComponentKind` and selected
batch count. Unsupported families, parameters and counts fail before owned AIR
construction. It executes no native proof and grants no registration, receipt,
phase lease or dispatch authority. Production transaction acceptance is unchanged.

## Geometry and limits

| Family | Selected count | Height | Public values | Periodic columns | Maximum source period |
| --- | --- | --- | --- | --- | --- |
| Statement | one | 16,384 | 8 | 2 | 64 |
| Private Proof | one | 8,192 | 4 | 3 | 64 |
| Affine | power of two, 1–64 | 512 × count | 4 | 9 | 512 |
| NTT | 1–32 | next power of two of 896 × count | 8 × count | 9 + 2 × count | height |
| Multiplication | 1–32 | next power of two of 1,216 × count | 12 × count | 21 + count | height |
| G-bound | one | 4,096 | 8 | 39 | 128 |
| Permutation | one | 256 | 8 | 134 | 256 |
| LinearMap | one, 1–16 inputs | 64 × next_power_of_two(inputs + 1) | 4 × (inputs + 1) | 5 × inputs + 6 + signed-bound count | height |

The source bounds are at most 1,024 trace columns, 384 public values, 134 periodic
columns, and period 65,536. The shared counts-only compiler's 256-column ceiling
does not widen any family: Permutation is checked against exactly 134, and
LinearMap is bounded by 104. Widths come from allocation-free validated AIR
constructors except LinearMap's private read-only planning-layout accessor.
The existing affine 64 and NTT/multiplication 32 selection limits are retained,
even though their general AIR constructors can accept larger batches.

Statement's witness generator builds a different 17-column full-height schedule.
The verifier's actual `BaseAir::periodic_columns` returns two 64-element columns.
Private Proof returns three 64-element columns. These planners do not run
witness-generation callbacks.

## Source allocation audit

The common `NativePlanningStorage::for_closed_source` formula charges four times
the logical periodic table and Vec headers, owned descriptor backing and extra
construction backing, plus the inline AIR size. Four covers source capacities
and growth/clone overlap. It separately charges four times the callback's
expression and variable Vec payloads. Compiler programs, symbolic recorder
storage, invalid templates, input values, returned wires and helpers retain the
independent shared bounds described in `BOUNDS.md`.

| Family | Callback Expr Vec entries, conservatively summed per evaluation | Callback Var Vec entries | Extra backing |
| --- | --- | --- | --- |
| Statement | 4 × 32 | public + periodic | two scalar Poseidon constructor constant sets |
| Private Proof | 8 + 4 × 32 + 60 | public + periodic | none |
| Affine | at most 8 × 32 | public + periodic | one scalar Poseidon constructor constant set |
| NTT | 4 × 4 + 6 × 32 | public + periodic | 768 × 32-byte steps during metadata construction |
| Multiplication | 5 × 32 | public + periodic | none |
| G-bound | 2 × 8 + 4 × 24 | public + periodic | none |
| Permutation | at most 8 × 28 | public + periodic | none |
| LinearMap | at most 8 × 32 | public + periodic | cloned inputs, coefficient arrays and signed-bound Vecs |

These sums cover all explicit callback Vecs, including the shared
`ntt_air::constraints::canonical_range` helper. They exceed the maximum
simultaneously live payload where range loops release one Vec before the next.
The pinned Poseidon AIR callback uses stack arrays; symbolic expression/Arc
storage is separately enforced by the recorder. The symbolic builder's public,
periodic and main variables have the same concrete variable type.

The separate scalar `default_goldilocks_poseidon2_8` constructor owns three
constant Vecs: four width-eight initial rounds, four width-eight final rounds,
and 22 internal constants. Statement's `bundle::initial` calls it twice, while
Affine's `bundle_initial` calls it once. Each complete set (86 values and three
Vec headers) is additionally charged as source construction storage before
callbacks run; it does not consume the common compiler helper's allowance.

NTT metadata retains `Vec<Step>` with 768 entries beside its periodic table.
Each pinned x86_64 step contains two `usize` and two `u64` fields (32 bytes).
This is construction scratch, not retained descriptor backing, and is charged
before calling `periodic_columns`.

LinearMap's constructor-validated descriptor has private fields and immutable
public access. Its read-only accessor calculates exact width, height, public
and periodic counts without cloning. The clone backing is the logical lengths
of `inputs: Vec<PolynomialKind>`, `coefficients: Vec<[i64; 256]>` and
`bounds: Vec<u32>`; the inline `[i64; 256]` constant is in the AIR header. The
planner checks the complete auxiliary allowance before `descriptor.clone()`.
Vec cloning copies length, so excess capacity in caller-owned descriptors is
not retained by the planner. Caller-owned descriptor storage remains the
caller's responsibility. Table compression truncates Vec lengths without
releasing their original allocation; the bound uses the original height.

This is a bound on planner-owned Rust backing. It is not an RSS limit, a native
proving-memory bound, a GPU allocation bound or complete phase admission.

## Qualification

The focused tests compare geometry and actual periodic callbacks for every
family, both supported moduli and permutation kinds, both G bounds, selected
batch limits, signed and canonical maps, and maximum map input/bound counts.
They reject malformed parameters and unsupported batch counts and check the
strict auxiliary-budget boundary before compilation. The NTT temporary table
and linear descriptor clone backing have separate source-accounting checks.

The ignored allocation audit prepares all inputs before observation, then
checks zero allocation for geometry and admission refusal. It also checks that
cloning a valid descriptor with excess caller capacity fits its length-derived
bound. This uses the existing C observer and must be built without core's
`stream` allocator. Source/compiler parity tests run separately with the
production-compatible recursive-wide/stream feature set and require
`LATTICA_NATIVE_CORE_SHAPE_QUALIFICATION=1` under the coordinator's serialized
guard. They compare primitive counts, wires, input counts and canonical
manifest digests with the existing verifier compiler; they include a late
compiler refusal followed by an independent successful compilation.

## Accepted serialized checks on 2026-10-24

The coordinator ran Rust 1.96 release qualification under the existing resource
guard. All three runs passed terminal/reaping, source-input immutability,
executable immutability and raw-log hash audits. Read-only reviews of the source
allocation boundary and the shared compiler interface found no blocker for
this counts-only prerequisite scope.

| Check | Result |
| --- | --- |
| Geometry, periodic backing, invalid descriptors, batch caps and memory boundary | 4 passed |
| Allocation observation without the stream allocator | 1 passed |
| Statement/private and algebra compiler parity, including refusal recovery | 2 passed; 23 reported cases |

Geometry and budget refusal requested **zero bytes in zero allocation calls**.
Cloning the valid descriptor with excess caller capacity requested **2,064
bytes in two calls**, below its **8,256-byte** source bound. The 23 parity cases
include the maximum signed-map stress fixture without raising any recorder or
compiler quota. Every accepted case matched primitive counts, wires, input
counts and the canonical manifest digest of the existing verifier compiler.

| Observed maximum across the parity cases | Value |
| --- | ---: |
| Native core active rows | 182,873 |
| Native core padded rows | 262,144 |
| Source-derived auxiliary reservation | 413,280,632 bytes |
| Planner requested program-storage peak | 403,408,600 bytes |
| Guarded memory peak for the complete parity job | 1,118,027,776 bytes |

The parity tests took 26.14 seconds (88.24 seconds for the guarded job, including
build/launch). The requested program-storage observation is not total RSS, and
the auxiliary reservation remains a source-derived bound rather than an
allocation observation. These results establish neither a paired-SHAKE speedup
nor complete-workflow admission; no proof was generated by these checks.

From the research crate, the test filters and feature sets were:

```text
cargo test --release --locked --offline --features native-verification-allocation-audit --lib component_tree::native_shape::unchanged::tests:: -- --test-threads=1
cargo test --release --locked --offline --features native-verification-allocation-audit --lib component_tree::native_shape::unchanged::tests::geometry_refusal_and_cloned_descriptor_obey_allocation_bounds -- --ignored --test-threads=1 --nocapture
cargo --config 'env.LATTICA_NATIVE_CORE_SHAPE_QUALIFICATION="1"' test --release --locked --offline --features recursive-wide,lattica-prover-p3/stream --lib component_tree::native_shape::unchanged::tests:: -- --ignored --test-threads=1 --nocapture
```

The exact guarded launch commands and environments are in the artifacts under
the C worktree's `.tools/pq-opencl-opt/runs/`. The following basenames use prefix
`concurrent-c-unchanged-native-` and suffixes `.json` and `.log`.

| Run | JSON SHA-256 | Log SHA-256 |
| --- | --- | --- |
| `tests-1` | `8c15e6913bbdcddf7b4f2788f0b6697b4a2cb7cc316e29693c0eedd364412078` | `ea7b3fa82ea966d070f41e108aa4fd858314ff3b6104e3f187b42698aa03f03d` |
| `allocations-1` | `b9f15f225043b7f0b6d0790729162262ec32a17243bbd061c82ec6c22746e887` | `b76334137853d41bdede668ebdec0f80905bf6bb10670758010eedea74745e05` |
| `core-qualification-1` | `29580c6394b4dfe2ae433e5613739f5069fb39d183b5695d4398bedfb39239c5` | `a9e9abfc9b330fed6214b077a4beb6639ea3e27d2d6e9ae0d7a35107a0d1a5cd` |
