# Fixed CPU note producer source boundary

This is a research producer for the seven `seven-distinct-public-fixtures-v1`
cases. It does not accept a caller AIR, proof, seed, callback, or arbitrary
witness. `CpuPrepared::reserve` consumes quota capacity before public checking,
entropy, configuration, trace construction, or proving. Its original token
includes the entire continuation. Decoder and verifier tokens are split from
it, and the remaining original token and encoded bytes move into the decoded
artifact. No owned output accessor, `Clone`, numerical replacement receipt, or
temporary public proof acceptance can bypass that ownership.

The exact types are production `config::MyConfig`, quadratic challenges,
`Radix2DitParallel`, CPU hiding MMCS, four random codewords, cap height6,
96queries, query POW16, commit POW0, blowup16 and maximum FRI arity16. The
reviewed degree hint8 delegates every constraint and other AIR method to the
original join-split. It changes no relation or proof parameter. Both ChaCha
RNGs are seeded independently from `SysRng` for every proof configuration.

The CPU call uses `p3_uni_stark::prove` directly. The general legacy proof
wrapper is excluded because it has a different relation/check/report/timing
boundary and, in stream builds, arms a spill scope. This producer does not arm
a spill scope, inspect GPU devices or select a backend from environment.

## Requested payload census

`CpuPlan::new` is allocation-free. It derives every byte subtotal from fixed
source geometry and typed sizes, then refuses totals outside24GiB native/output
or32GiB worker host. No allowance is substituted for a bound. Numbers are
cumulative requested backing retained until output destruction, not RSS or
allocator high-water observations. Summing sequential requests deliberately
overcharges overlap. Native stack frames, allocator slack, system entropy,
Rayon scheduling/runtime storage and output/tracing infrastructure remain under
the dedicated external process/thread guard. The worker installs no tracing
subscriber; disabled instrumented formatting is not a payload path.

The source is P3 0.6.1 and Rust1.96 x86_64. Exact fixture geometry is
4096×19 trace,33periodic columns,26public values, challenge degree2, hidden
degree8192,18committed matrices and maximum LDE height131072. The quotient
evaluation domain is no larger than this LDE ceiling. Its16quotient chunks have
width6 including hiding columns; main width23 and randomization width6 give
125private LDE columns total. There is no preprocessing or permutation AIR.

| Subtotal | Source requests charged |
| --- | --- |
| Trace | Exact4096×19 field trace,4096 i128 deltas, two growing32-entry link vectors,74 scalar Poseidon constructors of688bytes each. The trace's fixed row arrays stay inline. |
| Configuration | Six Poseidon constant sets: five in the config and the fresh challenger clone. Two DFT cache sets, each with three original Arc/lock/map roots: PCS and periodic evaluation. RNG/Mutex state is inline. |
| Symbolic | Builder/main clone variables, constraint/type/index vectors, alpha powers and at most2048 Arc expression requests. There are81base constraints, no extension constraints. The budget permits128. |
| Quotient | Twelve full base-field vectors bound selectors and their denominator/inverse inputs. The existing reviewed verifier census overcharges periodic construction. Three full33-column tables bound DFT column output, rectangular table and packed table. Every possible indexed leaf gets its own main/constraint buffers and inline descriptors; the bound does not assume only eight initialized Rayon states. Three full extension vectors bound quotient output, flattening and splitting. Chunk/domain/adapter vectors are separate. |
| Transforms | Four copies of all125private LDE columns cover input/hiding, exact-reserve old/new overlap and materialization. Three additional copies of16×6columns cover quotient random slabs, vanishing coefficients and forward results. All67transforms (main,random,twice16quotients,33periodic) are charged independently for cache roots, twiddle payloads, coset descriptors and BTree nodes. |
| Commitments | Each of the three original trees independently owns four salt columns per matrix, all digest layers, sorting/arity/injection lists, input/prover wrappers, dimensions, and cap construction/observation/ownership copies. |
| Opening | Coset, two opening-point difference/inverse/adjusted vectors,18compressed matrices and one reduced vector; every possible columnwise fold/reduce identity, returned point/value/hiding wrappers, matrix views and maps. The exact canonical proof-shape census additionally covers returned uni-stark field clones. |
| FRI | At most13binary-progress rounds. Each is conservatively charged at the full initial height for its salted tree, folding copy/output and inverse powers. All96queries own their three original batch openings, up to13FRI steps, source salted rows, split rows/salts, sibling values/paths and wrappers. Original FRI prover-data and final proof vectors are separately charged. |
| Output | A64MiB maximum original encoding. `postcard::experimental::serialized_size` precedes one exact-capacity Vec, followed by allocation-free `to_slice`; no hidden growing encoder buffer. Decoder packet/canonical buffer and both independent verifier lifetimes have separate preceding claims. |

Growing Vec bounds include all replaced buffers using four times the final
fixed count, with a conservative minimum8elements. This applies only to the
audited exact-sized/truthful iterator or amortized doubling paths; no caller
capacity, oversized reserve request, or arbitrary iterator is admitted.

Each FFT has at most32cosets. Their twiddle lengths sum below the output height;
forward/inverse pairs and both representations fit the charged eight
output-height field vectors. At most34cache insertions per transform include
32coset tables and two ordinary/inverse pairs. The immutable cache never
deletes nodes: total node allocations are bounded by twice the inserted key
count. Rust1.96 BTree nodes have11keys/values and12edges; the typed upper layout
allows two words for every key and Arc value and three header words. Both the
intermediate Vec of coset descriptors and final Arc slice backing are charged.
No cache sharing between transforms is credited.

The symbolic expression ceiling follows fixed source loops. Two8-lane external
layers use at most76arithmetic operations, the internal layer24, nine
add-and-pow7 evaluations45, and eight filtered round constraints72. The
remaining73constraints use at most10operations each; shared scalar expressions
add fewer than20. Total is below1024operations, each creating at most two Arc
nodes. Symbolic clones only increment existing Arc counts. The pure test
independently checks81constraints and degree8 against the original relation.

`DuplexChallenger::grind` uses its specialized packed `find_map_any` loop. It
borrows the permutation and keeps candidates inline, so the random number of
POW trials does not multiply a challenger clone or vector allocation. The
generic cloning-grinder implementation is not used by this concrete config.

## Matched timing and qualification

The exact ignored selector is
`note_gpu::workflow::tests::cpu_seven_distinct_note_workflow_verifies_roundtrips_and_cleans_up`.
It requires its own env-clear `cpu-required` worker, eight Rayon threads, zero
swap and the unchanged coordinator direct-full process envelope. It must not
be selected by the GPU-required guard. Compilation may include both paths; the
test selector and concrete CPU config keep execution independent.

Both workflows start before session, report and fixture admission. All seven
fixtures and fourteen distinct nullifiers are checked before any proof. Each
case prepares fresh public state, creates one fresh proof configuration, proves,
encodes and destroys producer scratch, then follows the identical PQNOTE1
decoder, independent CPU verifier, packet-copy/decoder/verification roundtrip,
and original artifact destruction path. Each case checks the exact original
live-quota baseline. Fixture and session destruction precede the final timer.
Report publication and separate negative mutation probes remain outside both
timing boundaries. The report remains owned until caller destruction.

Schema v2 carries fixed source recipe, per-case statement digest and independent
random packet hash. The digest binds a domain separator, explicit recipe
length/bytes, context, and all26canonical public values in little-endian order.
CPU and GPU comparisons must match these digests, not just fixture ordinals.
CPU substage times describe fresh config, trace, `prove`, canonical encoding
and config/proof cleanup; `reported_native_proof_scope_ns` is the nested CPU
`prove` interval. Only the outer complete workflow interval is comparable.

No CPU screen has run merely because this source exists. No2×claim, protocol
migration, recursive aggregate, production acceptance, or RingCT throughput
claim follows from this experiment. Process host telemetry comes from the
external cgroup guard; actual process/VRAM peaks stay absent in the owned report.
