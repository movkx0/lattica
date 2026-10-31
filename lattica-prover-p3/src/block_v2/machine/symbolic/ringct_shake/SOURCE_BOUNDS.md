# Bounded closed SHAKE recording bridge

This feature-gated release Linux/x86_64 bridge is available only with
`gpu-bounded-info`, `stream` and `ringct-research-quota`. The coordinator's
`owned-native-shake` research feature selects these prerequisites and must reject
combination with `native-verification-allocation-audit`, whose independent test
allocator is incompatible with the stream allocator. This bridge starts no
SpillScope, context, session, entropy source or proof operation.

`ShakeRecorder::begin` accepts a pure source-built `ShakePreparationPlan`, an
exclusive borrow of the original preparation reservation, and its original
concrete ledger. It checks identity, the 32 GiB host/8 GiB device ceilings,
exact `SymbolicCompiler` ownership, minimum source-derived `PhaseScratch`, zero
device claim, and absence of unrelated categories before constructing any
builder or column backing. It never accepts a numeric memory allowance. This
claim covers recording only; native generation, PCS, output, report and verifier
claims remain additive and independently mandatory.

The existing recorder owns its original 64 MiB cumulative allocation scope,
including expression Arcs and geometric Vec growth, and refuses nested scopes.
The retained wrapper changes only scope lifetime. Its thread-bound marker keeps
it on the original TLS thread. Error/unwind cleanup destroys builder and column
fields before the original scope; nested failure poisons the existing scope.
The original symbolic 192 MiB partition covers retained recording, normalization
and compiler overlap without releasing it early.

The only new periodic backing is exactly 42 vectors of 128 field elements plus
the outer vector, all checked for exact requested capacity. A016 already charges
these field columns, canonical word columns, flattened upload staging, metadata
and their vector headers in its 132,048 byte periodic partition. No callback
constructs an owned table. Every borrowed column must be requested exactly once,
and finish rejects missing, repeated, out-of-range or nonbinary columns. The
core continuation consumes these same columns without copying them or invoking
any AIR/periodic provider.

`additional_host_bytes` adds actual `size_of` storage for the recording owner,
retained result, retained scope and layout to A019's scratch claim. A016 already
includes `uni::Prepared` and its planner/configuration headers. This conservative
sum intentionally does not credit elided moves or repeated embedded headers.
Existing source-bound symbolic/failure partitions retain any bounded dynamic
error until it is mapped to the inline bridge error. These are requested Rust
backing bounds, not process RSS or opaque-driver measurements.

The recorder stores data; it does not authenticate a generic AIR as SHAKE.
Source selection is closed in the research `PendingNativePreparation::record`
method, which owns the actual immutable request/segment and explicitly matches
the two concrete enum arms. Core completion checks fixed layout, a nonempty
base-only graph, empty interactions and exact base emission order. The research
caller additionally checks any source-supplied constraint count. Neither path
changes native segmentation, transcript semantics or cryptographic parameters.

The opaque `PreparedShake` cannot be cloned or have its dynamic fields extracted
publicly. It keeps the exclusive original preparation claim across moves. The
crate-private fixed-consumer conversion returns `uni::Prepared` together with
that same exclusive claim; the consumer must retain the claim through all PCS
and compiler cleanup. Its numeric PCS allowance is crate-private and supplied
only from the independently admitted fixed consumer, never a public admission
constructor. The bridge supplies no complete native-proof admission by itself.

Five core and three research tests are authored and formatted but not executed
by Agent A. They distinguish upstream symbolic/table comparisons from actual
GPU proving and independent CPU verification. The coordinator serializes all
execution and must preserve failures as evidence. This capsule claims no proof
completion, reuse speedup, whole-workflow promotion or security qualification.
