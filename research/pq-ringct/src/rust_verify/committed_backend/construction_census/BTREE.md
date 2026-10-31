# Pinned constructor collection bound

This extends the B013 source investigation with a checked, private test-only
requested-byte model. The formulas now live in `source_graph::collections` and
are shared by this census and the test-only original graph constructor's
preceding scratch reservation. The census itself issues no token. B013 remains
an immutable earlier snapshot. The coordinator accepted the allocator
qualification described below; complete native admission remains unavailable.

The source pins are the Rust 1.96 alloc files listed in BOUNDS.md. The model
requires 64-bit pointers and key/value alignments at most eight. All actual
keys/values are Copy values with no heap referents:

| Container | Key | Value | Maximum unique entries | Node request ceiling |
| --- | --- | --- | ---: | ---: |
| constants | `(u64,u64)` | `usize` | 47363 | 420 |
| canonical_maps | `(u64,[usize;256])` | `PolyId` | 2596 | 22948 |
| signed_maps | `[usize;256]` | `PolyId` | 178 | 22860 |
| dependencies.seen | `usize` | `()` | 1165932 | 244 |
| dependencies.inputs | `PolyId` | `()` | 4351 | 332 |

`PolyId` contains only owner/index scalars; it does not retain another graph or
reference-counted payload. Keys containing expression indices also contain no
borrowed or independently allocated data. The BTreeMap/BTreeSet headers are
inline in the backend/traversal stack; only nodes allocate.

## Node size and insertion lifetime

Pinned LeafNode has five fields: pointer, u16, u16, eleven keys, eleven values.
For these alignments, an intentionally excessive eight padding bytes per field
bounds every field boundary and tail. InternalNode embeds the leaf and twelve
pointers; another eight bounds its tail. Thus every node request is at most
`8+2+2+11*(K+V)+5*8+12*8+8 = 156+11*(K+V)` bytes. This bounds requested Layout
size, not allocator headers, size-class rounding, page residency or RSS.

The actual collection operations are lookup, insert, iteration and final drop.
There is no clear/remove/rebuild, range extraction or cloning during graph
construction. `entry.rs::insert_entry` creates one initial leaf. For later
unique keys, `node.rs::insert_recursing` inserts into a leaf, then walks upward
while a split is pending. `split` creates one right node and moves inline
elements/edges into it; an overflowing root adds one parent. No old node is
deallocated during insertion. Every new node is owned by the resulting tree,
and every node of that nonempty completed tree contains at least one key.
Therefore after N successful unique insertions at most N nodes have ever been
allocated. During an insertion, nodes are only added and are all needed by the
completed tree for the same insertion. The implementation charges N+1 nodes
for a nonempty profile, leaving one conservative initialization margin; empty
profiles charge zero. Duplicate insertions replace inline values and allocate
no nodes. This bound covers cascaded splits, not just a single leaf split.

All scalar key comparison implementations used here are infallible and do not
allocate. Keys and values have no Drop implementation. BTree allocation failure
uses the standard global OOM path; it cannot return a successful owner from this
infallible collection API. A future fallible constructor still needs its own
allocation/failure policy and cannot infer one from this census.

IntoIter owns inline lazy traversal handles. The same node allocations remain
charged as they are drained and deallocated; iteration/destruction creates no
replacement tree. In `dependencies`, the inputs tree and the new returned Vec
coexist during collection. The tree is charged here; the surviving Vec is
charged by B013's nested-operation bound. This does not grant overlap credit.

## Coexistence and totals

All three memo maps remain live while each dependency traversal runs. Traversals
are sequential: there is one seen tree, one inputs tree and one todo Vec at a
time. The maximum total enqueues are `D+2*expression_ceiling = 2332120` because
each unseen expression enqueues at most two children. The todo Vec therefore
receives three times that length in usize backing to cover both old/new capacity
during growth. Previously returned ID Vecs remain in the separate graph bound.

The model sums all memo node bounds, both dependency node bounds, todo growth
backing and the inline CommittedBackend object. Before the inline backend, this
is 425484172 requested bytes, below 512 MiB. It deliberately combines maxima
that need not occur together. It omits the graph Vec payloads, imported/generic
polynomial-reference containers, native operation staging/runtime, and report,
error, stack and cleanup obligations. `complete_constructor_bound` and
`workflow_dispatch_authority` stay false.

## Accepted collection qualification

The default pure test checks actual type sizes/alignments, count derivation,
overflow, unsupported alignment and false authority flags. It does not allocate
the modeled trees.

The ignored `fixed_constructor_btrees_cover_splits_duplicates_iteration_and_drop`
test reuses the repository's existing
`native-verification-allocation-audit` global observer. It must be built without
the core stream allocator and run alone in the coordinator's serialized guard.
It measures cumulative requested bytes for ascending, descending and alternating
edge insertion orders. Constants include sizes 0,1,11,12,144 and the full ceiling;
the other four concrete types exercise their full source ceilings. It also
replaces existing keys, drains map iterators, and drops complete sets. Since
these insertion-only trees do not retire nodes before the final drain, cumulative
requested bytes bound retained and in-progress backing for this scope.

The coordinator ran this audit successfully in
`fullgpu-constructor-census-cpu-tests-2`; the six focused checks and separate
genuine native fixture check passed. The terminal-integrity-audited record is
[constructor-census-qualification-20261025.json](../../../../reports/constructor-census-qualification-20261025.json).
The focused guard receipt SHA256 is
`389328b6e590dc23020a2b15f7b946b3ffdc06f13a47c1ea2fb81cf910a636c6`
and its raw-log SHA256 is
`febea0538717322ac2ae1f699a6d906dbbd24c544fe14f40ab35f6dab3ab16ce`.
The earlier stopped broad selection remains preserved as failed/incomplete
with its external terminal cleanup audit in that record.

This qualifies only the pinned collection shapes. It does not qualify an
OperationContext, complete proof producer or workflow memory envelope. The
new shared-model ownership integration needs its own coordinator validation.
