# Genuine graph construction census

This private test-only module reads the existing native relation graph. It
creates no graph copy, ownership token, Session, registration, proof, or dispatch
permit. Its report is an observation after construction, never a preallocation
claim or measured peak. All authority flags remain false. PairedV1 stays closed.

The existing GPU constructor in `gpu.rs::lower_unproved_on_gpu` creates a
`CommittedBackend`, imports the decoded inputs, runs shared
`generic::verify_relation`, then moves out `backend.graph`. The three memo maps
die with the backend. The graph's four Vecs and its nested operation Vecs survive
the move. A reservation ending at the native-operation callback therefore does
not own the returned graph.

The GPU constructor now uses `source_graph::inputs::FixedInputs::inspect`
before entering the native callback or importing nodes. The census uses this
same allocation-free raw dimension check. The legacy CPU constructor still
imports before the shared relation's dimension check. Checking dimensions does
not validate coefficients, serial uniqueness, a native proof, or graph
provenance. Input Vec capacities can exceed their lengths; the shared input
view measures every retained capacity without retroactively owning it.

## Fixed relation call counts

All counts below follow `generic.rs` with `CommittedBackend`'s specialized whole
polynomial methods. The generic scalar NTT/multiplication implementations are
not executed by this backend. No deduplication or witness-value credit is used.

| Source | Count or derivation |
| --- | --- |
| Imported statement polynomials | `10*2*(4+5) + 2*4 + 2*5 = 198` |
| Imported proof polynomials | `12 canonical + 79 signed = 91` |
| Parameter polynomials | `7*4 + 4*3 + 29*5 = 185` |
| `linear` multiply-add calls | `(5+5+5+7+7+4)*4 = 132` |
| `auxiliary` multiply-add calls | `4+4+2+2+4+4 = 20` |
| Other multiply-add calls | `2+1+10+2+1+25+12*5*2 = 161` |
| Multiply-sub calls | `8+40+8+2+1+5+40 = 104` |
| Standalone products | `1+3+1+12+40 = 57` |
| Whole products | `313+104+57 = 474` |
| Whole additions | `313+(50+2+3+1+40) = 409` |
| Whole subtractions | `104+(2+1+1+1+12+80) = 201` |
| Whole automorphisms | `2` |
| NTT calls | `3+18+9+12+12+11+11+10+1+8 = 95` |
| Norm input IDs | `9+9+9+11+11+8 = 57` |
| HashAlpha polynomial parts | `180+8+10+8+4+4+3+4+4 = 225` |
| HashX polynomial parts | `1+1+5+5+4 = 16` |

Every `canonical_id` and `signed_id` call is treated as a cache miss. The former
occurs twice per add/sub/product, once per automorphism and parameter polynomial,
and once per transcript polynomial: `2*(409+201+474)+2+185+225+16 = 2596`.
The latter occurs once per NTT, once per norm input, twice per GBound, and twice
for final equality: `95+57+24+2 = 178`.

`byte_id` is called four times by the two byte equalities, once by ParametersPp,
twice by SampleG, once by ExpandAlpha, three times by HashAlpha and once by
HashX: at most 12 extra ByteMap nodes/operations. In the genuine schedule these
references normally already identify contiguous byte sources; the bound does
not depend on that optimization.

| Graph container | Logical ceiling |
| --- | ---: |
| Polynomials | `289 + (409+201+474+2) + 2*95 + 8+3+1 + 2596+178 = 4351` |
| Bytes | `5 imported + setup + pp + alpha + 12 maps = 20` |
| Expressions | `4351*256 + 185*256+3 + 9*256+85+5*256+4*256+20 = 1165932` |
| Operations | `1086+190+6+12+2+1+1+2+1+1+1+2596+178+12 = 4089` |

The three scalar zero calls are one in `verify_relation` and two in column-2
`auxiliary`. The other scalar-expression groups are f0 subtraction, inverse-x
negation, w construction, the public commitment term, and public-slot updates.
Node creation contributes exactly 256 input expressions. Fixed constants only
reduce the bound through memo reuse.

## Four vectors and nested operation ownership

The four graph Vecs start empty and only push. Pinned Rust 1.96 `RawVec` grows to
`max(2*old_capacity, required, minimum_nonzero_capacity)`. All four logical
ceilings exceed that type's minimum. Thus retained capacity is at most twice
the logical ceiling; old/new backing during growth is at most three times it.
These are requested backing bytes, excluding allocator metadata and RSS.

Only CanonicalMap/SignedMap/Norm own `Vec<PolyId>`. A dependency set contains at
most every graph polynomial once. Retained ID capacity is conservatively bounded
by `2*((2596+178)*4351 + 57)`. Only HashAlpha/HashX own transcript Vecs; they have
228/17 logical parts respectively, and retained capacity is bounded by
`2*(228+17)`. The report uses actual `size_of` for each current source type and
checks all arithmetic. The deliberately loose growth ceiling uses factor three
for every vector simultaneously, plus the inline graph object.

The genuine fixture test checks the graph's actual four capacities, nested
capacities and exact principal operation counts against these ceilings. It
reports live graph capacity after construction, not temporary or peak storage.
Synthetic tests exercise spare capacity and malformed dimensions without
claiming a native proof. No graph payload is cloned by inspection.

## Containers still outside the bound

The graph-only byte ceiling must not be used as the constructor admission size.
The constructor also retains the following storage:

| Owner | Source inventory |
| --- | --- |
| Imported symbolic statement/proof | 198 statement polynomial arrays; 9 heap canonical and 78 heap signed proof arrays; outer ring/account/recipient/coin/z_out Vec headers; inline coefficient/byte-reference arrays |
| Generic parameter values | 185 symbolic polynomial arrays and 40 row Vec headers; the native 185 arrays coexist during conversion |
| Generic relation intermediates | f12, z_out18, z0 9, w_out8, w0 4, t_in50, f_ntt12, f_qhat12, z1 11, z2 11, w1 4, w2 4, h3, hx3, alpha2, zb10, g_qhat12, a5, gamma0 4, gamma1 4, p40, z8, e4: 250 heap polynomial arrays plus their nested headers |
| Memo maps | At most 47363 constants, 2596 canonical identities, 178 signed identities |
| Each `dependencies` call | `todo: Vec<usize>`, `seen: BTreeSet<usize>`, `inputs: BTreeSet<PolyId>`; the input tree's backing coexists with the returned ID Vec during collection |
| Raw parameter helpers | AES bytes, coefficient words, copied polynomial arrays and matrix rows; mat2's consumed IntoIter backing stays until cursor drop |
| Raw sampler helpers | Input byte and output word/poly vectors; collection from an owned Vec may preserve its larger allocation when changing element type |
| Transcript serialization | Alpha 230496 bytes, X 16416 bytes; setup/binding buffers; live output buffers and return owners |
| Native GPU operation context | Operation plans, input/output staging, report/receipt/error state, device/host runtime objects and leases |

The symbolic heap array inventory is 285 imported +185 parameters +250 generic
intermediates =720 polynomial-reference arrays, before spare capacity and
construction overlap. This is a logical inventory, not a checked reservation.
The raw decoded inputs remain separately owned throughout lowering. Arrays and
descriptors on the stack also need the enclosing worker's stack accounting.

`dependencies` processes each expression at most once after insertion into
`seen`. Its work list starts with 256 IDs and can enqueue at most two children
per processed expression, so `256+2*1165932` is a conservative logical work-list
ceiling. It cannot be multiplied by all map calls as simultaneous storage:
dependency traversals are sequential, while their returned ID Vecs survive.

## Pinned BTree source investigation

Rust source is installed at
`.tools/rust-1.96.0/lib/rustlib/src/rust/library/alloc/src`. This investigation is
not an admitted BTree bound and contributes no bytes to the current report.

`collections/btree/node.rs` fixes B=6, 11 key/value slots and 12 child edges.
Leaf storage consists of a parent pointer, two u16 fields and the two slot
arrays. An internal node embeds the leaf plus 12 pointers. For these particular
key/value types, alignments are no greater than eight. A conservative candidate
requested node bound is `156 + 11*(sizeof(K)+sizeof(V))`; its padding margin is
larger than every possible field/tail padding in these definitions. It is not a
portable claim about arbitrary Rust BTree versions or allocator metadata.

These maps/sets insert without removal. `entry.rs::insert_entry` allocates a
leaf for an empty tree; otherwise `node.rs::insert_recursing` splits upward and
may add a root. Each new node becomes part of the resulting tree. A candidate
node-count ceiling is one node per unique inserted entry plus one conservative
insertion-in-progress node. This argument still requires independent source
review and focused allocator-request qualification, including cascading root
splits and destruction, before it can close the BTree obligation.

The inspected IntoIter owns two lazy leaf handles and length; it does not own a
heap traversal stack. BTreeMap Drop drains that iterator. Its tree storage must
remain charged through iteration/destruction and while collecting a new Vec.

| Pinned source | SHA-256 |
| --- | --- |
| collections/btree/node.rs | `2200ca0a4fe38592c314dc7f5f40bbb160e06b6f9e4abd1eb5bc40701540ab25` |
| collections/btree/map.rs | `85387f4b8283bef443c154979c149dae4c8c61b96ea75432c58a573a13734dae` |
| collections/btree/map/entry.rs | `cbdc9c4304c5925d43eeaf2af6d415ff0be122bbd7669689a71f56d2996106cd` |
| collections/btree/navigate.rs | `930d1f8c072be5456a9aab02b6ab7f5f620151e0e280db896ef6654cb3ab53f8` |
| raw_vec/mod.rs | `39ae2ccc61fd3bad236978201cda2ad97599403eb103de7eafdf6d7f6dd8b6f3` |

One alternative is fixed-capacity sorted memo Vecs preserving exact key order,
and a fixed seen bitmap/work-list plus ordered polynomial-ID output for
dependencies. That changes insertion complexity and construction allocation
patterns. It needs a separate reviewed scope and topology/equality checks; no
container replacement is implemented here.

## Narrow constructor required for ownership

An eventual source-owned constructor must accept checked immutable fixed inputs
and the real ledger, derive the complete storage plan itself, and reserve before
creating the backend, imports, memo maps or native-operation staging. It must
not accept a caller's graph-byte declaration, arbitrary callback, or already
built graph as proof of ownership. It must lower exactly once with the existing
genuine constructor semantics. A private non-Clone owner should contain the
actual graph and its ledger claim, expose only borrowed graph views, and drop
the graph before releasing the claim. Constructor scratch remains leased until
all backend/import/memo objects and outstanding native work retire, including
failure. Moves transfer the same owner; they do not create a new admission.

This graph owner alone cannot enable the paired producer. Complete native
operation staging, runtime/report/error storage, downstream source-graph
coexistence, and cleanup lifetime are still required. No Session or proving
hook is added by this census.

## Test-only graph payload owner

`source_graph/README.md` describes the implemented qualification constructor.
It reserves new decoded input storage and graph vector backing before decoding
or lowering; original tokens then follow the actual graph across callback
completion and later moves. The graph `Ceilings` formulas live in
`source_graph/bounds.rs` and are shared by this census and that constructor.
Its real graph-payload ownership does not close the other source/runtime
referents above. Lowering through that owner remains test-only and cannot
supply a production paired dispatch capability.
