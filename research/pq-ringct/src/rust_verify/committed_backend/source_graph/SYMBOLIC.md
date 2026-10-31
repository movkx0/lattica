# Symbolic constructor scratch ownership

The test-only `Construction::new` now includes symbolic container storage and
the existing pinned collection model in its original PhaseScratch reservation.
The real ledger admits this together with input and graph storage before
decoding or constructing the backend. A caller cannot supply this size or
attach a token to preexisting symbolic inputs.

`growth_reservation` now covers both graph/decoder growth and this symbolic
scratch. It stays with the original constructor, then `PendingGraph`, until
imports, generic temporaries, memo/dependency containers and the native callback
have retired. The GPU qualification wrapper also destroys the returned report
before `after_callback` releases that reservation. Failure drops the backend
and imported containers while the original reservation remains live. The
successful `OwnedGraph` keeps its separate graph and decoded-input tokens.

## Fixed source inventory

These counts come from `import.rs`, `generic::verify_relation`, and the whole
polynomial overrides in `backend.rs`. Specialized backend overrides mean the
generic scalar multiplication/NTT fallback implementations do not execute.

| Owner | Polynomial arrays | Heap container descriptors |
| --- | --- | --- |
| Symbolic statement | 198 canonical | ten account pairs, two recipient rows, two coin rows |
| Symbolic proof | 9 canonical, 78 signed | two `z_out` rows |
| Parameters | 185 canonical | 7 + 4 + 29 rows |
| Generic relation | 238 canonical, 12 signed | 2 `z_out`, 2 `w_out`, 10 `t_in`, 10 `p` rows |

The generic relation's canonical arrays are `z_out18, z0 9, w_out8, w0 4,
t_in50, f_ntt12, f_qhat12, z1 11, z2 11, w1 4, w2 4, h3, hx3, alpha2,
zb10, g_qhat12, a5, gamma0 4, gamma1 4, p40, z8, e4`. Its signed `f`
has 12 arrays. Together the four rows above have 720 heap polynomial-reference
arrays. Inline polynomial fields in the statement/proof owners are charged
with those owners' actual `size_of` and are not counted a second time as heap.

The model charges three times every logical heap count. Every source Vec in
this symbolic layer starts empty, is created at an exact capacity, or collects
from a borrowed fixed slice/range. No arbitrary `reserve`, caller capacity,
owned native allocation reuse, or clone of a preexisting oversized Vec is in
this layer. For pinned Rust 1.96, normal growth is
`max(2*old, required, minimum_nonzero)`. All polynomial elements exceed 1024
bytes and have a minimum of one; all heap descriptor lists have at least two
elements, with exact collection/allocation or a minimum of four. Three times
the final logical count therefore covers retained backing and old/new overlap.
In particular, `f` starts at one array and extends directly to twelve while
the old single-array allocation may still exist. Maxima are summed without
lifetime overlap credit. Named top-level Vec descriptors and generic parameter,
statement and proof owners are additionally charged inline.

After the preceding reservation, `check_imported_storage` measures the actual
imported arrays and every nested capacity without allocation. This checks source
drift; it is not admission based on a caller's already allocated container.

## Shared collection model

`source_graph::collections` contains the unchanged `Tree` and `Collections`
formulas formerly in `construction_census::btree`. The old qualification tests
import that exact shared model and keep their test paths. All three memo maps,
one dependency traversal's two trees and its todo-vector growth, and the inline
backend are included before construction. Returned dependency-ID vectors stay
in the separate graph-payload bound. No second copy of either formula exists.

The coordinator accepted the pinned BTree allocation audit, including full
entry ceilings, cascading splits, duplicates, iteration and destruction. See
[BTREE.md](../construction_census/BTREE.md) and the linked qualification record.
That audit is evidence for these collection allocations, not a native-runtime
or whole-process memory bound. The new combined ownership code has authored
tests; the coordinator owns its execution and final receipt audit.

## Remaining limits

This increment owns symbolic heap construction and known inline owner sizes.
It does not establish a compiled stack high-water bound or allocator overhead.
Raw parameter/sampler results, native-to-ID collectors that may reuse a larger
owned allocation, arithmetic/crypto adapter staging, runtime/context/driver
objects, original diagnostic creation, outer reporting, and downstream graph
authentication remain separate obligations. Native raw matrices can coexist
with their symbolic conversions and must be charged independently.

No production constructor, native dispatch permit, recursive proof, benchmark,
or PairedV1 enablement is added. All limits are unchanged. Do not schedule full
graph GPU proving from this prerequisite.
