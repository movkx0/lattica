# A046 synthetic schema/codec differential admission

This test-only subtree builds a deliberately invalid 54-column upper schema.
It does not create an AIR, Program, registry, real root, GPU/runtime, verifier or
proof. It independently exercises the concrete registered encoder/decoder, but
does not independently establish the maintained template's actual lookup packing
or fit of a real proof. A045's source derivation still requires its own review.

The sole entry is through two focused tests under the already gated A045 test
module. No production path, CLI selector, output adapter or artifact action is
added. The frozen A045 model is unchanged except for test-subtree wiring.

## All-live ownership

Before constructing a fixture or packet, `phase` admits one original-ledger
PhaseScratch reservation for:

- 64 MiB cumulative fixture Vec backing, including all nested element headers;
- another 64 MiB cumulative decoded vectors plus canonical re-encoding;
- two independent full 2 MiB packet capacities, including unused suffixes;
- the fixed typed schema, caller, error, census, report and codec forwarding
  frames described below.

The fixture allocator charges `count * size_of::<T>()` before each fallible exact
capacity request. It refuses any returned excess capacity and never refunds a
construction charge. Each vector starts empty, so there is no growth overlap.
On a returned failure its partly constructed values die while the enclosing
original phase reservation is still held. Closure captures and fixed arrays
are stack values; no collect/clone or detached raw proof access exists.

The successful decoded proof coexists with the original fixture and both
packets. It is destroyed before the second decode call; the whole decoder quota
remains live, including its cumulative canonical-buffer charge. The original
fixture and packets remain held for that second call. No second live decoded
proof is admitted. An unexpected second success is immediately destroyed and
fails the test. A same-input decoder boundary probe is explicit synthetic test
behavior, not retry or fallback after any actual proof dispatch.

The phase reservation is declared before every payload and drops after them on
success, returned errors and ordinary unwinding. Explicit success destruction
also occurs before returning the fixed report. A separately admitted driver
caller covers that report, its error variant, envelope arrays, snapshots and
printing after phase return. Tests check restoration of the driver's current
charge after every case and zero current categories after driver destruction.
Ledger bootstrap and test-harness operation are outside the tested phase. These
are requested-source-storage checks, not allocator/process/GPU RSS or a physical
worker admission certificate.

## Fixed forwarding census

`claims::schema_frame` adds the complete sizes of every concrete schema value
and returned Result: full BatchProof, commitments/opened-values/instances,
MerkleCap, opening/Fri/query/step, scalar/extension/arrays, optional/nested vector
headers, authentication tuple and terminal. Opaque terminal element size comes
from the same never-called typed selector mechanism as A045. Results are added
to their values rather than treated as a union. No optimization, move elision,
slot reuse or borrowed-proof size discount is assumed.

The source-pinned `codec/proofs/schema.rs` permits only scalar/array, Vec,
Option, pair and the named structs. There are no arbitrary Deserialize callbacks
or new variant containers. `Storage::payload` invokes one schema Seed under one
Guard. A recursive compound forwards through the concrete seed/Decode, Guard,
Postcard deserializer, Visit, concrete visitor, sequence Access, wrapper Seed,
and child Seed/Decode. Sixteen complete additive frames per level cover this
chain, the API/Storage caller and the corresponding fixed-u64 serializer/derived
forwarding. All 32 permitted compound levels are charged simultaneously, even
though this fixed schema uses fewer. Fixture construction and the capacity census
have shallower named recursion and share none of the reserved schema values.

Each forwarding level also adds 128 machine words for all source-fixed control
fields together: Storage's four usize counters plus rejection flag, Attempt's
reference, Guard/Visit/Seed/Access references/depth/encoding/sequence metadata,
Postcard Slice serializer/deserializer and SeqAccess cursor/counts, scalar-array
and option visitors, wrappers, iteration/count state and the fixture's bounded
closure captures. This is separate from every full concrete value/Result layout.
Pin these exact helper implementations; changed source requires a fresh census.

The outer phase additionally charges sixteen copies of all fixture/census,
reservation/ledger/snapshot/requirements, complete codec results, fixed report,
timer/error, loop and byte-buffer return types, plus 64 KiB for bounded core
diagnostic formatting and byte helpers. The independent driver adds sixteen
copies of its full report/envelope/iteration/ledger/result/format-argument layouts
and another 64 KiB. All totals and products are checked; all requirements remain
inside the original 32 GiB host allowance and request zero device bytes.

## Differential evidence and its limits

Every height from 8 through `2^20` uses maximal canonical field words, except
the transparent terminal which is zero. The encoder's actual length must equal
A045's bound for this exact upper fixture. A separate traversal sums actual
returned Vec capacities and Merkle cap backing, verifies exact capacity at every
node, and checks fixture construction accounting and A045's decoded-vector sum.
This traversal does not call the layout algebra. The successful exact decoder
allowance is that actual backing plus encoded length excluding the eight-byte
magic. The canonical re-encoding uses another full packet and must equal the
original used bytes. A second test compares zero/maximal words at both endpoint
heights, consistent with the locally trusted fixed-u64 codec.

After successful decoded destruction, decode the identical bytes with the same
bound minus one. Preserve the returned `postcard::Error` variant and explicitly
report `short_failure_cause_classified=false`. The core API maps budget,
allocation and serde failures into shared generic variants; this test cannot
claim a typed storage-only rejection. Its failure cannot earn mutation coverage
or later artifact acceptance. Core `bounded_decoded_proof_storage` diagnostics
remain available to the coordinator as separate observations, not a substitute
typed outcome. The expected successful canonical charge and actual capacity sums
are printed so those observations can be compared externally.

Each `transport_schema_case` marker keeps schema-only true and real-proof fit,
artifact completion and complete RingCT workflow false. Timers describe synthetic
codec calls only. Two authored tests are not executed evidence until the
coordinator compiles and runs them serially. All existing 2 MiB/64 MiB limits,
cryptographic settings and production acceptance remain unchanged.
