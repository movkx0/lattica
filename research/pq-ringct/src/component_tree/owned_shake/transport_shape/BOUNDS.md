# Fixed SHAKE-root registered transport geometry

This module is an isolated prerequisite for a future artifact action. It has
no action, encoder, decoder, proof, verifier, runtime, ledger token, acceptance
capability or dispatch path. The coordinator must wire the module separately.
Authored pure geometry tests are not executed qualification evidence.

The sole public-to-parent calculation uses the locally trusted wide profile and
all 18 row heights from `2^3` through `2^20`. Its statement has 46 public values.
Every height must satisfy all transport caps before the report returns. There is
no splitting, larger cap, weaker security, fallback, retry, or post-proof fit
decision. A runtime profile comparison refuses drift in public count, lanes,
opcode bits, row ceiling, field layouts, encoding, query/security constants and
byte caps. The capsule's immutable dependency pins additionally bind the source
derivations below. Changing any pinned schema/AIR/packing source requires review
and a new census; checking numerical profile constants alone cannot qualify a
source change.

## Geometry derivation

`machine/verifier/template.rs::batch_from_geometry` supplies the maintained
registered BatchProof schema. `machine/air.rs` has main width 94 and preprocessing
width `8 * LANES + 2 * EXT_LANES + 2 = 200` at 23 lanes and seven extension lanes.
The AIR's maximum constraint degree is eight. The unpacked lookup degree is at
most three. The maintained hiding rule in `machine/symbolic/mod.rs` therefore
uses `log_chunks = ceil(log2(8)) = 3`; `machine/analysis.rs` gives 16 quotient
chunks. No symbolic graph, AIR instance or shape template is allocated here.

The lookup-width bound is derived without measuring a sampled registry. The AIR
emits four consecutive bus interactions per lane, followed by the 46 public
interactions. All use the same global bus. Each of the 92 lane tuples has maximum
degree one and multiplicity at most three. In a group of `t` lane interactions,
`machine/symbolic/lookup.rs::degree` is at most `max(t + 1, t + 2)`. Thus every six
consecutive lane interactions fit the packing degree of eight, and the greedy
same-bus packer produces at most `ceil(92 / 6) = 16` lane groups. Public tuples
have degree zero; their multiplicity is a degree-one preprocessing coefficient
times a degree-two bank selector, hence degree at most three. They can require
at most one additional group, regardless of the final lane group's occupancy.
The bound is therefore 17 packed groups plus one running-sum extension column,
or `3 * (17 + 1) = 54` base columns. This intentionally avoids relying on the
tighter observed width or on treating public multiplicity as degree two.

For `degree = log2(rows) + 1` and `log_lde = degree + 4`, the schema has:

- Four commitments, including two present Options; cap roots number
  `2^min(log_domain, 6)`.
- One opened-values instance: 94 trace extension values, no trace-next values,
  200 preprocessing extension values, no preprocessing-next values, 16 quotient
  vectors of three extension values, three random extension values, and two
  permutation vectors bounded by 54 extension values each.
- Five hiding rounds with matrix counts `[1, 1, 16, 1, 1]` and point counts
  `[1, 1, 1, 1, 2]`. Each point has four extension randomizers except the
  preprocessing round, which has zero.
- `degree` FRI caps and scalar commit witnesses, 128 queries, one extension
  final-polynomial value, and one scalar query witness.
- Each query has five input openings. The matrix widths are
  `[3, 94, 3, 200, 54]` plus four hiding columns except preprocessing. Each
  matrix has four scalar salts; each round has a digest path of length
  `log_lde.saturating_sub(6)`.
- Each query has `degree` binary FRI steps. Each contains a one-byte `log_arity`,
  one extension sibling, four scalar salts, and a digest path of length
  `(log_lde - layer - 1).saturating_sub(6)`.
- One present lookup terminal and one `usize` degree entry.

Lower actual packed widths produce no larger wire, backing or guard usage.
The field values do not affect encoded size under the fixed-u64 codec.

## Encoding and decoder accounting

`codec.rs`, `codec/fixed_u64.rs`, `codec/proofs.rs` and
`codec/proofs/schema.rs` define the actual wire and allocation behavior. The
registered magic is `LBV2RP02`. Scalars and `usize` use eight raw bytes; u8 is one
byte. Postcard sequence length prefixes remain unsigned varints, so 128 queries
need a two-byte length. Structs, tuples and fixed arrays have no wire prefix;
Options use one discriminant byte. Extension fields are a two-field struct
containing a stack-only three-scalar array and unit marker.

The layout algebra separately accumulates encoded bytes, requested Vec backing,
nonzero allocation counts, logical guard items, largest sequence and compound
depth. Parent Vec backing includes complete element sizes, including embedded
child Vec headers. Descendant backing is additional. Typed, never-called field
selectors obtain opaque actual Vec element sizes from `BatchProof<Config>`;
no proof is created to discover a layout. `Storage::reserve` uses exact requested
capacity and refuses larger actual capacity. Zero-length vectors add their
wire length and compound depth, but no backing or allocation.

The fixed-u64 eight-byte scalar adapter bypasses the outer logical sequence
guard: one field word is not charged as eight logical items. The census follows
the concrete decoder seeds, including array/struct field counts and optional
compound depth. It checks sequence length at most 256, compound depth at most
32, and cumulative logical items at most `2^20`.

The unchanged **2 MiB inner limit includes its eight-byte registered magic**.
The decoder strips that magic and allocates one additional exact-size canonical
re-encoding buffer. Its **64 MiB allowance is cumulative decoded Vec backing plus
canonical bytes**, not the maximum of the two. That canonical charge remains
consumed even after its buffer is destroyed. All additions, products, shifting,
layer subtraction and resulting cap checks use checked or bounded arithmetic.

This calculation does not represent a full artifact or worker bound. A future
action must separately reserve its versioned 46-public root header, original
retained key/proof and runtime, encoded transport buffer, fixed decoded Proof,
all caller/result/report frames, independent verifier, allocator/process
overhead, and cleanup overlap. Decoding creates an additional proof while the
original remains live. No credit is taken for replacing original storage with
decoded storage. The four-public direct-ring 212-byte header is inapplicable.
No report authenticates a key, source, transaction context or dispatch identity.

## Required qualification

The authored tests cover all 18 heights, local profile/height refusal, varint
boundaries, scalar-vs-guard accounting, extension stack decoding, nested Vec
headers, empty vectors, additive canonical storage, exact caps, guard limits and
integer overflow. The coordinator must compile and run them serially after
module wiring and peer review. Before an artifact action is enabled, separately
cross-check the census against admitted source-derived template/schema encodings
and actual decoder allocation reports, then qualify actual round trips, negative
inputs, numerical verification and complete destruction under original-ledger
admission. No such execution or proof/artifact claim is made by this module.
