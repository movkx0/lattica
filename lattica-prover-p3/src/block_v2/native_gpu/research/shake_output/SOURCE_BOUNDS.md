# Fixed native SHAKE output ownership

This release Linux/x86_64 module requires the original RingCT ledger and the
bounded GPU/stream feature prerequisites. It allocates no proof and starts no
GPU operation. The future closed producer is the only caller of the private
completion method. There is no public supplied-proof attachment or extraction.

The pure storage inventory specializes the existing research
`NativeRetentionShape::heap_bound` to 517/518 columns, 4096 through 2^20 rows,
216 public values, the existing cubic field and hiding FRI profile. It reserves
all nested vector/cap capacities before generation using at most 32 quotient
chunks, 128 queries, binary FRI and four hiding codewords. The actual fixed
source must return exactly 16 quotient chunks and the next-row opening. A
source canary compares the complete inventory body to the existing research
implementation. Temporary PCS/opening construction remains separately charged.

The proof reservation remains exactly 64 MiB. New opaque ownership headers,
inline public fields and readback/conversion are additive to the nested proof
inventory, with overlapping copies charged conservatively. Research-specific
request/key/child headers must independently fit the same ceiling before graph
integration; this module does not claim to own those objects. It separately
requires the exact `FixedProofReportStorage` reservation before any Run/report.

`ShakeOutputPlan::claim` consumes the original non-cloneable proof and report
reservations from the same ledger and rejects unrelated categories, nonzero
device claims and one-byte budget changes. Its pending owner retains those
claims until the fixed producer finishes or the claim is destroyed after
failure cleanup. It is an empty output slot, not dispatch authority.

The closed completion audits actual nested capacities and validates the actual
GpuRequired stage report. It returns only an opaque `OwnedShakeProof`: artifact
and report fields are destroyed before their original reservations. Readonly
artifact/report/reservation borrows allow independent CPU verification without
extracting payload or token. Successful stage coverage is a native component
receipt, not complete transaction or paired graph qualification.

Five source/ownership tests and two report mutation tests are authored. No build,
test execution, GPU proof, independent numerical verification, benchmark or
whole-workflow promotion is claimed by this capsule. The coordinator must run
the focused tests and actual fixed producer qualification serially.
