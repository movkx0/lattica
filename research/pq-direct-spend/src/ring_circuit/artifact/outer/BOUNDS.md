# Bounded single-child outer artifact transport

This research-only helper is selected solely by the existing
`ring-recursive-outer-experiment` feature. Production transaction acceptance,
child artifact bytes, the native proof codec and all security parameters remain
unchanged. The helper returns an unverified decoded proof to the enclosing
single-child qualifier; it cannot construct expected source or a verifier key.

## Domain and expected-source checks

The envelope retains the existing 212-byte header layout and 2 MiB maximum
inner payload. `LDOUTR01` plus the domain-separated outer profile digest identify
exactly one outer proof of one independently verified direct-ring child with
four public words. The digest contains the existing complete child local-profile
digest, which commits to the unchanged crypto/machine parameters. The manifest
and program ID remain descriptive claims, checked independently after decode.
Child decode explicitly retains its original `LDRING01` domain. Exchanging just
magic, profile digest, representation, context, public words or descriptor is
not a route to trusted state.

The expected context, representation and public words are copied only when the
private numerically verified child is consumed into `ExpectedRecursiveSource`.
No untrusted packet can create that owner. Encoding contains no program, cap,
verifier key or public AES matrix. `decode_expected` checks outer domain,
canonical header words, expected profile/context/public/complete descriptor
and exact packet length before bounded proof decode. The independently
reconstructed and freshly registered outer program must still match the
original complete descriptor before numerical CPU acceptance. The decoded proof
passes the existing four public and one restored opening mutation probes.

## Reservations and ownership

Before outer dispatch, `storage_for_shape` admits `required_host_bytes()` plus
the unchanged 1 MiB caller. The helper reserves:

- the maximum of the existing 64 MiB retained-proof slot and cumulative decoder
  storage limit (currently the same bound);
- the full header plus 2 MiB encoded output capacity, including spare capacity;
- the unchanged 16 KiB codec allowance;
- the additive `TRANSPORT_FIXED_BYTES` source census for header, descriptor,
  proof/result/catch/move owners, Vec headers, reports, context, representation,
  public arrays, timers and fixed scalar/parser frames.

The last term is a new phase reservation inside the existing 32 GiB worker,
not a larger codec, caller or worker allowance. Shared codec wrapper frames are
also added to its compile-time 16 KiB census without removing original terms.
Persistent transport metrics and larger private-source owners are included in
the unchanged recursive 192 KiB and complete caller 1 MiB censuses through the
actual source types. Those exact censuses must pass before proof qualification;
source arithmetic or formatting is not evidence that the compiled types fit.

After the actual proving session retires, encoding borrows the sole original
proof and fallibly allocates its full output. Encoding failure drops both.
Success explicitly destroys the original proof before decoder allocation.
Bounded decoding charges the actual full input capacity and cumulative
allocation/canonicalization quota. The packet is destroyed before the decoded
proof leaves the helper. No proof clone overlaps decoding. Panic is caught as
a terminal transport refusal, with normal ownership destruction; the outer
caller attaches its previously obtained proving terminal. No GPU owner is
live during this phase. Serialization recheck scratch is sequential with the
existing CPU verifier phase; that phase keeps its original independent scratch
and proof reservation. No retained state or raw proof escapes the qualifier.

## Reports and qualification limits

Successful outer reports add `artifact_transport` with encoded length, decoded
retained-proof bytes and transport elapsed nanoseconds. The enclosing
`artifact_roundtrip` becomes true only after independent CPU verification and
all existing typed negative probes succeed. `proving.total_ns` now includes
transport, while backend proving/setup stage durations remain unchanged.
`storage.artifact_roundtrip_peak_bytes` includes the unchanged caller and all
phase reservations. A canonical decoded shape alone never earns verification
or proof-generation credit.

Five authored focused tests use invalid zero-filled proof shapes only for codec
and guard checks: outer/child domain separation, expected claim mismatch,
canonical/header/geometry guards, exact boundary admission and canonical
round-trip bytes, and spare input capacity/trailing/truncation/wrong payload.
The existing genuine outer GPU test is updated to require successful transport,
source reconstruction, CPU acceptance, mutations and original terminal cleanup.
No GPU result is established by these test sources.

This is an in-memory serialization/decode round trip. It writes no external
artifact file and performs no storage-system audit. Full transaction/final
aggregation, N3/N4 workflows, matched complete-workflow performance and
qualified security review remain separate requirements. C performed only
isolated rustfmt parsing, source inspection and hashes; the coordinator owns
all builds, tests, exact caller measurements, guards and GPU qualification.
