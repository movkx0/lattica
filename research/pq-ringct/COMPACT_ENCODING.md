# Lossless native RingCT transport, version 1

This module packs the existing MatRiCT+ n10 proof and public statement without
altering a coefficient, transcript, bound, security parameter, candidate pair,
input, output, or serial. Decoding recovers the original canonical native bytes.
It does not construct a recursive proof or measure a recursive proving speedup.

## Native proof encoding

Each polynomial has 256 coefficients. The codec treats the original unsigned
coefficient encoding as a digit `a[i]` in its exact allowed radix `b`, then writes
`sum(a[i] * b^i)` as a fixed-length little-endian integer. Signed coefficients
retain their existing offset representation. No probability distribution or
typical coefficient size is assumed.

| Field group, in native order | Polynomials | Radix | Bytes per polynomial |
| --- | ---: | ---: | ---: |
| c, v, v1, v2 | 7 | 167,770,241 | 875 |
| b | 5 | 3,489,661,057 | 1,015 |
| alpha | — | raw 32 bytes | — |
| x | 1 | 3 | 51 |
| z_out, z0, z1, z2 | 49 | 76,693 | 520 |
| f1 | 11 | 1,131 | 325 |
| zb | 10 | 76,693 | 520 |
| z | 8 | 12,425,173 | 755 |

The total is **51,578 bytes**, saving 2,022 bytes (3.77%) relative to the existing
53,600-byte native proof. Alpha is copied unchanged. The native verifier still
consumes the original 53,600-byte encoding and the existing native parameter
fingerprint still describes that inner encoding.

Encoding rejects coefficients outside the original canonical ranges. Decoding
rejects integers at least `b^256`; it never reduces such integers modulo that
bound. Fixed lengths prohibit truncation, trailing data and alternate padding.
The converter uses at most 256 `u32` limbs per polynomial, with bounded `u64`
multiplication/division and no general-purpose heap bigint.

## Statement encoding

The standalone statement contains a raw 32-byte setup seed, 198 polynomials over
Q, and two raw 32-byte serials. Each Q polynomial occupies 875 bytes instead of
1,024. This yields **173,346 bytes**, down from 202,848. Its original ordering,
including all 20 accounts in ten pairs, remains intact.

## Packet framing

Both packet modes use this fixed 80-byte header:

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `LPQMCP01`, compact transport version 1 |
| 8 | 2 | Original native scheme, little-endian u16 |
| 10 | 2 | Original native profile version, little-endian u16 |
| 12 | 32 | Original native parameter fingerprint |
| 44 | 32 | Context, compared with the receiver's expected context |
| 76 | 4 | Mode, little-endian u32: 1 standalone, 2 referenced |

All fields, including the exact mode-specific total length, are checked before
body decoding. The existing `NativePacket` codec remains unchanged and does not
accept this new framing accidentally.

Mode 1 appends the compact statement and compact proof, for **225,004 bytes**.
It is self-contained to the same extent as the original research packet.

Mode 2 appends:

1. The 32-byte ledger checkpoint identifier.
2. The unchanged 32-byte setup seed.
3. Twenty u64 little-endian ledger indices, in original ring order (160 bytes).
4. The 18 non-ring statement polynomials (15,750 bytes).
5. Both original serials (64 bytes).
6. The compact proof (51,578 bytes).

The total is **67,696 bytes**. No ring entry is removed or silently deduplicated.
Repeated indices, if present in an original ring, preserve the original statement;
this transport does not select an anonymity policy for callers.

## Authenticated account resolution

The receiver passes a `LedgerCheckpoint` obtained independently from trusted
ledger state. It binds the network/domain identifier, public setup seed, account
count, tree root and native profile. A sender-supplied root or a newly supplied
`LedgerSnapshot` is not automatically trusted.

`LedgerSource` returns untrusted account data plus an authentication path.
Decoding verifies every path locally against the expected checkpoint and rejects
missing accounts, out-of-range indices, incorrect path length, altered accounts,
different setup seed, context, profile or checkpoint. Encoding checks that the
references reproduce the original ordered ring. Decoding preserves reference
order; native proof verification rejects a reordered or substituted ring.

The account tree is a binary SHA3-256 Merkle tree. `H(tag, parts...)` means
SHA3-256 of the exact tag (including its final NUL), the 32-byte native parameter
fingerprint, and the following fixed-width parts in order:

| Object | Tag suffix after `lattica/ringct/compact-ledger/` | Parts |
| --- | --- | --- |
| Scope | `scope/v1\0` | domain[32], setup_seed[32] |
| Account leaf | `account/v1\0` | scope[32], index_le_u64, canonical_account[9216] |
| Empty padding leaf | `empty/v1\0` | scope[32], index_le_u64 |
| Branch | `branch/v1\0` | scope[32], height_u8, left[32], right[32] |
| Checkpoint ID | `checkpoint/v1\0` | domain[32], setup_seed[32], account_count_le_u64, root[32] |

The tree pads to the next power of two. Branch heights start at one above the
leaves. Account indices determine sibling orientation. A membership witness has
exactly `ceil(log2(account_count))` siblings; depth is capped at 32. The convenience
in-memory store is capped at 65,536 accounts; external stores may serve larger
checkpoints up to 2^32 accounts.

The checkpoint and all reference bounds are checked before decoder allocations
or account lookups. Membership verification does not prove that a serial is
unspent, authenticate a chain's consensus, implement recipient delivery, or
replace native proof verification. Standalone packets retain the original
caller's obligations for public setup policy.

The smaller wire size assumes account data and authentication paths are already
available locally. First-time ledger synchronization, remote fetching, and path
transport are additional costs. A receiver lacking this data can use mode 1.
This is an explicit research integration boundary, not a production ledger
migration.

## Validation and measurement

From this crate, with the project's Rust toolchain and dependencies available:

```sh
cargo test --locked --offline --no-default-features --features native-matrict --lib compact::tests
cargo run --release --locked --offline --no-default-features --features native-matrict --bin pq-ringct-compact-measure -- /tmp/ringct-compact-artifacts
python3 tools/compact_packet_audit.py /tmp/ringct-compact-artifacts
```

The measurement command refuses an existing output directory. It generates
three fresh native proofs, checks exact packet round trips, verifies each result
with both the C reference and Rust verifier, and checks proof, reference and
duplicate-serial mutations. It emits public artifacts, fixed sizes and CPU codec
timings (11 measured calls after an untimed warm-up for each operation).

The independent Python audit uses Python integers, rather than the Rust limb
algorithm, to reproduce every encoded polynomial and both packet modes. It also
independently reconstructs the ledger roots/checkpoint identifiers and checks
artifact hashes. It does not independently implement the lattice proof relation.

Codec timings include allocation and membership checking where applicable.
They exclude native proof generation/verification, ledger construction and disk
output. All these operations are CPU-only and do not qualify GPU workflow speed.
