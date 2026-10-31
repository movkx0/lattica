# Lossless RingCT transport v3

`compact::v3` adds a bounded entropy encoding for the unchanged native MatRiCT+
n10 proof. Across 32 fresh proofs, the median encoded size was **47,631.5 bytes**
(about 47,632 bytes), versus 47,923 bytes for v2 on the same cases. The median
per-case saving was **290.5 bytes / 0.606%**. The total reduction from the original
53,600-byte proof is **11.135%**.

The codec reconstructs the original proof byte for byte. It preserves every
original canonical coefficient value, ring size, transcript, native cryptographic
parameter, and proof-verification rule. All v1/v2 implementations and APIs remain
unchanged. This format is opt-in research transport; production acceptance is
unchanged, and no GPU or recursive-aggregation work is involved.

## Format selection and bounds

First compute the canonical [v2 encoding](COMPACT_ENCODING_V2.md). Its proof mode
byte is 0 (radix fallback) or 1 (Rice). Mode 2 is eligible only when native `c`
coefficients 0–3 and 128–131 are all zero. These zero values were observed in the
existing generator, but eligibility is checked for each input. Nonzero values
are preserved through the v2 fallback rather than discarded or rejected.

Build mode 2 only if it is **strictly smaller** than the v2 encoding for that
same input. Ties retain the v2 bytes. Consequently v3 is never larger than v2
for any canonical native input. The global bounds remain 13,766–51,579 bytes;
the minimum is a parser bound for canonical arrays, not an attainable size claim
for valid cryptographic proofs. The worst-case size retains v2's one-byte
overhead over v1, without adding another mode byte.

An encoder computes a candidate cap before entropy encoding. It stops and returns
the v2 representation when emitted bytes would exceed that cap. It does not
allocate an unbounded intermediate entropy stream.

## Mode 2 layout

| Part | Bytes |
|---|---:|
| Mode byte `02` | 1 |
| Compact native head | 11,204 |
| Low coefficient bits | 24,640 |
| Final rANS state, little endian | 4 |
| rANS normalization bytes | Variable |

The head preserves the original polynomial order. Remove the eight checked zero
coefficients from `c`, maintaining the order of the remaining 248 coefficients.
Encode the resulting base-167,770,241 integer in **847 little-endian bytes**.
Reject integers at least `167770241^248` on decoding and insert the eight zeros
at their original positions. The remaining six Q polynomials, five QHAT
polynomials, and 32-byte alpha use their unchanged v1 radix/raw encoding. Thus
the native 11,424-byte head becomes 11,204 bytes, 28 fewer than in v2.

For each signed original offset coefficient `d`, set
`s = d - (base - 1) / 2`, then `u = 2*s` for `s >= 0`, otherwise `u = -2*s - 1`.
Split `u` into quotient `u >> k` and its `k` low bits. The full original domain
remains supported; the probability model does not narrow it.

| Group | Polynomials | Original width | Original radix | k |
|---|---:|---:|---:|---:|
| x | 1 | 2 | 3 | 0 |
| z_out, z0, z1, z2 | 49 | 17 | 76,693 | 10 |
| f1 | 11 | 11 | 1,131 | 4 |
| zb | 10 | 17 | 76,693 | 10 |
| z | 8 | 24 | 12,425,173 | 17 |

Each polynomial has 256 coefficients. Pack low bits in original coefficient,
polynomial, and group order, least significant bit first. All polynomial lengths
are byte aligned, so this portion has exactly 24,640 bytes and no padding.

## Fixed probability tables and rANS

The integer cumulative frequency tables in
[`tools/compact_v3_models.json`](tools/compact_v3_models.json) are normative. Their
SHA256 is `0e45e3e72d7e0f3d9186fee1a287a9b0e11c4524b711650209023be72ac16112`.
The Rust codec uses identical constant arrays in `src/compact/v3/models.rs`.
No input supplies its own model, and the codec uses no floating-point arithmetic.
Changing these tables requires a different transport version.

The x table has frequencies `[54272, 5632, 5632]` for zigzag symbols 0, 1, 2.
The other tables approximate the existing sampler with
`sigma = B / sqrt(2*ln(2))`, using B values 7,525, 111, and 1,219,127. These are
compression model inputs, not new cryptographic parameters. The Python audit
reproduces the tables from these scales: reserve frequency one for every symbol,
normalize the remaining probability mass, take integer floors, and distribute
the remainder by descending fractional part, breaking ties by symbol index.
All original-domain quotient buckets have positive frequency.

Use byte rANS with total frequency `T = 2^16` and lower bound `L = 2^23`:

1. Initialize state `s = L` and visit quotients in reverse decoding order.
2. For a quotient with cumulative start `c` and frequency `f`, emit the low byte
   of `s` and shift it right by eight while `s >= 32768*f`.
3. Replace `s` with `floor(s/f)*T + (s mod f) + c`.
4. Serialize the final state in four little-endian bytes, followed by emitted
   normalization bytes in reverse order.

The decoder requires the initial state in `[L, 256*L)`. Find the quotient whose
CDF interval contains `s mod T`, then set
`s = f*floor(s/T) + (s mod T) - c`. While `s < L`, replace it with
`256*s + next_byte`. Combine the quotient with the corresponding low bits and
reject `u >= base`, including unused values in the final quotient bucket. After
exactly 20,224 coefficients, require state `L` and complete stream consumption.

The decoder rejects malformed lengths, states, radix blocks, out-of-range values,
truncation, and trailing data. Re-encoding the reconstructed native proof must
reproduce the complete input. This enforces unique mode selection and rejects a
larger mode 2 representation or an older representation when mode 2 is smaller.
All symbol counts, loops, allocations, and input sizes are profile bounded.

## Packet framing and ledger trust

The v3 packet magic is `LPQMCP03`. The remaining 80-byte header, native parameter
fingerprint, trusted context, standalone/reference modes, statement encoding,
and ledger membership rules are unchanged from [v1](COMPACT_ENCODING.md).
The proof occupies the remainder after a fixed prefix: 173,426 bytes for
standalone packets or 16,118 bytes for referenced packets, including the header.
Receivers explicitly select the packet version; v1/v2 APIs are still available.

Referenced packets preserve all twenty account indices in order. The receiver
must supply an independently trusted checkpoint and locally available membership
witnesses. Reported sizes exclude initial ledger synchronization and witness
transport. Decoding authenticates account membership and reconstructs the native
packet; it does not establish checkpoint trust, verify a spend, reject spent
serials, or replace ledger acceptance. Reordered authentic references can decode
to an altered ring, which the existing native verifier must reject.

## Evidence and tradeoffs

The original sixteen v2 artifacts were used for exploratory distribution and
model screening. Tables and codec implementation were fixed before generating **32 new proofs**
for validation, covering all ten ring positions, distinct contexts and setup
seeds, and balanced two-input/two-output values including zero, one, powers of
two, and `2^52 - 1`.

Every reconstructed proof passed both the C reference verifier and the independent
Rust verifier. Both rejected modified proofs, altered account references, and
duplicate serials. A separate Python integer/rANS oracle reproduced and decoded
all encoded proofs, reproduced both packet modes and ledger commitments, and
checked the preserved v1/v2 encodings. Corruption tests also updated artifact
checksums, demonstrating that checksums alone cannot hide the tested mutations.

| Representation | Minimum bytes | Median bytes | Maximum bytes |
|---|---:|---:|---:|
| Original native proof | 53,600 | 53,600 | 53,600 |
| v2 proof on matched cases | 47,892 | 47,923 | 47,960 |
| v3 proof | 47,607 | 47,631.5 | 47,678 |
| v3 standalone packet | 221,033 | 221,057.5 | 221,104 |
| v3 referenced packet | 63,725 | 63,749.5 | 63,796 |

All 32 cases selected mode 2. Per-case savings ranged from 272 to 299 bytes. These
are measured sample sizes, not universal valid-proof size guarantees. The small
additional savings are consistent with the exploratory coefficient distributions
being close to the current encoding's statistical limit; this is not a proven
lower bound on possible proof size.

Release CPU timings used one warmup and eleven timed calls per operation per
case. The median of per-case medians was 0.985 ms to encode and 2.033 ms to decode
v3, versus 0.691 ms and 1.438 ms for v2. Encoding/decoding is about 0.3/0.6 ms
slower. These measurements include codec allocations but exclude native proof
generation, cryptographic verification, ledger construction, and disk I/O.
They do not establish recursive workflow throughput or a proving speedup.

Validation passed 41 native-feature library tests, 37 no-native library tests,
and five Python oracle tests. Coverage includes exact output-cap/tie behavior,
all guarded zero positions, original-domain extremes, the last quotient bucket,
noncanonical modes and streams, malformed-input mutations, packet framing,
ledger admission, and preserved v1/v2 behavior.

## Reproduction

```sh
cargo test --locked --offline --no-default-features --features native-matrict --lib
cargo test --locked --offline --no-default-features --lib
cargo run --release --locked --offline --no-default-features --features native-matrict --bin pq-ringct-compact-v3-measure -- /tmp/ringct-compact-v3-artifacts
python3 tools/compact_v3_audit.py /tmp/ringct-compact-v3-artifacts
RINGCT_V3_MEASUREMENT=/tmp/ringct-compact-v3-artifacts python3 tools/test_compact_v3_audit.py -v
```

Use a new output directory. Checks ran with a 4 GiB memory limit, 3 GiB memory
high-water threshold, zero swap, 200% CPU quota, two build/Rayon threads, and a
128-task limit. The enclosing `compact-proof-v3-20261030` directory contains the
source-complete checkpoint, exploratory evidence, patch, complete source archive,
validation logs, public proof artifacts, independent audit, and `VALIDATION.json`.
