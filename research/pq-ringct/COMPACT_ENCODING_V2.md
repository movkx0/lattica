# Lossless RingCT transport v2

`compact::v2` reduces the transport size of the existing MatRiCT+ n10 proof by
encoding its signed response coefficients with adaptive Golomb–Rice codes. It
reconstructs the original **53,600 bytes exactly** before either native verifier
runs. Ring size, equations, coefficient bounds, transcript, cryptographic
parameters, and production acceptance are unchanged. All v1 APIs and wire bytes
remain available. This is an opt-in research transport format.

## Proof framing

Mode 0 is byte `00` followed by the complete 51,578-byte [v1 radix
proof](COMPACT_ENCODING.md), for 51,579 bytes. This bounded fallback supports the
full original coefficient domain and costs one byte more than v1.

Mode 1 is byte `01`, five parameter bytes, the 11,232-byte v1 radix head, then a
single Rice bitstream. The head consists of seven base-167,770,241 polynomials,
five base-3,489,661,057 polynomials, and the unchanged 32-byte alpha. Its native
representation occupies 11,424 bytes. Every polynomial has 256 coefficients.

The five parameter bytes correspond to these consecutive signed groups:

| Group | Polynomials | Original bit width | Original radix |
|---|---:|---:|---:|
| x | 1 | 2 | 3 |
| z_out, z0, z1, z2 | 49 | 17 | 76,693 |
| f1 | 11 | 11 | 1,131 |
| zb | 10 | 17 | 76,693 |
| z | 8 | 24 | 12,425,173 |

For an original offset coefficient `d` in `[0, radix)`, let
`s = d - (radix - 1) / 2`. Its unsigned zigzag value is `2*s` for nonnegative
`s`, otherwise `-2*s - 1`. This mapping covers the entire original domain.

For each group independently, select `k` in `[0, original_width)` minimizing
`sum((u >> k) + 1 + k)`. Ties use the smallest `k`. Encode each value with
`u >> k` one bits, a zero terminator, then the `k` remainder bits in least
significant bit order. Pack the stream from the least significant bit of each
byte. There is no padding between values, polynomials, or groups. Unused high
bits of the final byte are zero.

Select mode 1 only when its total **padded byte length** is strictly less than
51,579 bytes. Otherwise select mode 0, including ties. The encoder computes the
size before allocating the stream, and the writer cannot extend that allocation.

Decoding rejects unknown modes, wrong lengths, invalid parameters, noncanonical
radix blocks, out-of-domain coefficients, truncated or excessive unary runs,
trailing bytes, and nonzero padding. It recomputes optimal parameters and mode
selection to reject alternate representations, including unnecessary fallback.
All loops and allocations have fixed profile/packet bounds. The proof parser
accepts lengths only in `[13,766, 51,579]`; the minimum is a bound for canonical
coefficient arrays, **not a size claim for cryptographically valid proofs**.

## Packet framing and trust

The v2 packet magic is `LPQMCP02`. The remaining 80-byte header layout, profile
fingerprint, trusted context, standalone/reference modes, statement encoding,
and authenticated ledger rules are exactly as documented for v1. The two codecs
reject each other's packet versions. The native profile fingerprint describes
the reconstructed proof, so it remains unchanged.

The proof is the remainder after a fixed prefix; there is no additional length
field. The standalone prefix including the header is 173,426 bytes; the
referenced prefix is 16,118 bytes. Decoders check the total length against these
prefixes plus the proof minimum/maximum before accessing the payload.

Referenced packets preserve the order of all twenty account indices, representing
ten candidate pairs. The receiver supplies an independently trusted checkpoint
and locally available account membership witnesses. The checkpoint binds the
domain, setup seed, account count, Merkle root, and native profile. Initial ledger
synchronization and authentication-path transport are excluded from reported
packet savings. Reordered authentic references can reconstruct a different ring;
the native proof verifier must reject that altered statement.

Decoding alone does not verify a proof, check spent serials, establish checkpoint
trust, or authorize a transaction. Run the existing C or independent Rust verifier
on the reconstructed bytes and apply the existing ledger acceptance rules.

## Measured validation

The 2026-10-30 CPU measurement generated 16 fresh proofs with distinct contexts
and setup seeds, covering all ten ring positions and values including zero,
one, powers of two, and `2^52 - 1`. Every input/output pair balances exactly.
Both native verifiers accepted byte-exact reconstruction from both packet modes
and rejected changed proofs, changed references, and duplicate serials.

An independent Python integer/Rice implementation reproduced and decoded every
proof, reconstructed both packet modes, and reproduced every ledger commitment.
Oracle tests reject corrupted artifacts even after their checksums are updated.

| Representation | Minimum bytes | Median bytes | Maximum bytes |
|---|---:|---:|---:|
| Original native proof | 53,600 | 53,600 | 53,600 |
| v1 proof | 51,578 | 51,578 | 51,578 |
| v2 proof | 47,901 | 47,932 | 47,958 |
| v2 standalone packet | 221,327 | 221,358 | 221,384 |
| v2 referenced packet | 64,019 | 64,050 | 64,076 |

The measured median proof reduction is **10.57% from native** and **7.07% from
v1**. All 16 samples selected Rice parameters `[0, 13, 7, 13, 20]`; the codec
still selects them from each input and retains the full-range fallback.

Release CPU codec timings used one warmup and eleven timed calls per case. The
median across the sixteen per-case medians was 0.719 ms for v2 proof encoding and
1.393 ms for decoding, compared with 0.628 ms and 4.303 ms for v1. These calls
include allocations, and packet timings additionally include membership checks.
They exclude generation, cryptographic verification, ledger construction, and
disk I/O. This is a transport measurement; no recursive/GPU workflow throughput
claim follows from it. No GPU work was launched.

Validation includes 30 native-feature library tests, 26 no-native library tests,
three Python oracle tests, and the sixteen fresh-proof measurements. The test
suite covers full-domain extremes, exact mode-size ties, nonminimal and tied Rice
parameters, truncation/padding, malformed-input mutations, both packet modes,
trusted-checkpoint admission, and v1 compatibility.

## Reproduction

From this research crate, using the existing locked dependencies:

```sh
cargo test --locked --offline --no-default-features --features native-matrict --lib
cargo test --locked --offline --no-default-features --lib
cargo run --release --locked --offline --no-default-features --features native-matrict --bin pq-ringct-compact-v2-measure -- /tmp/ringct-compact-v2-artifacts
python3 tools/compact_v2_audit.py /tmp/ringct-compact-v2-artifacts
RINGCT_V2_MEASUREMENT=/tmp/ringct-compact-v2-artifacts python3 tools/test_compact_v2_audit.py -v
```

Use a new output directory. The measurements here ran with a 4 GiB memory limit,
3 GiB memory high-water threshold, zero swap, two build/Rayon threads, 200% CPU
quota, and a 128-task limit. The source-complete checkpoint, patch, source archive,
test logs, measured public artifacts, independent audit, and `VALIDATION.json`
are in the enclosing `compact-proof-v2-20261030` campaign directory.
