# Prover ↔ node wire formats (normative)

> **Document role:** Normative byte-level contract between Rust proof code and Zig consumers.

The Zig node and the Rust prover (`lattica-prover-p3`) exchange bytes across the C ABI declared in
`lattica-prover-p3/include/lattica_prover_p3.h` (mirrored by `src/ffi_integration.zig`,
`src/integration_node.zig`, `lattica-prover-p3/tests/ffi_integration.c`). The legacy contracts below
are **frozen**: a change is a node-seam break, and for the starred (★) items a consensus break.

## Candidate / inactive v2 boundary — no new byte schema

[Block-proving v2](block-proving-v2.md) introduces a separately versioned candidate profile and a new
ordered 64-leaf Merkle commitment; it does **not** reinterpret the unversioned legacy proof bytes or
the batch tx-root below. Historical v1 decoding and verification remain unchanged. The v2 target is
one aggregate proof ≤2 MiB for at most 64 total transactions including issuance, with no individual
proofs retained in the block. Aggregator interfaces must accept only proofs and public inputs, never
wallet witnesses; the witness ABI below is not a network submission format.

**CANDIDATE / INACTIVE:** exact v2 identifiers, domain tags, public-input encodings, and proof-byte
layout are not assigned here. The candidate cubic-extension/binary-FRI profile remains unfrozen
pending complete-tree soundness and full-depth qualification. The bounded verifier
has a real four-transaction/two-level proof and root-only verification after inner
artifact deletion, but no production acceptance ABI or network format. The local
research envelopes in the [evidence report](bounded-execution-engine.md) are not
new normative wire assignments. Depth-six/64-transaction performance and activation
remain open. Activation requires reviewed encodings and explicit host consensus
changes. Neither a v2 failure nor this section authorizes a downgrade to witness
batches or individual-proof containers.

### Local research node files — not network wire assignments

The bounded recursion tools select their node format from the locally trusted
build/profile, never by using an untrusted file header to choose a verifier:

| Research build | Header | Payload |
|---|---|---|
| Default `block-v2` | `LBV2RC01` | Original Postcard representation, unchanged |
| Opt-in `block-v2-wide-lanes` | `LBV2RC02` | Postcard framing with each Serde `u64` value encoded as exactly eight little-endian bytes |

The adapter applies recursively, including scalar types that Serde represents
as `u64`; sequence lengths and enum discriminants retain Postcard framing.
Wallet artifacts (`LBV2WL02`) retain the legacy encoding and wallet profile.
Both node formats retain the **2 MiB total envelope limit including the header**.
The encoder writes into a fixed-capacity buffer. Decoding enforces canonical
re-encoding, field canonicality, sequence/item/depth budgets and exact input
consumption. Schema-known tuple lengths remain bounded even when their fields
encode to zero bytes; variable-length inputs still require checked length hints.
Wrong, unknown and downgrade headers are rejected by the selected decoder.

The wide program manifest is version six and its registry binds node-codec
revision two. Default program/registry identities remain unchanged. This is a
research representation change, not weaker proof parameters, a production ABI,
or authorization to activate a network format. Passing codec tests does not
establish full-size recursive closure, resource feasibility or tree security.

## Proof bytes

`postcard::to_allocvec(p3_uni_stark::Proof<MyConfig>)` — **no version prefix**. Pinned to:

- p3-* **0.6.1** struct definitions (serde derives), postcard 1.x;
- the production config `MyConfig` in `lattica-prover-p3/src/config.rs` ★: Goldilocks, F_p²
  challenges, Poseidon2-8 sponge/compress, salted `MerkleTreeHidingMmcs` (ChaCha20, 2/4/4),
  `HidingFriPcs` with 4 random codewords, FRI `{log_blowup: 4, num_queries: 96, query_pow: 16 bits,
  arity ≤ 2⁴, cap height 6}` (≈103-bit proven / ~127-bit conjectured).

Verifiers reject `proof_len > MAX_PROOF_LEN = 1 << 21` (audit M-08; `src/ffi.zig` mirrors the bound).

## Digests

32 bytes = 4 Goldilocks limbs, **little-endian u64 each, canonical** (< p); non-canonical limbs fail
closed on every parse path.

## Public inputs (little-endian, byte-exact)

| circuit | bytes | layout |
|---|---|---|
| join-split | 208 | `anchor(32) ‖ nf₀(32) ‖ nf₁(32) ‖ out_cm₀(32) ‖ out_cm₁(32) ‖ tx_binding(32) ‖ fee(u64) ‖ mint(u64)` |
| HTLC | 248 | join-split layout ‖ `current_height(u64) ‖ redeem_hashlock(32)` |

Note the wire order differs from the in-circuit `PI_*` order (`lib.rs` re-orders on parse/encode);
`PI_*` in `joinsplit_air.rs`/`htlc_air.rs` is the in-circuit layout.

## Witness records (wallet → prover)

Fixed-length concatenated records; the normative field order is `lib.rs` (`js_witness_len` /
`htlc_witness_len`). `JS_WITNESS_LEN = 2464`, `HTLC_WITNESS_LEN = 2728`. The **join-split** record,
per input: `nk0,nk1 (u64) ‖ diversifier ‖ asset ‖ value ‖ rho0,rho1 ‖ rcm0,rcm1 ‖ 32×sibling(32) ‖
32×path-bit (1 byte each, strictly 0/1)`. The **HTLC** record extends it per `lib.rs`'s
`parse_htlc_witness` (note_type, mode, redeem/refund tags, hashlock, timeout, current_height —
do not infer the layout from this page). Batch proving: `witness_len == n_tx × record_len`, and
`padded_tiles(n_tx) ≤ MAX_BATCH_TILES = 64` ★.

## Batch tx-root ★

The batch proof's only public input: the block tx-root digest (32-byte wire form above). Defined as
the `DOM_TXROOT`-tagged Merkle–Damgård fold over per-tx statement digests (chunk order: `[dom‖anchor]`,
each nullifier, each out_cm, `[fee, mint, 0, 0]`, `tx_binding`, and for HTLC additionally
`[current_height,0,0,0]` + hashlock). The node recomputes it natively (`src/poseidon2.zig`
`txStatementDigest`/`batchRoot`, KAT-pinned by `dump_p2`); the circuits reproduce the same chain
in-circuit (`batch_joinsplit_air.rs` / `batch_htlc_air.rs`).

## Hash / domain constants ★

Poseidon2-Goldilocks W=8 with the vetted `GOLDILOCKS_POSEIDON2_RC_8_*` constants; domain-separation
tags per `lattica-prover-p3/src/domains.rs` (the normative table): `DOM_OWN=1, DOM_CM=2, DOM_NF=3,
DOM_HTLC=4, DOM_NF_HTLC=5, DOM_TXROOT=6`; note types `NOTE_PLAIN=0, NOTE_HTLC=1` (commitment lane 7);
asset id in commitment lane 6. Cross-language equality is KAT-pinned (`dump_p2` → `src/poseidon2.zig`).

## Return codes

- verify: `0` accept, nonzero reject (fail-closed; never unwinds across the ABI).
- prove: `0` ok; `1` malformed/invalid input or internal failure; `2` output buffer too small —
  on rc=2 the `*_len` outputs are **not** written (caps are checked before any store); size buffers
  from `MAX_PROOF_LEN` / the fixed PI widths. `*_len` are written only on rc=0.
