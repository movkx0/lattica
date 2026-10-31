# Owned private-note GPU qualification

`note-gpu-proving-experiment` is a disabled-by-default research feature. It
adds one fixed continuation to an already admitted private-note preparation.
The ordinary `require_dispatch` and admission diagnostics continue to refuse
dispatch. No production transaction acceptance, proof parameters, wallet keys,
Merkle membership rules, nullifier rules or balance constraints change.

The continuation uses the two-input/two-output, 52-bit private-note fixture and
unchanged join-split relation. Its quadratic proof retains 96 queries, blowup
16, maximum FRI arity 16, 16-bit query PoW, four random codewords and cap height
6. This is a different ledger/key construction from RingCT. A successful
qualification is not a protocol-preserving RingCT speedup or a cryptographic
security review.

Before any device query, `Admission::reserve` atomically acquires the runtime,
packet, full bounded decoder, independent CPU verifier and enclosing owner
claims on the original preparation's ledger. The decoder preclaim uses the
existing 64 MiB native encoding ceiling. Split operations transfer that actual
reservation; no byte receipt, new ledger, callback or unrelated output can
replace it. Every phase still requires the unchanged external process/VRAM
guard and its immutable env-clear dedicated worker.

The core feature returns `OwnedEncodedNote` only after a strict successful
native report, exact epoch shutdown, zero managed and retained-tree bytes and
lease release. All configuration, capacity and session aliases retire first.
The encoded allocation retains the entire original operation reservation.
No public constructor, Clone, owned byte extraction or quota extraction exists.

Research `ProducedNote::into_decoded` checks terminal ownership, ledger and
public identity before allocating the PQNOTE1 packet. It borrows the native
encoding immutably, writes the existing envelope, and transfers its preceding
decoder token into the same bounded parser used by ordinary decoding. The
decoded artifact retains the native owner, preparation residual, remaining
handoff owner and verifier reservation. Packet, decoded proof and native
encoding drop before their respective tokens, including on error and unwind.

Independent verification remains in the research crate. A producer artifact
borrows its pre-admitted verifier scratch through a single-flight guard. A
concurrent or reentrant attempt is refused; error and panic reset the guard.
Ordinary decoded artifacts retain their existing reserve-before-verification
behavior on the same ledger. Both paths use the identical numerical verifier
and unchanged join-split constraints. The caller's session can be dropped while
the artifact and its actual quota remain live.

The authored exact ignored GPU test is
`note_gpu::proving::qualification::tests::gpu_owned_note_handoff_verifies_fresh_proofs_and_rejects_mutations`.
It generates two fresh proofs, independently verifies both after runtime
retirement, decodes and verifies canonical round trips, rejects twelve header,
profile, context, field, public-statement, trailing-byte and opening mutations,
and checks original quota cleanup after session drop. Timings describe this
qualification interval; fixture construction, mutations, final RingCT
aggregation and complete seven-transaction workflow are not included.

The source capsule includes pure admission, original-token transfer and scratch
failure/unwind tests. They are authored and source-formatted only until the
coordinator's serialized execution. Core C016 previously passed two actual
native GPU proofs without independent verification; that earlier result is
not substituted for this new test. No speedup or adoption claim is made.
