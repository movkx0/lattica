# Seven private-note research fixtures

`DecodeSession::research_fixtures` builds exactly seven transactions on its
existing ledger. Each has two inputs, two outputs, 52-bit values and two valid
membership paths in a depth-32 tree. All cases use the caller's independently
supplied context. SHAKE domain-separated public case material changes the keys,
diversifiers, randomness and asset across cases. These deterministic keys are
research fixtures, never wallet key generation or proof randomness.

The unchanged `joinsplit_air` oracle computes recipients, commitments, Merkle
hashes and public nullifiers. The generator places the two inputs at leaves 0
and 1 of an otherwise empty tree. It constructs sibling arrays directly, so it
does not allocate the reference demo's temporary leaf/path vectors. Before the
set is returned, it rejects repeated statements and any duplicate among all
fourteen nullifiers. Varying only transaction context would not pass this test.

The quota reservation precedes fixture construction and moves with the fixed
seven-element owner. No owned extraction or clone exists. The reservation drops
after every statement and witness, including construction failure and after
the original decoding session has been dropped.

For each case, reference hash construction performs 115 permutations: six for
two input commitments, 31 for empty subtrees, two for output recipients and 76
inside `native_outputs` (72 for input ownership, commitments, membership and
nullifiers; four for output commitments). The pinned scalar Poseidon2
constructor requests two 4-by-8 Goldilocks vectors and one 22-word vector,
688 bytes per invocation. All cumulative requests are charged, without taking
lifetime overlap credit. Seven exact 26-word public vectors add 1,456 bytes,
giving 555,296 bytes of cumulative source heap requests. A separate, typed
inline census covers both fixed arrays during ownership transfer, explicit
witness/hash temporaries and the owner, plan and reservation handles. The
ledger's actual Rc request is charged by `DecodeSession` itself.

The source census does not describe allocator metadata, stack frames chosen by
the compiler, process startup or the runtime. Those remain obligations of the
unchanged external process/thread guard. Reference relation checks in unit
tests are test oracles; they are not secretly added to a timed proving workflow.

The fixture receipt times generation and distinctness checks after admission.
The per-case generation times exclude common admission and set-level checks.
A complete research workflow must start before fixture admission, include all
seven proofs, canonical decoding, independent CPU verification and round trips,
and finish after the original payloads and session have been destroyed. It must
not treat these fixture timings as complete RingCT transaction measurements.
