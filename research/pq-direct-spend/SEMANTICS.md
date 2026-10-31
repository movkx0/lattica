# Semantic comparison and adoption blockers

| Property | Existing RingCT / proposed direct ring | Private-note direct profile |
| --- | --- | --- |
| Input shape | One hidden selected pair among ten authenticated candidate pairs; both inputs share the same selector | Two independently authenticated note positions below one depth-32 Merkle root |
| Anonymity | At most ten candidate pairs for this fixed profile; candidate-set construction/ledger authentication remains external | Potentially any eligible note below the anchor; tree population and ledger policy determine the actual anonymity set |
| Spend authority | Eight degree-256 ternary lattice polynomials per account; public key equation includes AES-derived G(serial) | Two canonical Goldilocks nullifier-key limbs and diversifier; ownership is domain-separated Poseidon2 |
| Commitment opening | Nine degree-256 ternary polynomials, Q=167770241, original partial NTT and Montgomery representation | Two-permutation Poseidon2 commitment with two-limb rho and rcm, hidden asset and PLAIN note type |
| Serial/nullifier | Public 32-byte original gamma; AES-256/bounded sampler linkage retained; duplicate serials rejected | `H(DOM_NF, nk0, nk1, rho0, rho1, position)`; duplicate nullifiers rejected |
| Ledger relationship | Public account pk/coin pairing and candidate eligibility must be authenticated by ledger; compiler alone cannot establish that | AIR authenticates Merkle membership; consensus must authorize the root and reject already spent nullifiers |
| Value / issuance | Initial research shape fixes two inputs/two outputs, 52 bits, exact integer balance, zero fees/mint | Same comparison shape, retaining the unchanged production AIR's 52-bit range parameters |
| Public setup | Exact original AES public matrices and original Q/QHAT constants; no proof parameters weakened | Existing production join-split hash/AIR/FRI parameters, tree depth and note format unchanged |
| Proof architecture | The opt-in `gpu-proving` API proves the complete direct witness relation without generating a MatRiCT proof, with fresh public reconstruction and independent CPU verification; the legacy host `ring::prove` remains deliberately refused. Recursive transaction/aggregate closure is absent | Fresh proof of the existing join-split AIR, no MatRiCT verifier or ring proof; separate owned CPU and GPU research workflows retain the same relation |
| Wallet migration | Existing ASK/coin secrets are applicable in principle; direct proving, registry and transcript security still require review | Different secret keys, addresses, commitments, nullifiers, state index and scanning/recovery rules; cannot spend an existing RingCT account without an explicitly designed migration |

The ring relation is stronger than a superficial balance predicate: it binds both
accounts' selected public keys and commitments to ternary secrets, and constrains
new output commitments from ternary openings. Outputs are assigned to the public
recipient keys as account pairs; spending authority is proved when those accounts
are subsequently spent. The ledger must authenticate this pairing. Neither
prototype permits two arbitrary members to be selected from the ten pairs or
silently splits a transaction into unrestricted subproofs.

The original reference mint encodes 64 amount bits in every fourth partial-NTT
coefficient. The direct relation fixes bits 52 through 63 to zero; its range
matches the existing qualified 52-bit transaction profile. It does not reduce
lattice dimension, moduli, key bounds, AES strength, proof security settings or
the join-split Merkle depth. QHAT belongs to the removed MatRiCT proof's auxiliary
verification equations; the direct account/opening relation uses original Q.
Removing that proof system is a new construction requiring review, not a
protocol-preserving optimization or a claim that QHAT security is unnecessary.

Unresolved adoption questions include direct-knowledge/zero-knowledge security,
binding of verifier reconstruction and registration to the exact public
statement, shared-pair selection semantics, malicious setup/candidate policies,
ledger serial/nullifier state transitions, fresh output randomness, side-channel
behavior, and wallet migration/recovery. Self-tests and a faster component cannot
answer these questions. Qualified independent review and complete-workflow
measurements are mandatory before any redesign adoption or 2x performance claim.

The seven-case direct-ring screen is an isolated ignored test using the existing
full relation, fixed parameters and baseline public-hash kernel. It varies genuine
account secrets, openings, serials, hidden selected pairs and balanced 52-bit
values under one fixed context and setup seed. Each proof is independently
reconstructed and verified after an artifact round trip. Seven separate relation
proofs do not constitute N3/N4 recursive aggregates or ledger-authenticated
transactions. Its report keeps all protocol-adoption and redesign-speedup flags
false. The same-note CPU/GPU comparison also measures backend execution of one
unchanged note construction, not equivalence to RingCT or a protocol migration.

The existing join-split constraint self-audit is a useful reference
(`../../docs/joinsplit-constraint-audit.md`) and is explicitly not an external
cryptographic security audit. This crate imports the constrained implementation
directly, with no production acceptance changes.
