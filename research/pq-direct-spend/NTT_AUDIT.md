# Independent fixed-Q NTT representation audit

This audit covers the research-only `FusedPublicNttV1` representation and
`src/ring_circuit_ntt_audit.rs`. Source review found no arithmetic blocker.
All eight independent tests passed in the coordinator's serialized combined
suite. The audit author ran no builds, tests or benchmarks. This is not
cryptographic adoption approval or a complete-workflow performance result.

## Exact transform and integer bounds

The original Q-transform has butterfly strides 128, 64, 32, 16, 8 and 4. Each
preserves the coefficient index modulo four. Its final permutation changes
quartic blocks and preserves the lane inside each block. Therefore all four
lanes share one 64-by-64 public linear map. Deriving this map from public unit
vectors retains every original conversion, twiddle, sign and output permutation;
it does not use a private witness or replace a relation with native acceptance.

For `Q = 167770241`, `R = 2^32`, and Goldilocks
`p = 18446744069414584321`, `R^-1 mod Q = 54987456` and
`R^2 mod Q = 138438709`. The first low-half contribution multiplies by
`R^2 * R^-1 = R mod Q = 100711271`; the first high-half contribution multiplies
by `omega[1] * R^-1`. Every subsequent high-half butterfly contribution
multiplies by its pinned `omega * R^-1`. No further Montgomery division belongs
on the final public dot product: its coefficients already contain these factors.

Every dot product has exactly 64 canonical coefficients and 64 canonical private
residues. With no extra addends, its integer bounds are

```
LHS_max = 64*(Q-1)^2 = 1801398619498086400 < p.
floor(LHS_max/Q) = 10737295296; LHS_max % Q = 64.
k <= 64*(Q-1) = 10737295360.
RHS_max = k_max*Q+(Q-1) = 1801398630403152000 < p.
```

Nonnegative partial sums also stay below p. The bounded quotient, canonical
remainder and field equality consequently enforce the unique integer remainder.
This argument does not hold for 64 products at QHAT. The dot helper rejects a
foreign modulus, noncanonical host value or noncanonical public coefficient
before emitting its quotient/remainder hints.

The transform entry is restricted to the existing ternary domain: every sealed
signed input has bound one, its host metadata lies in `{-1,0,1}`, and the existing
signed-to-canonical-residue constraints remain in the same builder. Host metadata
only generates hints; the signed wire and sign/canonicality constraints still
determine the actual input. The compiler continues to enforce all surrounding
ownership, openings, ranges, balance, serials and expected-statement checks.

## Independent oracle and adversarial coverage

The audit's oracle is a separate six-stage integer butterfly implementation. It
uses u128 modular multiplication and the independently pinned 64-entry output
permutation, rather than the candidate's matrix or native Montgomery reducer.
It reads the unchanged public omega constants. For every one of the 256 input
coordinates, positive and negative unit vectors are checked against both the
untouched native transform and every corresponding candidate matrix output.
This covers all four lanes, signs and output positions, and rejects cross-lane
mixing or a missing conversion/permutation factor.

The eight independent tests additionally cover exact fixed-Q bounds, genuine
Goldilocks aliases, alternate integer quotient/remainder encodings, canonical
private wires even under zero public coefficients, corrupted host metadata,
foreign modulus/coefficient/arity refusal before hints, a complete constrained
transform, a changed public matrix entry, and the wrong research profile.
The complete-transform checks bind all 256 oracle outputs: 192 expected constants
plus 64 public values within the existing machine limit. A corrupted host sign
remains ternary metadata but disagrees with its sealed signed wire and must fail.

The alias attack preserves the field equation: for valid positive r, replace
`(k,r)` with `((k + Q^-1 mod p) mod p, r-1)`. The new remainder is canonical, but
the quotient exceeds its explicit bound. A separate mutation changes
`(k,r)` to `(k-1,r+Q)`, preserving the integer equation while violating remainder
canonicality. Incorrect public expectations are also rejected.

C's separate tests cover constrained comparison with the original inline
schedule, witness-independent program shape, ternary-domain refusal, selector
behavior and a separately guarded alternating component screen. These checks
complement the independent oracle and mutation tests; component results cannot
qualify a full proving workflow.

## Storage and trust boundaries

The public coefficient table occupies 32768 bytes. The candidate reserves a
fixed 512 KiB portion of the existing 16 MiB compiler auxiliary allowance for
the table, native basis/output arrays, constrained lane/output arrays and
conservative moves. Compile-time layout checks include four table buffers, four
native polynomial buffers and sixteen constrained polynomial buffers, including
the bounded `ntt_many` result. No resource ceiling increases. Compiler-generated
stack spills, OS stacks and allocator overhead still require the enclosing
process guard; named fixed buffers are not a complete physical stack bound.

The transform table is private and derived only from frozen public arithmetic.
The changed-table test deliberately uses child-test visibility to simulate a
wrong compiled map; production callers cannot provide such a map. Expected
statement/profile/context authentication and binding of the final compiled
program remain duties of the enclosing compiler and eventual protocol.

`Signed` and `Residue` seal wire construction and bounds/moduli but do not encode
builder identity. The reviewed internal path constructs all operands in the same
builder. The helper is not permission to accept externally supplied constrained
wires, tables or proof programs. Passing `MachineAir::trace` establishes host
constraint satisfaction only. Cryptographic proving, independent verification,
recursive graph closure, full-workflow measurements and qualified security
review remain separate adoption requirements.

## Coordinator qualification and measurements

The frozen combined direct-spend suite passed 46 library tests, 2 CLI tests and
8 relation tests (56 passed, 3 ignored), including all eight independent NTT
audits and five evaluation-admission tests. The coordinator also completed
three alternating component pairs and three alternating complete-relation
compiler/evaluation pairs. All six complete-relation jobs satisfied their host
constraints and passed terminal/current-source audits. The comparison used the
same deterministic public research fixture and executable SHA-256
`1cbcc764f50b8c835048e396a9be8fb30fe934afb722e25fd2690cfd506a77a6`.

The medians across all three repetitions are:

| Diagnostic | `fused-public-linear-v1` | `fused-public-ntt-v1` |
| --- | ---: | ---: |
| Compiler seconds | 9.591446929 | 3.428101539 |
| Host constraint-evaluation seconds | 0.788128530 | 0.281384986 |
| Guarded elapsed seconds | 12.108227708 | 4.090608589 |
| Wires | 35806310 | 12695988 |
| Active rows | 6017802 | 2063220 |
| Padded rows | 8388608 | 2097152 |
| Witness hint values | 299646 | 73342 |
| Retained program bound, bytes | 4379757128 | 1503289944 |
| Whole-live evaluation bound, bytes | 11125435768 | 3332911096 |
| Guarded job peak, bytes | 9314279424 | 3216216064 |

Compiler and host-evaluation timers describe their own phases. Guarded elapsed
time also includes enclosing work and is recorded separately; no repetition is
discarded from the medians. Logical retained/evaluation bounds are distinct from
the observed guarded job peak. The candidate also passed a separate
confirmation with the existing 8 GiB program and 16M-wire profiles, without
increasing a resource limit.

These are complete research-relation compilation and host-constraint screens.
They generated no cryptographic proof, performed no independent proof
verification or recursive aggregation, and do not qualify the complete-workflow
speedup gate. The representation remains opt-in and research-only pending the
remaining protocol, security and workflow qualification.
