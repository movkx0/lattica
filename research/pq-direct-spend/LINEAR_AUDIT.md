# Independent fused public-linear arithmetic audit

This source review covers the research-only `FusedPublicLinearV1` compiler
representation and its independent test module `src/ring_circuit_linear_audit.rs`.
It is not cryptographic adoption approval, proof verification, or a workflow
performance result. Production acceptance and resource limits are unchanged.
The coordinator qualified these sources through serialized builds, tests and
guarded compiler/evaluation screens; outcomes are recorded below. No builds,
tests or benchmarks were run by the audit author.

## Integer soundness of one fixed-Q dot product

Let `Q = 167770241`, `p = 18446744069414584321` (Goldilocks), and `R = 2^32`.
There are at most twenty products of canonical residues and at most two
canonical addends. Both factors in each product are in `[0, Q-1]`. Therefore

```
LHS <= 20*(Q-1)^2 + 2*(Q-1) = 562937068928692480 < p.
floor(LHS_max / Q) = 3355404782; LHS_max % Q = 18.
```

The candidate explicitly constrains the quotient to
`k <= 20*(Q-1)+2 = 3355404802` and the remainder to `0 <= r < Q`. Thus

```
k*Q+r <= 3355404802*167770241+167770240
      = 562937072451867522 < p.
```

Every nonnegative partial sum has the same bound. The constrained field equation
`LHS = k*Q+r` is consequently an integer equation: neither side can wrap modulo
Goldilocks. Canonicality then makes the remainder unique. This derivation is
specific to Q; twenty products at `QHAT = 3489661057` exceed p and cannot use this
argument. The candidate rejects foreign moduli and oversized arities before
emitting dot-product hints.

The tests include an actual field alias, rather than only an incorrect equation:
replace a valid positive remainder r with `r-1` and k with
`(k + Q^-1 mod p) mod p`. The field equation remains valid and the new remainder
remains canonical, but the new quotient violates its explicit bound. Other
tests preserve the integer equation while making the remainder or private input
noncanonical, and corrupt host value metadata while retaining the original wire.

## Montgomery factors and quartic signs

`R^-1 mod Q = 54987456` and `R^-2 mod Q = 106966669`.
For quartic output coordinate o and private coordinate j, the public coordinate
is `i = (o+4-j) mod 4`. The untouched native reference first computes
`mont(a_i, x_j)`. If `i+j >= 4`, it then applies `mont(result, omega)` and the
pinned block's negacyclic sign. The folded public coefficient must therefore be

```
no wrap:  a_i * R^-1 mod Q
wrap:     sign * a_i * omega * R^-2 mod Q
```

Canonicalizing a negative coefficient changes its integer representative but
preserves its residue modulo Q, allowing the nonnegative bound above. The
candidate retains the existing sign and omega tables. Independent basis-product
tests compare all 64 blocks, four private coordinates, and four outputs against
the untouched generic/native multiplication for zero, maximal, and varied public
coefficients. Expected results do not call the candidate coefficient routine.

## Coverage and trust boundaries

The eight independent tests cover pinned bounds/factors, every quartic
coefficient, scalar extrema, adversarial quotient/remainder hints, canonical
private inputs and host metadata, refusal before dot hints, complete
256-coefficient maps with zero/one/five columns, and wrong context/profile
admission. The complete-map tests reject incorrect expected outputs and outputs
from different public coefficients. C's separate tests cover the two/four/five
column helper routing. Existing inline NTTs and commitment value-bit addition
remain in the candidate; this audit does not duplicate a complete expensive NTT
compiler run.

The expected public coefficients are constants embedded in the compiled program,
not witness-selected parameters. Authentication of the expected statement,
profile, context, and eventual program remains the enclosing compiler/protocol's
responsibility. The selected candidate rejects the wrong profile or context
before arithmetic and labels those failures with its chosen representation.

All residue operands must have canonical constraints in the same builder that
emits the dot product. The internal `Residue` type seals wire/modulus creation but
does not encode builder identity. The reviewed compiler constructs its operands
in its own context; the fused helper is private. This internal prerequisite is
not an authorization to accept externally supplied residues or proof programs.

`MachineAir::trace` executes host constraints. These passing tests do not
establish recursive closure, cryptographic proof availability, independent CPU
proof verification, or any complete-workflow speedup. Those claims require their
separate qualification gates and, for protocol adoption, qualified security
review.

## Coordinator qualification and preserved failed evidence

The first combined library run passed 28 tests and failed this audit's complete
polynomial fixture before arithmetic: it requested 256 public values from a
machine whose unchanged maximum is 64. The correction keeps all 256 output
equalities, binding the first 192 to reference constants and the final 64 to
public inputs. The test helper also caps witness inputs at
`min(input_limit, wire_limit - public_count)`, as required by the existing
constructor. The wrong-output and wrong-public-coefficient checks mutate the
public portion and still require rejection. No production limit was changed.

The coordinator retained the original failed run with receipt SHA-256
`7a0e48d05714659162caf4392bf96dbe51ffabc578f620d786d16145ead42f13`
and log SHA-256
`b04530429b1baf5ef7ccd4e9872310c49120124d3b3398d6b808a05ed0b745f3`.
The corrected complete suite passed 29 library, 2 CLI and 8 relation tests
(39 passed, 2 ignored), with a guarded elapsed time of 32.147 seconds and
979230720 bytes peak memory. These results were reported after the coordinator's
terminal and artifact audits.

The subsequent terminal, audited candidate screen compiled the complete research
relation with 35806310 wires, 6017802 active rows and 8388608 padded rows.
Compiler time was 9.533136086 seconds. All host constraints passed in
0.800464827 seconds. The guarded run took 12.107935683 seconds and peaked at
9316761600 bytes. The baseline compiler refused at the unchanged 67108864-wire
limit in `input_opening`, after 16.548089529 seconds of compiler time.

The baseline refusal is not a completed comparable workflow. Neither screen
generated a cryptographic proof, recursively closed a transaction graph, or
measured fresh proving/aggregation/verification throughput. These results show
that the candidate fits this compiler screen and satisfies its host constraints;
they establish no complete-workflow speedup or production adoption approval.
