# Independent signed-ternary NTT audit

This audit covers the research-only `fused-ternary-ntt-v1` representation and
`src/ring_circuit_ternary_audit.rs`. The independent source review found no
algebraic blocker in the fixed-Q relation. All nine independent tests passed in
the coordinator's serialized combined suite, and all six matched complete-relation
compiler/evaluation screens passed their terminal and integrity audits. The audit
author ran no builds, tests or benchmarks. This is not cryptographic approval or
complete-workflow qualification.

## Integer relation and exact bounds

For each row, let `a_i` be its 64 frozen public coefficients, with
`0 <= a_i < Q = 167770241`. Each private input is the same builder's sealed signed
wire with bound one, so its unique signed interpretation is `x_i in {-1,0,1}`.
Define only from the public row:

```
C = sum(a_i)
B = ceil(C/Q)*Q
S = B + sum(a_i*x_i)
S = k*Q + r, with 0 <= k <= 127 and 0 <= r < Q.
```

The bias is a multiple of Q, so the remainder is exactly the original transform
row modulo Q. It is not an additional private witness or a changed transform.
The coefficient map still includes every native Montgomery factor, conversion,
twiddle, sign and output permutation.

The exact uniform bounds are:

```
C <= 64*(Q-1) = 10737295360
B <= 64*Q     = 10737295424
0 <= B-C <= S <= B+C <= 21474590784 < 2^35
floor(S_max/Q) = 127; S_max % Q = Q-64
k*Q+r <= 127*Q+(Q-1) = 21474590847 < 2^35.
```

Both sides are below Goldilocks `p = 18446744069414584321`. Starting the field
accumulator at B keeps every signed partial sum between `B-C` and `B+C`, even
for all-negative inputs. Although `-1` has field encoding `p-1`, the relation
therefore represents an exact nonnegative integer equality. The bounded
quotient and canonical remainder exclude alternative encodings and field
aliases. Seven quotient bits suffice: 127 is the full seven-bit interval, so
the existing comparator needs no additional slack decomposition for this bound.

The signed-domain gadget constrains `x+1` to the integer interval `[0,2]`.
Domain enforcement remains necessary even if every coefficient of an input is
zero. Host metadata only generates quotient/remainder hints. It cannot replace
the private wire, change the public bias or table, or decide which constraints
are emitted. A host value within the ternary set can still be dishonest about
its signed wire; the compiled equation must reject the resulting false hints.

## Independent oracle and adversarial coverage

The new audit preserves the previous fixed-Q audit unchanged. Its independent
oracle uses six integer butterfly stages, u128 modular multiplication, the
frozen public omega constants and a separately pinned 64-entry permutation. It
does not call the candidate's dot helper, table derivation or native Montgomery
reducer. Both signs of every unit vector in all 256 coordinates are compared
with the native reference and the immutable table's read-only row view. This
checks all four lanes, cross-lane zeros, signs and final output positions.

The nine audit tests cover:

- Fixed-Q integer bounds, public bias, exact quotient maximum and conversions.
- Every signed basis coordinate and output permutation.
- Zero and extreme coefficient/input rows, alternate integer quotient/remainder
  encodings, and an actual Goldilocks alias that preserves the field equation.
- Invalid private signed wires even when all their coefficients are zero.
- Bad host domain, sealed bound, coefficient and batch arity before dot hints.
- Ternary host metadata that disagrees with the existing signed private wire.
- Complete constrained transforms with all 256 outputs bound to the independent
  oracle, including all-negative and all-positive inputs.
- Identical compiled programs for different private signs and zero patterns.
- Wrong research profile rejection before relation arithmetic starts.

For the integer re-encoding attack, `(k,r)` becomes `(k-1,r+Q)` and the expected
public remainder changes with it. Only canonicality can reject that unchanged
integer equation. For the genuine field alias, `(k,r)` becomes
`((k + Q^-1 mod p) mod p, r-1)`. The remainder stays canonical and the field
equation is unchanged; the seven-bit quotient limit must reject it. These are
separate attacks from simply corrupting a value and breaking equality.

Complete-transform diagnostic fixtures bind 192 outputs to independent expected
constants and expose the final 64 publicly, respecting the machine's public
input limit. The shape fixtures omit those witness-dependent oracle constants;
all their program constants come from fixed arithmetic or the public table.
Program equality across fixtures then checks that private values have not leaked
into circuit shape or constants. These fixture choices do not alter production
compiler routing.

## Ownership and reporting boundaries

The reviewed compiler constructs all constrained inputs in the same builder.
The existing `Signed` wrapper seals wire/bound construction but does not encode
builder identity. This internal helper is not an API for accepting externally
supplied wires or a caller-selected transform. The table bridge is read-only;
the earlier canonical-residue representation and audit remain available.

The fixed buffers must fit within the existing compiler auxiliary allowance;
no worker, process or GPU ceiling may increase. Source-requested byte counts are
logical storage bounds, distinct from physical guarded peaks. The existing
program retains its construction peak after packing; the narrow read-only
`Program::construction_host_bytes` query reports it without rescanning operation
capacities. Reports retain `compiler_requested_bytes_peak` as the explicitly
documented pre-finish snapshot and add `compiler_packed_admitted_bytes_peak` for
the construction peak through final compaction and packing. Retained program
storage continues to come from the already sealed evaluation plan, whose
description remains bound to its immutable owner through admission. Neither
construction counter is a measured physical peak or an execution permit.

Passing `MachineAir::trace` establishes host constraint satisfaction only.
Cryptographic proving, independently rebuilt verification, recursive closure,
artifact and terminal checks, complete-workflow measurements and qualified
security review remain separate requirements. Neither the seven-bit quotient
argument nor lower compiler counts alone establishes proving speedup.

## Coordinator qualification and measurements

The frozen combined direct-spend suite passed 70 tests with four ignored,
including all nine independent ternary audits. The coordinator also passed the
bounded core-analysis differential test and three alternating component pairs.
Three alternating complete-relation compiler/evaluation pairs then completed
under the existing 8 GiB program and 16M-wire profiles. All six jobs passed host
constraints and terminal/current-source audits, using the same deterministic
public research fixture and executable SHA-256
`9abf6cdcb76388140dcf6d17fb9aa650ef02a7ba6cc7cd845e866d081e9ef967`.

The medians across all three full-relation repetitions are:

| Diagnostic | `fused-public-ntt-v1` | `fused-ternary-ntt-v1` |
| --- | ---: | ---: |
| Compiler seconds | 3.485659641 | 2.106356108 |
| Host constraint-evaluation seconds | 0.281550924 | 0.177571111 |
| Whole diagnostic seconds | 3.803359618 | 2.304325456 |
| Guarded elapsed seconds | 6.097394671 | 4.090704546 |
| Wires | 12695988 | 8012253 |
| Active rows | 2063220 | 1276409 |
| Padded rows | 2097152 | 2097152 |
| Witness hint values | 73342 | 60030 |
| Pre-finish requested construction peak, bytes | 2422210560 | 2388656128 |
| Admitted construction peak through packing, bytes | 2662638248 | 2388656128 |
| Retained program bound, bytes | 1503289944 | 930640144 |
| Whole-live evaluation bound, bytes | 3332911096 | 2722791416 |
| Guarded job peak, bytes | 3219984384 | 1992364032 |

Compiler and host-evaluation timers measure their own phases. The whole
diagnostic also includes fixture generation and surrounding admission/reporting
work. Guarded elapsed time includes enclosing process work and is recorded
separately. Every
repetition remains in the medians. Source-requested construction, retained and
evaluation counts are distinct from the observed guarded job peak.

The candidate reduces active rows while the full relation still pads to
2097152 rows. Its admitted construction peak of 2388656128 bytes exceeds the
existing 2 GiB program allowance, so no 2 GiB confirmation was attempted. All
resource limits remain unchanged.

These measurements cover complete research-relation compilation and host
constraint evaluation. They generate no cryptographic proof and include no
independent proof verification, recursive aggregation or complete RingCT
transaction workflow. They do not satisfy the complete-workflow improvement
gate; the representation remains opt-in and research-only.
