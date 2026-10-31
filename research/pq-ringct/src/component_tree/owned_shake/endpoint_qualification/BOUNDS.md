# CPU endpoint constraint qualification

This module exists only in release, x86_64 test builds. The ignored qualification
requires `LATTICA_SHAKE_ENDPOINT_QUALIFICATION=1` and a serialized process guard.
It creates six fresh CPU native proofs and compiles five wrappers: each of the
three singletons, their first pair, and the odd squeezing tail. No recursive
proof, GPU receipt, complete transaction acceptance, or throughput measurement
is produced. `PairedV1` remains disabled and the production native dispatch
permit remains uninhabited.

The 137-byte input and 137-byte SHAKE256 output live in a fixed fixture. Its
reservation precedes XOF/commitment preparation and includes the fixture,
XOF state, source-array copy overlap, two captured native public arrays with
copy overlap, and one scalar Poseidon temporary. The input/output roots come
from these exact bytes. `ShakeRequestPlan` copies the immutable input under its
own preceding request reservation. Native owners are claimed before fresh
production; existing process guarding still covers the original native proving
scratch. Every wrapper goes through the actual CPU context's compiler phase
and actual cleanup. The two small execution bridges exist only in test builds,
accept no quota or generic callback, and forward to the existing closed path.

Before evaluation, the exact output's wire count and height derive these
simultaneously live requested-storage terms with checked arithmetic:

- `wire_count * sizeof(Val)` for `Program::evaluate`'s values vector;
- `padded_rows * machine::WIDTH * sizeof(Val)` for `MachineAir::trace`;
- one scalar Poseidon constructor, whose pinned p3 0.6.1 x86_64 implementation
  moves two four-round, eight-field external vectors and a 22-field internal
  vector (688 heap bytes), plus fixed object/array headers;
- at most eight reads and eight writes in simultaneously live helper vectors;
- fixed vector/matrix/machine/evaluator headers and bounded original source
  capacity-query error text.

The existing 2 GiB program reservation, compiler-input reservation, bounded
report, request owner, and fixture remain live. They are never shrunk to an
observed capacity. The new scratch reservation is admitted on the same worker
ledger before even calling the retained-capacity query. The query counts the
exact shared program and its nested/spare capacities; public/witness capacities
are checked against their existing reservation. No replacement program, caller
footprint, generic token, or enlarged worker allowance is accepted. The full
trace, wire values and short typed execution error are destroyed before scratch
retires. The compiled output's payload still dies before its retained tokens.

These terms bound live requested storage, not cumulative allocation volume or
RSS. Repeated scalar permutations allocate their constant tables serially, and
successive mutations run serially under one reservation. Allocator overhead,
enclosing context/runtime and OS stacks still need the existing process guard.
The worker/row/wire/device limits remain unchanged.

Valid witnesses must satisfy every compiled program equation via
`MachineAir::trace`. Tests check exact/one-byte-short evaluation admission,
foreign-ledger refusal, malformed geometry, and token cleanup. The real-native
test mutates every fixed header/endpoint-root field, proof inputs, missing
witness data, both complete reordered child-input blocks, all 108 fields on
both sides of the pair's interior boundary, and all 108 starting fields of the
odd squeezing tail. Native-public mutations exercise rejection by the whole
compiled verifier; they do not isolate each join equation from the native
verifier's own public-input authentication. Existing compiler-owner tests
separately reject missing/reordered/foreign native owners before compilation.
All temporary mutations are restored and valid evaluation is repeated before
the retained output is destroyed. Final ledger cleanup and context retirement
are asserted.

Final input/output roots bind only when a wrapper ends the full request. Each
of their eight fields must reject mutation on the final singleton and odd
tail. The nonfinal first pair and earlier singletons intentionally allow a
changed final root; a complete authenticated request tree must link those
headers to its final wrapper. Context and statement remain explicit framing
placeholders, and their mutation is demonstrably allowed here. This
qualification authenticates source byte roots only where the component
relation requires them. It does not close the transaction/obligation-manifest
binding or recursive proof-height obligations.

## Audited qualification

The coordinator ran the frozen source serially on 2026-10-25 UTC using Rust
1.96 release and `recursive-wide,native-matrict,native-verification-allocation-audit`,
two build/Rayon threads, one test thread, CPU-required execution, an 8 GiB
process cap, 6 GiB high watermark and zero swap. Both receipts report unchanged
source/executable identities, successful exit, and all subprocesses terminal
and reaped. A separate review matched all six B source/document hashes to the
integration tree and endpoint receipt before this documentation-only update.

| Serialized check | Result | Guard wall seconds | Peak process bytes |
| --- | --- | ---: | ---: |
| `nttopt-integration-shake-tests-1` | 48 passed, 7 ignored; both new ordinary endpoint tests passed | 62.186501984 | 1,323,081,728 |
| `nttopt-integration-shake-endpoints-1` | Explicit ignored endpoint qualification: 1 passed | 50.168242655 | 840,650,752 |

The second check completed six fresh native proofs and five valid compiled
constraint evaluations. Its five wrappers reported:

| Wrapper | Active rows | Padded rows | Wires | Input values | Additional evaluation bytes | Rejected boundary mutations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Singleton 0 | 101,683 | 131,072 | 1,503,593 | 155,319 | 110,596,512 | 0 |
| Singleton 1 | 101,687 | 131,072 | 1,503,796 | 155,319 | 110,598,136 | 0 |
| Singleton 2 | 101,600 | 131,072 | 1,501,833 | 155,319 | 110,582,432 | 0 |
| Pair 0 | 203,181 | 262,144 | 3,004,067 | 310,638 | 221,166,448 | 216 |
| Odd tail 1 | 101,600 | 131,072 | 1,501,833 | 155,319 | 110,582,432 | 108 |

The pair's additional reservation comprised 24,032,536 wire bytes,
197,132,288 trace bytes and 1,624 helper bytes. The source-capacity query found
223,533,336 retained program bytes and 4,194,672 retained input bytes for that
pair; their original conservative compiler reservations remained charged.
Additional evaluation storage is not the whole live worker footprint or RSS.
The final singleton and odd tail each rejected all eight final-root mutations;
the other wrappers preserved the documented nonfinal-root behavior. All
wrappers also rejected fixed-header/endpoint-root mutations (26 each, or 34
including final roots), native proof-input mutation and missing witness data.
The pair rejected missing/reordered complete child inputs. All 324 selected
boundary mutations failed, valid reevaluation after restoration passed, and
the terminal marker asserted full ledger cleanup and context retirement.

This closes the previous fixture's compiled-witness satisfaction gap for these
five CPU component wrappers. It produces zero recursive proofs and zero GPU
work. Context/statement authentication, complete request-tree composition,
recursive height closure, transaction acceptance and full-workflow speedup
remain unqualified; the runtime refusal is unchanged. Guard wall time is
correctness-run elapsed time, not a benchmark or optimization comparison.

Evidence hashes (SHA256), retained in the integration worktree's
`.tools/pq-opencl-opt/runs/` directory:

| Check | Receipt JSON | Raw log |
| --- | --- | --- |
| Focused suite | `610e9d8e61b91b8133550dcf0c0055e459860ca401951fb811960567a62371b0` | `b94ff55349573c7f51df13d99a26f85d4b23b9974ae59bca37fb9540e3c01cea` |
| Endpoint qualification | `29904c2ff06b0d3559e0011ba41468de5593e3e48535ae65e511b3fcedf8bb93` | `6e6f7d8344d4ba69a4c29dd0978b4d071f4add34be954663aac68f4a7763d605` |
