# Validation record, 2026-10-24

The coordinator ran these jobs serially under an 8 GiB cgroup memory cap and zero
swap. All listed subprocesses were terminal/reaped, and each guard confirmed its
source inputs remained unchanged. Times below are guarded job wall times; peaks
are cgroup observations for the entire job, which can include Cargo/build work.
They are not proof-only memory peaks or matched transaction throughput.

| Label | Outcome | Job wall seconds | Cgroup peak bytes |
| --- | --- | ---: | ---: |
| `concurrent-c-relation-tests-2` | 4 unit + 8 relation tests passed; separate real proof test ignored here | 2.085 | 276103168 |
| `concurrent-c-note-proof-test-1` | Fresh CPU note proof, independent verification, statement/proof mutations and artifact round trip passed | 4.087 | 276905984 |
| `concurrent-c-ring-compile-screen-1` | `ResourceLimit`; no ring proof started | 2.083 | 173010944 |
| `concurrent-c-ring-compile-screen-2` | Diagnostic build/run; same logical refusal, no ring proof started | 68.220 | 1183805440 |
| `concurrent-c-constant-relation-tests-1` | Constant-only representation build; 6 unit + 8 relation tests passed | 66.198 | 1186279424 |
| `concurrent-c-ring-compile-screen-3` | Constant-only representation passed startup, then refused the same program allowance during ownership constraints | 2.083 | 179613696 |

The first relation build (`concurrent-c-relation-tests-1`) found a Rust type
inference error before executing tests/proofs. An explicit fixture Vec type
annotation fixed it. The diagnostic-only compiler change was subsequently built
and executed by screen 2.

The original inline representation failed while constructing public constants,
before allocating any private hint inputs. Screen 2 reported phase
`direct_relation_inputs`, logical limit `program_heap_request_allowance`, the
unchanged 268435456-byte builder allowance, an accepted requested-heap peak of
155975680 bytes, 778287 wires, zero input values and zero witness hints. A rejected
container-capacity growth can exceed the allowance even when the previously
accepted peak is smaller. The 134217728-byte witness allowance and 16777216-wire
limit were not exhausted. No complete graph row geometry or proof timing exists
for this failed compile.

Inspection identifies redundant canonical range-decomposition hints on
builder-known public constants as an immediate representation problem. The
`inline-public-constant-bits-v1` candidate uses the existing constrained
bit-reconstruction API on canonical public/fixed constants, preserving private
inputs and production modules. Boundary/no-hint/no-growth tests passed. Screen 3
advanced into `input_ownership`, then refused the unchanged program heap allowance
with accepted requested-heap peak 161480704 bytes, 795709 wires, and 6700 private
input/hint values. No proof started and complete graph geometry remains unavailable.
The original startup bottleneck is removed; the current inline representation is
still rejected. The different cgroup peaks above must not be confused with the
logical builder allowance or interpreted as a proof-performance comparison.

No typed decomposition or limit increase was implemented. For future research,
the exact relation contains 52 NTTs and 120 NTT-ring products. Existing typed AIR
geometry would yield 46592 active NTT rows (65536 padded) and 145920 active product
rows (262144 padded) if each type were a single batch. Those counts do not establish
resource admission or recursive-parent fit. Any fixed component schedule would
need complete child verification, exact joins, independent expected-statement
verifier reconstruction and complete resource admission. Ring proving remains
unfinished; this screening does not authorize further proof dispatch or a speedup
claim.

Raw JSON guard records and logs are preserved in the agent-C worktree's ignored
`.tools/pq-opencl-opt/runs/` directory. Raw log SHA-256 values:

```text
concurrent-c-relation-tests-2       9cb2caa472eb12269d5ed5dedd2ae665effac627b7b5559cc1762fe2d2cd5efe
concurrent-c-note-proof-test-1      6e0c1f94a63a351eff510507e2cdfba76ed87c90623557c981d8e0af53127336
concurrent-c-ring-compile-screen-1  add4e607962c339ad05065bd94689dac36f022c98dcba8fa82b287f56c71a2b6
concurrent-c-ring-compile-screen-2  807d6469babaf31cedd81c39b0093fe880c533482b8f261f79db5e38a8587a1f
concurrent-c-constant-relation-tests-1 3b65703bfe2f1d553f9c6eef8193b87db3dbbd88e19292c45a19a0c95f368514
concurrent-c-ring-compile-screen-3  b7987f2574a606b503f4aef2aa6db880c591a19d12270cc65b90cd0cf0556b88
```

Agent B's read-only engineering review found no remaining blocker for the isolated,
unqualified research scope after fixes to compiler admission and public statement
binding. Qualified cryptographic/security review remains outstanding. Ring full
proving, aggregation and matched complete-workflow measurement remain incomplete;
the note test establishes correctness of this CPU research wrapper, not a 2x claim.
