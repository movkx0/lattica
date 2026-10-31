# Reserved raw graph differential

This test compares one complete raw GPU graph with the independent scalar CPU
arithmetic on the same genuine MatRiCT fixture. It does not prove the graph,
accept a transaction, or measure complete workflow throughput. The fixture is
the existing two-input/two-output case: context `[71; 32]`, setup seed `[29; 32]`,
ring index 3, inputs `[17, 23]`, and outputs `[29, 11]`. Native CPU fixture
generation and its C verification occur outside the reported intervals.

The fixture's actual retained capacities are subtracted from the 32 GiB worker
allowance. The same resulting ledger admits the original pending runtime, two
independent `Construction` owners, and additional CPU reference scratch before
either graph is lowered or any device is inspected. The CPU graph uses
`CommittedBackend::new`: its scalar arithmetic, AES, SHAKE and Poseidon paths
have no `DeviceSession` and emit no GPU execution receipt. Its original decoded
input and graph tokens survive while the closed `prepare_owned_graph` boundary
constructs the actual GPU graph. This deliberate overlap must fit the unchanged
worker allowance; the test does not create a second quota or enlarge any limit.

Each Construction already covers its own graph vectors, imports, memo maps,
decoded inputs and raw adapters. `CpuReferenceScratch` additionally covers CPU
temporaries that must not be inferred from the GPU adapter budget:

- One reconstructed native statement is charged as three complete fixed
  decoded statement/proof backings, including nested vectors.
- All 185 parameter polynomials, both four-polynomial samples, two alpha
  polynomials, and every alpha/X transcript unpack are summed with a factor of
  three. The factor covers old/new vector growth. All outer matrix and w-out
  vector descriptors are included.
- Both serialized transcripts, fixed setup/binding buffers, every fixed AES
  byte result and SHAKE result are summed. An extra 15 bytes per result covers
  AES block padding, before applying the same growth factor.
- Sequential scalar Poseidon construction requests two 4-by-8 external
  constant vectors and one 22-element internal vector. Three copies cover
  constructor overlap. This is the pinned x86_64 p3-goldilocks 0.6.1 source,
  whose constructors move these vectors without packed-constant conversion.
- Actual inline sizes of the CPU AES/SHAKE/Poseidon states, scratch owner and
  local descriptors are included. This requested-storage census does not claim
  a compiled stack high-water bound, allocator overhead or full process RSS.

Additional CPU scratch ends only after CPU lowering and callback growth have
retired. CPU graph storage remains charged throughout GPU preparation and
comparison. Raw GPU operations stay within A013's node/arithmetic/crypto paths;
the separate nine-argument GPU manifest hashing helper is never called.

Comparison performs no serialization, hashing, cloning or heap allocation. It
compares every polynomial value, kind, commitment, source and expression index;
every byte value, commitment and source; every expression variant and parameter;
and every operation variant, ordered input, output, parameter and transcript
part. Only the independently issued private graph owner IDs are normalized.
Every referenced ID must still belong to its own actual graph and be in range.
Context and setup seed are also checked. This avoids digest-only or shape-only
equality claims.

Twelve negative checks mutate and restore the actual graph while both original
owners remain live: setup seed, polynomial value, polynomial root, source,
polynomial expression index, byte value, byte root, expression owner, operation
modulus, operation owner, operation order, and missing operation. Capacity is
unchanged. A small CPU test exercises identity normalization and these negative
checks without GPU access; a second CPU test checks exact scratch admission,
additive original-ledger ownership, moves, and refusal/release boundaries.

The ignored GPU selector is:

`rust_verify::committed_backend::source_graph::owned::differential::qualification::gpu_reserved_source_graph_matches_independent_cpu_and_rejects_mutations`

Root should add it as a separate exact `raw-differential` owned-runtime guard
mode using the existing sealed A013 environment. Existing A014 selectors and
their evidence remain unchanged. CPU reference lowering, runtime startup, raw
GPU graph preparation, and exact comparison have separate durations. Mutation
checks and fixture creation are excluded from those durations. None is a
complete-workflow benchmark.

Both graphs are destroyed before exact Session retirement. The final assertions
require zero managed device storage, zero host tree storage, released GPU lease,
and zero original-ledger live bytes. Authorship and source review are separate
from coordinator-run compilation, CPU tests, GPU execution and terminal audits.
