# Private-note research workflow boundary

This optional seven-case screen preserves the private-note direct-v1 proof
profile: two inputs, two outputs, 52-bit values, depth 32, quadratic extension,
hiding and the existing FRI, query, proof-of-work and hash parameters. It has no
RingCT component graph, recursive aggregate, production acceptance or speedup
claim. C017 remains the separate successful fresh-randomness and mutation
qualification; the new screen does not count those probes as workflow work.

The complete interval begins before quota/fixture admission and generation. All
seven deterministic research transactions and fourteen nullifiers must be
distinct before the first dispatch. Each case then constructs fresh public
preparation and an owned fresh GPU runtime/configuration, generates one native
proof, retires that exact runtime, creates and canonically decodes PQNOTE1,
verifies independently on the CPU, copies and decodes a canonical roundtrip,
verifies that copy with the same independent verifier, and destroys the proof
payloads. After all seven cases, it destroys the fixtures and decoding session.
The original reservation for the fixed-size report remains until the caller
destroys the report. Final logging/serialization and separate mutation probes
are outside the interval. The external guard's process timing also includes
process startup and test/report harness overhead, so it is a different metric.

All cases use the same context and have genuinely distinct notes/keys/roots;
context changes are not used as a substitute for distinct spends. Per-case
generation timers are separate from prepare-through-cleanup intervals because
set-wide distinctness must be established before any proof dispatch. The full
suite timer includes the intervening admission and checks; summing selected
subtimings is not substituted for its wall time.

The native report's validated NoteRun interval is retained inline through the
owned encoding. It excludes runtime startup/configuration and final retirement;
the larger `native_dispatch_and_retirement_ns` includes those operations. Public
metadata preparation, handoff decoding, independent CPU verification, roundtrip
and proof payload destruction have separate observations. Inclusive native
intervals must not be added together.

Before each first device query, the original ledger owns both the C017 native
output/first decoder/verifier continuation and the full second packet/decoder/
verifier continuation. The latter's actual tokens transfer into the roundtrip
artifact. No packet is copied before its decoder claim, and no independent
verifier obtains substitute capacity. The scope checks exact original-ledger
identity and the baseline live reservation after every proof is destroyed.
Report storage and fixed arrays have their own preceding reservation.

`host_payload_reservation_peak_bytes` is the actual quota high-water mark for
conservative source payload claims, not RSS or device memory use. Actual
process host/device peaks come from the coordinator's unchanged external guard
and are deliberately absent from this source-only report. They must accompany
the screen result. The envelope remains 8 GiB managed GPU, 4 GiB context reserve,
32 GiB worker host, 24 GiB native/output, at most 47 GiB process, zero swap and
eight Rayon threads. Allocator/runtime/driver internals and compiled stacks
remain guarded externally.

Schema v2 adds the separately guarded concrete CPU producer. It uses exactly
the same seven fixtures, generation/admission and proof cleanup boundary,
canonical decoder, independent verifier and roundtrip helper. Its fresh CPU
configuration and all source payload requests have an original reservation
before proving. See [CPU source bounds](cpu/SOURCE_BOUNDS.md). The legacy
`note::prove` wrapper remains outside this timing and ownership contract.

Every case now reports a stable digest of fixture recipe, context and canonical
public values, separately from its randomized packet hash. Matched CPU/GPU
measurements must agree on all seven statement digests. The CPU report counts
seven fresh CPU proof configurations and zero native GPU runtimes, and records
fresh configuration, trace generation, proving, encoding and cleanup times.
The nested CPU `reported_native_proof_scope_ns` measures `p3_uni_stark::prove`;
only the complete workflow interval is comparable to GPU. Neither source
presence nor a successful single run establishes a speedup. Qualified matched
measurements, resource audits and review remain coordinator obligations.

The optional `managed_device_peak_bytes` field is the high-water mark from
the original managed-allocation accounting owner of the exact retired Engine.
It is read under that owner's lock after Engine destruction and forwarded
through the move-only encoded proof owner. Each GPU case retains its own peak;
the workflow reports their maximum because the seven runtimes run sequentially
and fully retire between cases. CPU cases and CPU workflows report `None`.
This observation excludes opaque context/driver storage and is never a total
process device peak. Both `actual_process_*_peak_bytes` fields remain absent
from this source report and require separately audited guard telemetry.
The inline fields and retirement receipt remain included by the existing
typed `size_of` reservations; there is no new allocation or runtime lookup.
