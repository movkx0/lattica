# Opt-in OpenCL metadata ceilings

This directory vendors `ocl-core` 0.11.5. `UPSTREAM-SHA256SUMS` records the 36
upstream package files, excluding the local registry marker `.cargo-ok`.
`Cargo.toml` and `Cargo.toml.orig` are unchanged upstream files in this source
handoff. The coordinator owns feature declarations, dependency patches and
workspace exclusions. The expected new feature is `bounded-info = []`; it must
not be added to the upstream default feature list.

With that feature absent, upstream allocation and diagnostic paths remain the
default. With it enabled, fixed immutable limits reject oversized metadata
before the selected Rust payload allocations. There is no truncation, fallback,
environment override, admission token or new dispatch authority. A sizing query
may already have run in the driver before a reply allocation is refused.

## Covered paths

All 15 driver-sized reply-buffer families use the same checked boundary:

- platform, device, context and GL context information;
- command queue, memory object, image and sampler information;
- program and program build information;
- kernel, kernel argument and kernel work-group information;
- event and event profiling information.

Each reply is at most 64 KiB. Additional ceilings apply before allocation or
before a scalar reply can reach a caller that allocates from it:

| Metadata | Limit |
| --- | --- |
| Platform enumeration | 8 handles |
| Device enumeration, context/program/GL device arrays, version list | 64 entries |
| Kernel argument count | 128 |
| Program kernel count | 4096 |
| Work-item dimensions and size arrays | 3 |
| Context properties | 32 pairs plus final zero word |
| Event profiling reply | 8 bytes |
| Image formats | 64 KiB total requested raw and parsed vector backing |
| Program binaries | 64 KiB total size-vector capacity, outer headers, pointer table and payloads |

Typed array byte lengths must divide exactly by their element width. The
context property word count must be odd when nonempty, and its final word must
be zero. These checks do not validate every property key or duplicate. Small
native-endian scalar replies cannot authorize an arbitrarily large argument,
device or kernel fanout. Empty replies retain upstream empty-result handling.

Device enumeration refuses a returned count larger than the caller requested
before the existing unsafe `set_len`. It also refuses counts over 64. The API
can report a larger total when a smaller array was requested; that configuration
now fails explicitly under this feature rather than exposing unwritten entries.

Binary admission charges the actual size vector capacity, not merely its
length. Any binary, aggregate, count or arithmetic overflow fails before nested
payload allocation. Consequently querying binaries of a compiled program that
exceed the 64 KiB aggregate limit is unsupported in this mode. No explicit
binary query was found in the fixed note profile's repository sources; this is
not a guarantee about third-party or diagnostic callers.

Version parsing keeps the upstream case-insensitive first-six-character
`OpenCL` prefix and following exact two-`u16` dotted-word syntax. It no longer
collects an input-dependent substring vector or copies malformed driver text
into the error. Kernel argument/enqueue failures retain the original signed
native status without issuing a second kernel-name diagnostic query. Known
statuses still map through `Error::api_status`; unknown values remain available
in `Error::BoundedInfo(ApiFailure)`.

## Accounting boundaries still open

These are ceilings for particular Rust allocation requests, not observed memory
peaks or a whole-constructor bound. In particular:

- The unchanged `bytes_into_string` path can overlap a raw string and trimmed
  copy: up to 2C bytes for a C-byte reply, before allocator overhead. Retained
  results and multiple live queries need separate lifetime accounting.
- Context property parsing uses a `HashMap`. Bounding it to 32 pairs is not a
  complete allocator byte census, including buckets, control bytes and slack.
- Caller `KernelBuilder` vectors, argument ownership, its memory-argument map,
  source strings, compilation inputs, diagnostic wrapper copies and caches are
  separate owners. This patch does not bound arbitrary caller-supplied inputs.
- Vector capacity/allocation slack, typed conversion temporaries, formatting,
  allocator bookkeeping, thread stacks and runtime state require their own
  justified allowance. Existing unsafe FFI parser assumptions remain unchanged.
- Driver calls, contexts, queues, programs, build workspaces and kernel objects
  have opaque host/device allocations. A metadata ceiling does not establish
  that these fit an external or managed allowance.

The fixed Linux note launcher census currently has at most 16 supplied kernel
arguments; 128 is a conservative library ceiling, not that profile's measured
count or charged storage. Both limits need to be distinguished in reports.

The shortest path to a real proving qualification is to integrate and check this
feature, complete the fixed-profile Rust owner/lifetime census, and establish
the remaining context/program/driver admission contract before constructing the
runtime. Then use the existing resource guard for fresh proofs, independent CPU
verification, mutation rejection, artifact round trips and terminal cleanup.
An unresolved opaque bound must leave proving dispatch disabled; increasing an
allowance or labeling metadata checks as full admission does not resolve it.

## Coordinator validation, not executed by the author

The new `bounded_info::tests` are CPU-only: no device query or context creation.
They cover exact limits, arithmetic overflow, malformed replies, tiny scalar
fanouts, callbacks not reached on refusal, real spare size-vector capacity,
version syntax and signed native status preservation. They are authored but
unexecuted in this handoff.

After declaring the opt-in feature, run the filtered library tests with
`--features bounded-info`, and check the default feature build separately.
Audit all relevant Cargo roots and the resolved feature graph: Cargo feature
unification means one enabling dependency affects every user of that same
package in a build. Keep enablement specific to the research profile and report
it explicitly. Upstream's other tests may query a real GPU; do not run an
unfiltered test suite outside the coordinator's serialized validation guard.

No build, test, benchmark, GPU qualification, integration edit or dependency
selection is part of this source-only handoff.
