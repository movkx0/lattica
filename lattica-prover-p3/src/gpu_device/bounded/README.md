# Disconnected bounded queries for the shared device identity

The parent gpu_device.rs does not declare this module. The existing devices()
and select() implementations, all runtime callers, and production acceptance
remain unchanged. This is a Linux/x86_64/OpenCL candidate for guarded research
startup, not an admission token, context owner or second production selector.

Request::parse borrows two already bounded values from the root's sealed startup
environment. Both the canonical decimal global OpenCL GPU index and the GPU-
UUID are mandatory. UUID text is 40 bytes; its C representation would be 41 with
the terminator. The helper never enumerates or copies the process environment.
It rejects noncanonical indices, malformed UUIDs and selector disagreement.

Snapshot owns the existing gpu_device::Identity and the actual ocl Platform and
Device handles. No second public identity representation is introduced. Capture
and recheck use the same fixed-query implementation. Recheck validates the same
handle, platform, index, UUID, global memory, maximum allocation, name, driver
and optional PCI data without making new Rust allocations. The caller passes
its current sealed Request again; a changed request fails before enumeration.

## Query census

| Query | Output storage | Admission and consistency checks |
| --- | --- | --- |
| Platform IDs | 8 pointer slots | Count checked before fill; count must remain equal; no null or repeated IDs |
| GPU device IDs | 64 pointer slots plus 64 fixed platform/device entries | Combined global count at most 64; checked before each fill; stable counts; no null or repeated devices |
| UUID | 16 aligned bytes | Exact size on both calls; unique matching UUID must have the requested global index |
| Global memory | 8 aligned bytes | Exact size; nonzero; compared on recheck |
| Maximum allocation | 8 aligned bytes | Exact size; nonzero and at most global memory; compared on recheck |
| Device name | 256 aligned bytes, including NUL | Size checked before fill; fill size must match; terminal NUL, no interior NUL, UTF-8 and nonempty trimmed text |
| Driver version | 256 aligned bytes, including NUL | Same checks as name |
| Optional PCI data | 16 aligned bytes | Exact four native-endian u32 values; existing textual formatting fits 37 bytes |

CL_DEVICE_NOT_FOUND permits an empty platform. CL_INVALID_VALUE on an initial
UUID size query means that device has no available UUID; it cannot satisfy the
mandatory selected UUID. The same initial status omits optional PCI data. Other
errors and every failed fill are reported with their original signed status.
There is no retry, uncapped query, version/extension query or fallback selector.

All OpenCL calls are direct FFI. No ocl-core result/error formatter is used, and
the candidate never formats ocl::Device, whose Debug implementation performs
many additional queries. Error contains fixed enums, i32 status and usize count;
its diagnostic writer has 192 inline bytes. Counts never choose a Vec capacity.
Driver-reported lengths are checked before the first identity String allocation.
The OpenCL C ABI must still obey the supplied output capacities; this code does
not bound allocations performed inside a driver or ICD loader.

## Rust storage and ownership inventory

Scratch is an actual caller-owned fixed value containing all ID arrays and a
reused, eight-byte-aligned 256-byte query buffer. footprint() exposes size_of for
Scratch, one FixedSelection, Snapshot and Diagnostic. These are source owners,
not a claimed compiler stack high-water mark: stack copies, call frames, startup,
driver and allocator metadata remain enclosing obligations. A fixed selection
also holds two inline text buffers and optional PCI text while strings are built.

Successful capture makes at most four Rust allocation requests, all retained
inside the unchanged Identity:

| Owner | Maximum requested bytes |
| --- | ---: |
| UUID String | 40 |
| Name String | 255 |
| Driver String | 255 |
| Optional PCI String | 37 |
| Total | 587 |

Each String starts empty, calls try_reserve_exact once with the validated text
length, then copies within that capacity. Pinned Rust 1.96 String delegates to
Vec::try_reserve_exact; RawVec::grow_exact uses len + additional and records that
capacity. This is a requested-byte claim, not allocator usable size or RSS. A
partial allocation error drops strings already created. Capture rejection before
string construction, recheck, and bounded error formatting request zero Rust
heap bytes. The feature-stream mock observer tests these source expectations.

Snapshot intentionally has no Clone and exposes Identity only by shared borrow,
or by moving it together with its handles through into_parts. Its enclosing
admission token must follow whichever owner retains those strings; this helper
does not invent that token. Caller-created copies, serialization and reports
need their own prior reservation. Preserved envelope: 8 GiB managed GPU, 4 GiB
context reserve and all existing worker/process/thread/row limits.

## Verification authored, not executed

CPU tests cover exact boundary counts, growth between query/fill calls, null and
duplicate IDs/UUIDs, UUID/index disagreement, unsupported optional fields, short
and oversized reported lengths, malformed strings, impossible memory limits,
original signed errors, all recheck identity fields, and exact successful String
allocation requests. An ignored real-device test compares the candidate with the
existing shared selector and then rechecks; reference calls and environment
copies are explicitly outside the candidate heap claim. Root must supply the
sealed process guard and serialize that qualification.

No constructor, note producer, native proof, PairedV1 or complete-workflow
authority follows from this query helper. Opaque driver/context/program memory,
generic ocl wrappers and actual enclosing token lifetimes remain separate gaps.
