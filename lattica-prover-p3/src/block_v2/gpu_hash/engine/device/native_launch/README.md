# Disconnected bounded native launcher candidate

This module is not declared by device.rs and has no production callers. A test
hook may compile it only under Linux, x86_64 and feature gpu. It does not change
CUDA, Apple, public APIs, protocol parameters or PairedV1 dispatch. No benchmark
or full-constructor memory claim is made.

The seven kernels are the existing raw arithmetic, five raw crypto and node
commitment kernels. Their OpenCL source is unchanged. The entry points accept
the actual Engine and actual SecretAllocation owners. They do not create GPU
buffers, accept a caller-selected kernel name, return a detached event, or issue
an admission token.

The raw launcher replaces one operation's KernelBuilder path with fixed FFI:

- Source-linked typed arguments and checked exact buffer dimensions precede all
  writes and launches. Arithmetic checks metadata, schedule bounds, permutation
  uniqueness, modulus, counts, output/status lengths and work dimensions.
- All actual buffers must belong to the Engine's exact cached default queue,
  have no subbuffer offset and have distinct handles. Node constants come from
  the Engine; their lengths are derived from the actual Poseidon constants.
- Arithmetic and crypto upload their own checked metadata. Crypto expands its
  borrowed bytes into a scrubbed 2048-word stack staging array. It retains the
  original AES domain/counter and native segmentation/algorithm. This candidate
  additionally rejects AES counter wrap; genuine constructor profiles fit.
- Fixed stack queries check queue flags, kernel argument count, completion and
  profiling. No query length selects an allocation. No argument type/name,
  device version, program device-list or driver diagnostic String is requested.
- clSetKernelArg and clEnqueueNDRangeKernel are called directly. Using ocl-core
  helpers here would reintroduce kernel-name queries on failure.
- At most two kernel/event owners coexist (AES S-box setup and AES output).
  Both Engine queues drain before events/kernels retire and before the real
  borrowed allocation/context owners can drop. Host staging is declared before
  the launch scope so it is scrubbed only after error/unwind queue cleanup.
- A completed operation returns fixed timing entries. It neither accepts the
  raw output nor manufactures a proving Report. The eventual caller must check
  the kernel's output/status and attach the timings to its existing Run.

Every driver failure retains its signed i32 code, static kernel, phase and
argument index. Diagnostic formatting uses a 192-byte inline writer. An uncertain
cleanup aborts the worker while its owners still live, using one bounded Linux
write of that diagnostic. The scope never retries kernel dispatch. Completion
failure can trigger the same final queue drain on Drop as the existing fence;
reference-release failure is terminal and is not retried by complete().

The module itself constructs no Rust heap owner. Its largest explicit scratch
array is the 16 KiB byte-upload staging array. This statement does not bound
opaque OpenCL driver allocations, existing Engine/Session initialization,
SecretAllocation construction/scrub, kernel-result readback, Run/report/error
owners outside this module, or the graph constructor. All of those remain in
the enclosing admission census; the 4 GiB context reserve and 8 GiB managed
allowance are unchanged.

## Verification authored, not executed

CPU tests cover actual source signatures, malformed arithmetic metadata and
schedule indices, crypto profile/counter boundaries, typed argument/signature
refusal before enqueue, partial setup/enqueue/profiling/async failure, queue
drain before handle and owner destruction, panic cleanup, two-kernel completion,
and signed diagnostic preservation. Under feature stream, the existing Rust
allocation observer checks that the mocked scope plus formatting requests no
heap storage; this does not observe the external OpenCL driver.

The separate ignored GPU test compares all seven kernel names with the existing
operation path, including all ten arithmetic opcodes, SHAKE absorb/squeeze
boundaries, both samplers, all node encodings, rejection statuses and allocation
retirement. Its synthetic NTT/multiplication schedules check launcher parity;
they do not qualify those schedules as a cryptographic construction. It requires
8 GiB managed storage and 4 GiB context reserve, and the coordinator must supply
the existing exclusive-device, 47 GiB process/zero-swap guard. Test readback,
reporting and the existing launcher remain outside this module's heap claim.

An ignored CPU-only subprocess test injects persistent drain, event-release and
kernel-release failures. Child core dumps are disabled; each child must exit by
SIGABRT with its bounded original-status diagnostic before owners can retire.
These verification sources have not been executed by the implementation agent.

Before any routing change, the coordinator must compile these files, execute the
CPU tests serially, compare all seven actual kernels with the current launcher
on the selected GPU, and exercise fatal cleanup in an isolated subprocess.
Native status/mutation checks and terminal accounting must remain intact. A
whole-workflow speedup requires the separate matched benchmark protocol. The
candidate alone supplies neither constructor ownership nor workflow authority.
