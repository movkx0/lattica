# Native constructor OpenCL wrapper census

This continues NATIVE_STAGING.md against the installed ocl 0.19.7 and ocl-core
0.11.5 source. It is a source inventory, not a constructor memory bound. No
wrapper, kernel dispatch, diagnostic behavior or resource limit is changed.

## Current operation path

The raw arithmetic, raw crypto and node-commitment implementations each call
`engine.pq.kernel_builder(name).build()`. ProQue constructs a fresh KernelBuilder
for every call; an existing compiled program does not eliminate this work.

The finite wrappers visible before driver queries are:

| Owner | Actual fixed-profile source shape |
| --- | --- |
| KernelBuilder arguments | Vec with initial capacity 16; raw arithmetic and crypto add four buffer arguments; node commitment adds eight arguments |
| By-value node arguments | `kind: u32` and `modulus: u64` each become an owned Vec of bytes through ArgValKeeper::OwnedPrm; they are not inline in the argument Vec |
| KernelBuilder name | Owned String from one of seven static kernel names, at most 24 bytes, plus create_kernel's temporary CString |
| Named arguments | None: these paths call only positional `.arg`, so NamedArgs has no HashMap allocation |
| Buffer retention | MemArgs owns a BTreeMap keyed by argument index: four entries for raw arithmetic/crypto, six for node commitment; build clones that map into the returned Kernel |
| Argument types | Vec reserved for the reported argument count only after equality with the supplied argument count has been checked |

These counts are not a complete byte total: internal ArgValKeeper/ArgType layouts,
the two live BTree owners, queue/core-object references and cleanup lifetimes must
still be charged. MemCore cloning retains an OpenCL object; its Rust value is a
handle, not a copy of the device buffer. The driver object's lifetime continues
until all owning references retire.

## Queries allocate on successful kernel construction

`KernelBuilder::build` first calls `create_kernel`, then queries
`KernelInfo::NumArgs`. It unconditionally calls `ArgType::from_kern_and_idx` for
each argument. The loop still runs when `disable_arg_type_check` was requested;
that flag skips comparison and discards the collected types afterward.

Each argument-type lookup reaches this chain:

1. `arg_info` asks the Kernel for device versions.
2. Kernel obtains its Program, then `ProgramInfo::Devices`. `bytes_into_vec`
   reinterprets the byte Vec allocation and calls `shrink_to_fit`; this is an
   ownership transfer with possible reallocation, not a copied device Vec.
3. `device_versions` allocates a result Vec and asks each device for
   `DeviceInfo::Version`. The driver-provided version includes its vendor suffix.
   Parsing additionally collects dot-separated version components into a Vec
   before checking that there are exactly two components.
4. `get_kernel_arg_info` asks the driver for the `KernelArgInfo::TypeName` size,
   then allocates a Vec<u8> of that size before fetching the bytes.
5. `bytes_into_string` consumes that Vec into a String and copies `str.trim()` to
   a second String. The original byte allocation remains live during the copy.
6. A type mismatch additionally obtains TypeName and Name Strings for its error.

The installed wrappers use the returned `result_size` to allocate before any
application-side ceiling is applied. This includes the device-info and
program-info helpers. NumArgs itself has a fixed OpenCL scalar representation;
the program device count can be tied to the actual engine's construction.
Neither fact bounds the version/type/name Strings in the current source path.
No source ceiling for those buffers has been established here. In particular,
observing a short value from one driver run is not a preallocation bound.

Known `CL_KERNEL_ARG_INFO_NOT_AVAILABLE` and empty-argument-info errors become
unknown ArgType values, but the device/version query has already occurred.
Those escape hatches do not remove the allocations from the admitted path.

## Distinguish diagnostic sources

`create_kernel` allocates a CString for a static kernel name. Its ApiError uses a
static function name and that same bounded name as optional context. API errors
from some buffer, finish and object-retain/release calls carry only fixed enum
status and static function names. Their formatted length can therefore be
derived from the actual reachable variants; it is incorrect to describe all
OpenCL errors as arbitrary driver logs.

However, both `ocl_core::set_kernel_arg` and `ocl_core::enqueue_kernel` call
`get_kernel_name` after a failed driver operation. That introduces another
driver-sized info Vec/String before returning the error. Replacing only
KernelBuilder with these two lower-level helpers leaves the failure-path gap.

Argument-type errors can own queried names; device-version parsing can retain
queried version text. These concrete upstream owners remain unbounded by the
application's current constructor plan. Formatting or truncating the final
String cannot bound the earlier query allocation. `bytes_into_string` can also
retain the original byte Vec in its UTF-8 error.

Program build logs belong to engine/program initialization. The per-operation
path uses an existing program and does not build it. A complete workflow must
identify the real initialization owner and its lifetime separately; this census
does not charge all possible compiler logs to every raw operation.

## Required closure before admission

A genuine constructor needs either a reviewed bounded query path that checks
driver-returned lengths before allocating, or a private fixed-signature launch
path that never makes these introspection queries. The latter requires an
explicit source-linked kernel signature, actual Program/queue identity,
argument type and geometry checks, buffer lifetime through the completion
fence, error propagation and failure cleanup. Calling a raw OpenCL function
alone does not provide those guarantees.

The bounded path must account its Rust wrappers and error owners before they
are created, retain the existing context/managed-memory accounting, and keep
CUDA/Apple behavior isolated. Initialization queries, report publication and
Run/Session cleanup also remain separate obligations. There is no enabled
alternative launch path in this change, and no graph-constructor or PairedV1
dispatch authority is issued.

The smallest isolated candidate is a Linux/OpenCL-only launcher for these seven
kernel variants. It would borrow the actual Engine Program/queue, use static
C-string names, supply arguments through fixed typed entry points, and call
`clSetKernelArg` and `clEnqueueNDRangeKernel` without diagnostic introspection.
An optional argument-count check can use `clGetKernelInfo` with one stack u32
and a fixed supplied size, rejecting errors or a mismatched returned size/count
without allocating. API failures should first be represented by inline kernel,
stage, argument-index and i32 status fields, with a separately bounded formatter.
A non-Clone launch owner would retain its kernel/event and the actual buffer
borrows through completion; partial setup must release the same objects on error.
This is a proposed closure of one allocation gap, not a reviewed implementation
or a replacement for the constructor's cumulative owner and resource planner.
