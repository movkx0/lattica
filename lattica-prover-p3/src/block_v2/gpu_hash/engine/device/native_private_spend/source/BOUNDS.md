# Native n10 spend source census

This is a source-derived requested-backing bound, not a measured memory peak,
reservation or proof authority. It requires Linux x86_64, bounded OpenCL info,
the quota feature, the unchanged non-oracle native controller and canonical
`SpendLimits::bounded(24 << 30)`. That 24 GiB API ceiling is never charged as an
allocation. The enclosing workflow retains the existing worker, managed GPU,
context reserve, process, no-swap, thread and row limits.

The four request vectors own 454,656 bytes. Their original fixture owner must
retain that backing; `check_request` checks all four private lengths and
capacities without allocation or repacking. Packed staging separately owns
455,976 bytes, including the fresh entropy key. Six concrete device matrices
own 3,151,744 bytes, derived from the controller's exact input/arena/offset/RNG/
status/rejection-offset word counts. The controller's older 64 KiB API staging
allowance is not used as a footprint fact.

`requirements()` charges packed staging, specs, memory-plan output lengths,
matrix/Arc allocation owners, separate readback words, dispatch vectors, one
real DeviceSession and its host quota, native API/controller declared owners,
OpenCL builders, bounded diagnostics and actual six-buffer device bytes.
The specs `Result<Vec<_>>` collection is bounded by capacities 4 then 8. The
description Vec requests 2 then 4 entries. The fallible dispatch collection
and final push are bounded by capacities 4 then 8; both old and new backing
are charged without relying on an allocator extending in place. Maximum
dispatch length is four, not one: three preparations and one step kernel.
These requests repeat serially; no per-attempt cache is retained.

`output_requirements()` separately charges the statement/proof/key backing
(293,312 bytes) and concrete returned owners. The private-key Vec capacity is
checked too. The caller keeps the output original while separately decoding,
independently verifying and wiping private output keys. `check_evidence`
requires exact six-buffer bytes, both full phase masks and the locked kernel
source identity. Evidence is an observation and cannot fabricate dispatch.

`shared_static_requirements()` charges the static bundle, source-lock text,
layout tables and strings. Eleven source locks are checked before returning a
plan. The controller/types/API/device parent hooks are hashed as postimages.
The ocl 0.19.7 Cargo package checksum is checked; source drift refuses the
census and requires review. No driver, environment or entropy call is made.

The ocl inventory follows 0.19.7 `standard/program.rs` and `kernel.rs`:

- ProgramBuilder requests 64-entry options; source/includes/EOF and compiler
  option Vecs also start at 64. Its empty file-history HashSet requests 128
  buckets. The two newline CStrings, compile-option copies, device selector,
  source-pointer/length lists and public typed descriptors are additive.
- Five copies of bundle length plus terminator bound the builder String,
  cloned input, includes/source CStrings and moving conversion/shrink overlap.
- KernelBuilder requests 16 argument slots, with at most nine supplied values.
  Its private argument enum is bounded by a C-layout mirror of the same three
  payload types. Scalars allocate at most one u64 per argument. At most four
  Mem args fit one 11-key BTree leaf; a full internal-node bound is charged to
  the builder and all four retained kernels. Argument types have two enums and
  a bool, each bounded by a whole machine word. No named arguments or retained
  kernel cache occurs.
- Eight bounded 64 KiB reply/error slabs follow the maintained bounded OCL
  inventory. Fixed diagnostics are bounded by the complete controller and
  dispatch source lengths plus 128 decimal u64 values. These are additive to
  startup; no prior wrapper allowance is subtracted.

The Rust 1.96.0 allocation canaries exercise the actual ProgramBuilder and
KernelBuilder host code, request/output Vec ownership and the allocation-free
planner. These tests require the integration coordinator's serialized run.
Opaque OpenCL compiler/driver internals, allocator bookkeeping and fixed
thread stacks retain their existing context/process owners. The plan does
not claim those opaque internals as exact requested Rust backing.

The generation wrapper consumes this private-field source plan, checks both
same-ledger originals before dispatch, derives limits only from the plan,
and checks output/evidence before reporting. A failed operation is terminal;
no retry or replacement reservation is introduced. Native context shutdown
still precedes runtime-original release, and the authentic terminal checks a
strictly newer pristine planning context before the root generation bridge.
