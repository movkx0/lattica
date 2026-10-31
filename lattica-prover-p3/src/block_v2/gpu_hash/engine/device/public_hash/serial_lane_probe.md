# Disconnected single-lane public-hash probe

This source-only experiment adds no production selector, receipt, registration
reuse, protocol change or proof dispatch. The coordinator owns the optional
`all(test, feature = "gpu", feature = "gpu-tuning")` test-module hook, serialized
build, guarded execution and terminal audit. The author ran no build or test.

## Rationale and limits

The long-message implementation uses one sequential sponge spread across eight
or sixteen lanes. Each permutation requires dependent cross-lane exchanges,
including each of 22 partial rounds. The existing one-lane entry point instead
passes an eight-word private array through generic permutation helpers. The new
entry point uses eight named scalar words, keeps diagonal values in named
scalars, explicitly expands the matrix layer and requests round-loop unrolling.
It takes no address of a private state array and executes no shuffle or barrier.

This source shape may let the compiler keep state in registers and avoid some
dependent shuffle instructions. It also serializes arithmetic that other kernels
execute across lanes. Register pressure, instruction scheduling, instruction
cache use, constant loads and spills can defeat the hypothesis. Driver-reported
private storage is not a register count, spill census or occupancy measurement.
No generated-assembly evidence or speedup is claimed before execution.

The CPU comparator's exact small fixture took about 108–109 ms in the
coordinator's `fullgpu-cpu-public-hash-component-screen-1` log. That timing
includes scalar field generation and initialization, unlike this GPU timing's
prebuilt input. The roughly 5.27-second large CPU result uses a synthetic input
with a registration-like field count, not actual registration metadata. These
observations motivate another GPU implementation; they authorize no CPU
substitution, GPURequired receipt or complete-workflow projection.

## Unchanged relation

All four kernels use the existing Goldilocks arithmetic and constants, width 8,
four-word rate, domain/length prefix, initial external layer, 4 full + 22 partial
+ 4 full rounds, zero-filled final input block and canonical four-word output.
The final four state words are overwritten for every absorbed block. No padding,
splitting or parallel hashing of a single sponge is introduced.

For each group of four words the external matrix row is
`sum(x) + x[i] + 2*x[(i+1) mod 4]`. Each output doubles its own group's row and
adds the corresponding row from the other group. The internal matrix uses the
same diagonal multiplication plus the sum of eight words. Balanced additions
can change noncanonical representatives relative to the generic scalar helper;
only canonical field equality is required. Existing arithmetic handles full
u64 representatives. The independent scalar and slice CPU oracles check the
complete final relation.

## Comparison and resource census

One shared program contains four unchanged-or-disconnected entry points:

| Entry point | Global/local work items | Required compiled geometry |
| --- | --- | --- |
| existing cooperative shuffle | 8 / 8 | `[8,1,1]` |
| existing S-box pair | 16 / 16 | `[16,1,1]` |
| existing generic serial | 1 / 1 | `[0,0,0]` (no source attribute) |
| new named-scalar serial | 1 / 1 | `[1,1,1]` |

The existing generic serial control distinguishes the effect of named scalars
from merely choosing one work item. The host requires NVIDIA SM7+ and warp32 for
the shuffle comparisons; it does not fall back. All four actual kernel objects
are built and inspected before global buffers are allocated, then reused.
Missing metadata, wrong geometry, local bytes over 256 or private bytes per work
item over 4096 refuses the test. Serial kernels use the same finite ceilings;
absence of a source local array does not guarantee a zero driver report. The
actual reported bytes remain in the census. This applies existing component
ceilings; it is not a new
allocation authority.

Global backing is unchanged: 32-byte state, 32768-byte input scratch and 752-byte
constants, totaling 33552 requested bytes. The largest global allocation is
32768 bytes. Each call uses at most 32768 bytes of existing host staging. The
largest fixture requests 8388616 bytes and its actual vector capacity is
reported. The four kernels and constant buffers remain live across comparisons;
first-block framing initializes a fresh sponge each call. The maximum message
has 257 dispatches, 262145 permutations, 8388616 upload bytes and 32 download bytes.

Program compilation, selection metadata, source copies, kernel wrappers,
allocator slack, physical warp/register allocation and opaque driver/runtime
storage are outside this requested-buffer census. No process/driver peak or
complete preconstructor memory bound is established. The coordinator's existing
8 GiB managed / 4 GiB context / host / process / zero-swap envelope still applies.
No managed allowance, context reserve, row limit or thread limit is increased.

## Authored validation and timing boundary

The nonignored CPU-only fixture test recomputes the exact A005 input SHA3 and
checks both the scalar streaming and slice CPU digests against the frozen
reference. It creates no OpenCL context. The ignored GPU test checks each of four
kernels against both CPU oracles over 36 domain/length cases, including empty,
odd tails, four-word boundaries and 4096-word chunk transitions. There are 144
correctness hash calls before timing.

Three timing rounds use the same exact 1048577-field A005 fixture. Round order
is cooperative, pair, existing serial, new serial; the second round reverses
that order; the third repeats the first. There are exactly 12 timing records.
No large synthetic registration-count run or actual-registration timing occurs.

Device time is the sum of profiled kernel start-to-end intervals. Wall time
includes canonical validation, staging, input transfers, argument updates,
enqueue, synchronous queue completion, profiling reads and final output read.
It excludes program/queue setup, input creation, SHA3, CPU oracle and reporting.
Setup, correctness, fixture creation and the scalar oracle have separate times.
The overall component wall time includes them and ends after explicit kernel,
buffer and program/queue owner destruction, before the final JSON record.
Successful destruction does not replace the coordinator's terminal audit.

All input and source identities, geometries and timings are emitted as bounded
fixed-case records. Completion records explicitly deny transaction/proof,
receipt, GPURequired preprocessing and complete-workflow qualification. Fewer
instructions or lower component time alone cannot establish a workflow win.
If the candidate fails parity or the storage ceiling it must remain disconnected.

Suggested coordinator checks after installing the test-only hook:

1. `serial_lane_fixture_and_scalar_cpu_oracle_match_a005` (CPU-only).
2. `gpu_serial_lane_cpu_parity_and_alternating_timing --ignored --exact` using
   its full Rust test path, under the serialized GPU guard.
3. Audit 4 kernel census + 1 configuration + 1 input + 12 timing + 1 validation
   records, exact order/digests, raw log/terminal binding and unchanged limits.

Keep failed and slower measurements. Production integration and any full
workflow screening require a separate accepted result and ownership review.

The initial A009 fully unrolled candidate aborted in NVIDIA NVVM compilation
before any kernel census or timing record. The coordinator retained the guarded
run and core backtrace (`fullgpu-serial-lane-gpu-screen-1` and
`fullgpu-serial-lane-stack-backtrace-1`). Revision A009r uses `#pragma unroll 1`
for the same 4/22/4 round loops to reduce compiler expansion without raising the
test-thread stack or any other limit. This is a candidate correction pending
the same correctness, timing, and cleanup checks; it does not establish a
compiler-memory bound or a performance improvement. The original failure
remains evidence. Diagnostic A009d markers are not part of A009r.

A009r compiled successfully under the unchanged stack limit, then the second
guarded GPU screen reported one local byte and failed the extra zero-local
assertion (`fullgpu-serial-lane-gpu-screen-2`). Revision A009s removes only that
unjustified zero assertion; the existing 256-byte local and 4096-byte private
per-work-item ceilings remain unchanged. Correctness and timing are still
pending. Both failed screens remain evidence.
