# Fixed-note OpenCL wrapper backing census (A010)

This disconnected source supports a future reserved fixed-note constructor. It
performs checked arithmetic and no allocation, environment read, driver call,
construction, or dispatch. It grants no authority. The coordinator owns its hook,
release build, CPU canaries, actual reservation integration, and GPU validation.
No test execution or performance claim accompanies this handoff.

The existing 32 GiB worker host allowance, 8 GiB managed device allowance,
4 GiB trusted context reserve, 47 GiB process cap, zero swap, and existing thread
limits remain unchanged. This census separates source-controlled Rust backing
from opaque driver, libc, allocator, helper-process, and operating-system storage.
Those retain their existing guard/reserve obligations. A successful observation
cannot prove an unseen allocation peak.

## Required constructor contract

The actual constructor must consume the bounded selected-device Snapshot and
bind one explicit device, Context and Program. Legacy gpu_device::select/devices
is excluded: it enumerates and retains identity strings for other devices.
There are no source-file inputs, extra compiler options, named kernel arguments,
retained kernel cache, or more than 16 supplied arguments per builder. Native
and quotient calls are serial, with at most two live builder-plus-kernel pairs.
C's fixed-note lifetime review found at most one; the second pair is slack.
The generic witness path and its cached_wave container are outside this scope.

`inventory(nvidia, tuning, source_specialization_allowed)` rejects any actual
runtime Tuning flag and any permission to specialize source. The latter argument
must come from the source-built pre-context NoteQuotientPlan, retained through
NoteDevicePlan into NoteDeviceLease. After engine creation, that same owner must
pin and check the fresh Session before any operation; Session clones share this
one-way Interpreter policy. An unrelated report flag is insufficient. The pin
must make prepare_quotient skip
specialized::prepare entirely, preventing a second Program. The constructor must
hold the shared-quota Reservation before allocating the Context, source or
Program, transfer it into the real runtime owner, and release only after queue
work and helper processes are drained. The arithmetic Census is not that token.
No fallback may start an unreserved alternate constructor after refusal.

One nvidia boolean chooses the already pinned source prefix. It must agree with
the captured device; inventory performs no device query. The exact source list
must match the pinned Engine list. Changing any owner, source fragment, argument
limit, feature, toolchain, or upstream wrapper requires re-auditing this census.
The module is restricted to Linux/x86_64/gpu-bounded-info and rejects unexpected
core reply/count constants. Production hooks are absent from this handoff.

## Backing included

Let S be the complete joined OpenCL source length, including separators, and T
be the generated tuning String length. Compiling gpu-tuning creates T even when
all runtime tuning selections are false. The test-only random reference source
is counted only in cfg(test), exactly as in Engine.

| Owner or overlap | Requested backing allowance |
| --- | --- |
| Joined source, source clone, CString growth and final CString clone | 4 × (S + 1) |
| Tuning String growth, when T is nonzero | 4 × (T + 8) |
| ProgramBuilder vectors, source path/history table, compiler options, context properties, core pointer/length vectors and small descriptors | 64 KiB |
| Bounded reply/raw-to-text/error overlap | 8 × 64 KiB + 4 KiB |
| At most two simultaneous kernel builder/kernel pairs | 2 × 16 KiB |
| Fixed sampler Command parent backing | 4 KiB |
| Fixed sampler read array, counted separately | 8193 bytes |

The source term bounds cumulative requested allocation sizes during source
construction, making it conservative for simultaneous backing. The other rows
bound simultaneous live backing; they do not claim to bound lifetime cumulative
allocation traffic from repeated operations. Adding construction and proving
rows is conservative even though those phases do not all overlap. The sum is
not a measured peak, and no allocator metadata or driver-owned payload is
silently included in it. Inline runtime owners and complete thread stack
allowances remain separately held by the enclosing worker.

ProgramBuilder starts with capacity-64 options, source CString vectors, and a
capacity-64 HashSet<PathBuf> even with no source files. It stores the owned joined
source, clones it into a CString, then clones that CString while extending the
final source vector. ContextProperties starts with capacity 16, is cloned by the
context builder, and produces a raw capacity 32 word vector. Only one explicit
device and three CString source entries are supplied to core creation.

A KernelBuilder starts with capacity 16 arguments. Scalar arguments own small
byte vectors. MemArgs is a BTreeMap<u32, MemCore>; its clone overlaps the original
at build completion. With Rust's B=6, capacity11 B-tree nodes, 16 keys need at
most one root and two leaves. Six nodes for original plus clone, each charged
512 bytes, bound those maps at 3072 bytes. Type metadata is inline and its Vec
is created only after the queried NumArgs equals the supplied count. No named
arguments means the NamedArgs HashMap is absent. The16 KiB pair allowance also
covers argument descriptors/payloads, inline-type vector backing and the short
fixed kernel name. Argument/type query strings are covered by the metadata row.

All driver-sized replies are capped at 64 KiB before allocation by A008. The
fixed path uses one device, queries argument types sequentially, and retains no
metadata history. Raw+parsed text, two argument-type strings and their formatted
error, or one device build log fit the 8-reply overlap allowance. Unbounded source
and environment text must never be formatted into this fixed path's errors.
A retained output/report history requires its own reservation; this census
covers only the fixed small census/error formatting allowance, not proof reports.

The sampler runs /usr/bin/nvidia-smi with two fixed arguments, env_clear plus
LC_ALL=C, piped stdout, and null stdin/stderr. Program/argv0 and argument CStrings
request 116 bytes. Cleared and captured environment strings plus LC_ALL=C request
at most 32 bytes; argv old/new plus envp pointer arrays request 64 bytes. Two
one-entry environment BTreeMaps are charged 1024 bytes each. 4 KiB covers these
parent-side requests. Command/Child inline owners, pipes, libc spawn machinery,
child nvidia-smi address space and driver storage retain enclosing obligations.
Running's kill+wait Drop prevents the token releasing while its child is alive.
The service RuntimeMaxSec guard bounds blocking read/wait; sample is observational.

## CPU canaries and source pins

Four release-only tests are authored: zero-allocation inventory and checked
refusals; actual ProgramBuilder string/option processing; actual scalar argument
builder plus same-layout BTreeMap clone and ContextProperties processing; and
fixed Command construction without spawn. Synthetic source has exact length S.
The map surrogate has MemCore's size/alignment and avoids clRetainMemObject.
These canaries exercise pinned Rust requested allocation behavior. They cannot
replace the source/lifetime contract, a real token, or GPU/runtime validation.

METADATA.json lists SHA-256 pins for the relevant ocl 0.19.7/core 0.11.5 sources,
Rust 1.96 standard-library sources, fixed Engine fragments and dependencies.
Review program.rs get_src_strings/get_includes_eof/get_compiler_options;
kernel.rs KernelBuilder::new/build and MemArgs; core ContextProperties and bounded
reply helpers; Rust B-tree node layout, CString and RawVec growth; and Unix
Command::new/arg/capture_env/construct_envp plus CStringArray/CommandEnv/spawn.
The HashMap implementation is pinned indirectly by Rust 1.96 (hashbrown 0.16.1);
its absent local source is not replaced with an invented exact byte count. The
actual constructor-table canary must pass before consuming this allowance.
