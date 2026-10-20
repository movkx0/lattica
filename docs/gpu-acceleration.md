# GPU proving

Use [GPU benchmarking](gpu-benchmarking.md) for commands. This page describes the current integrated source; historical measurements and detailed development logs are in the [archive](archive/gpu-acceleration-2026-10-17.md).

## Backends

| Platform | Build feature | Execution and qualification |
|---|---|---|
| Linux OpenCL | `gpu` | Device buffers, GPU proving stages, and systemd resource controllers. The current inventory/admission scripts require NVIDIA UUIDs and `nvidia-smi`. |
| Linux CUDA | `gpu-cuda` | Opt-in native CUDA workers and private wallet proving. See the [CUDA qualification scope](cuda-prover-plan.md); each device and workload still needs qualification. |
| Apple Silicon | `gpu-metal` | Metal compute, shared-memory prefixes, compact salts, and public preprocessing sharing. Use native Mac qualification. |
| CPU | Neither GPU feature | Independent verification, fixture preparation, reference proofs, and correctness checks. |

Select exactly one GPU transport. Use explicit feature sets and separate target directories when comparing backends. OpenCL code availability alone does not establish AMD or Intel controller support.

## Proving policy and ownership

The proving request records which stages may execute on each backend. Strict GPU requests must reject unavailable stages and cannot silently claim a CPU fallback as GPU work. Device-owned paths retain trace, quotient, opening, and FRI data on the GPU where supported. Completion accounting checks the operations actually performed.

Apple and OpenCL share proving interfaces but have different storage implementations. Metal can retain shared host/device prefixes; OpenCL can retain device-owned buffers. Public preprocessing sharing must preserve profile and input identity. Private salt storage, scratch ownership, allocation limits, and phase lifetimes remain explicit.

CPU verification of a produced proof is separate from prover placement. Do not change proof parameters, randomness, or verification rules to improve a hardware benchmark.

## Workers and memory

Start with one worker per GPU. A pool can schedule independent jobs across multiple devices; sharing one device between workers is an opt-in experiment with additional admission requirements. Host RAM, managed device memory, per-allocation bounds, driver/context overhead, scratch, and free-memory headroom all count.

The full owned proving path holds its heavy memory phase through proof completion. The host-trace path can release that phase after retiring trace prefixes and entering the bounded late phase. Apple and Linux experiment settings use separate environment namespaces.

## Native GPU wallet startup

Select `-Dgpu-backend=cuda` or `-Dgpu-backend=opencl` and pass a matching Rust static library with `-Dprover-library=PATH`. The existing `-Dgpu-prover=true` option still selects OpenCL. CUDA builds require Linux and do not link OpenCL. Build the Rust library with `--no-default-features --features block-v2-host,stream,gpu-cuda` for CUDA, or replace `gpu-cuda` with `gpu` for OpenCL; keep separate target directories.

`zig build install build-ffi -Doptimize=ReleaseSafe -Dgpu-backend=cuda -Dprover-library=PATH` builds the wallet and standalone FFI tests without starting GPU work. The native bridge builder likewise accepts `--gpu-backend cuda`; its existing `--gpu` option still selects OpenCL. Neither build command authorizes or initializes a GPU worker.

Run GPU executables in an admitted wallet service with `LATTICA_PROVING_POLICY=gpu-required`, an explicit device UUID, matched resource limits, and an 8 MiB stack limit. CUDA uses the `lattica-wallet-local-cuda-v1` assignment schema, including its per-allocation ceiling and headroom; OpenCL uses `lattica-wallet-local-gpu-v1` and its required stage switches. GPU Zig roots use bounded signal-stack settings and OS fatal-signal handling while preserving ordinary panic reports and runtime safety checks. CUDA initialization, proving, drain, and shutdown must share one process lifetime; reuse after shutdown requires a fresh process.

The [Zig host qualification](evidence/cuda-zig-host-2026-10-19.json) covers CUDA and OpenCL wallet/FFI execution, a CPU FFI reference, and four native CUDA wallet fixtures with an independent CPU audit. The subsequent [native journal qualification](evidence/cuda-native-host-2026-10-19.json) applies two four-input CUDA-produced branches and verifies process restart, reorganization and injected storage-error recovery. Full-capacity delivery and sustained transaction throughput remain unqualified. See the [native integration instructions](../lattica-prover-p3/scripts/block-v2-pool-README.txt) and retained [OpenCL startup details](archive/gpu-acceleration-2026-10-17.md#native-gpu-wallet-startup) for the surrounding service workflow. The default mock demonstration cannot satisfy a strict proving request.

## Current limits

The merged code needs new per-device checks. Historical RTX 5080 and Apple results do not qualify this head, a different driver, or a different proof capacity. Full cold aggregation, finalization deadlines, durable host delivery, and security review remain distinct gates. See [block proving](block-proving-v2.md) and [bounded execution](bounded-execution-engine.md).
