# Lattica

Lattica is a post-quantum shielded-payment research implementation. A Zig wallet and node state machine use Plonky3 zero-knowledge STARK circuits in Rust. The payment proof path uses hash and FRI assumptions rather than elliptic curves.

`main` is the integration branch for the Apple Metal backend, Linux OpenCL proving, local worker pool, and optional recursive-proof research. Historical branch tips are retained in its history. This combined development snapshot still needs hardware qualification; it is not cleared for value-bearing deployment.

## Start here

- [GPU benchmarking](docs/gpu-benchmarking.md): build matching CPU/GPU binaries, prepare public fixtures, run bounded comparisons, and report throughput.
- [Documentation map](docs/README.md): current guides, specifications, audits, and archived research.
- [Protocol specification](SPEC.md) and [wire format](docs/wire-format.md): protocol and encoding contracts.
- [Audit scope and reproduction](docs/AUDITORS.md): what was reviewed and the remaining security boundaries.

## Repository

| Path | Purpose |
|---|---|
| `src/` | Zig wallet, node, storage, FFI, and demonstrations |
| `lattica-prover-p3/` | Rust proving/verifying circuits, GPU backends, and benchmark controllers |
| `scripts/` | Cross-language integration tools |
| `docs/` | Current guidance, specifications, audits, and retained evidence |
| `lattica-prover/`, `*-spike/` | Historical differential oracle and framework experiments |

The supported toolchain is Rust 1.96 and Zig 0.16, with Python 3 for controllers. Linux GPU runs also need OpenCL, NVIDIA management tools, and a systemd user session. Apple runs need native Apple Silicon macOS and Xcode command-line tools.

## Development boundaries

Wallets retain private witnesses. Aggregation workers receive completed wallet proofs and public inputs. CPU verification remains available for GPU-produced proofs.

The default crate features include OpenCL support. Use `--no-default-features` for CPU-only or Metal builds; `gpu` and `gpu-metal` cannot be enabled together. Block-v2, streaming, Tip5, and lookup research require explicit features. See [GPU architecture](docs/gpu-acceleration.md) and [block proving](docs/block-proving-v2.md).

GPU hardware comparisons must use the same commit, proof profile, public workload, and timing boundary. Older measurements describe their recorded snapshots, not the current integrated head. [Historical reports](docs/benchmarks/README.md) and [development archives](docs/archive/README.md) remain available.
