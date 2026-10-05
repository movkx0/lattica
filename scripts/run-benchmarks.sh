#!/usr/bin/env bash
# Build once, then run the current benchmarks sequentially on the host CPU.
set -euo pipefail
source "$(dirname "$0")/with-toolchain.sh"
cd "$LATTICA_ROOT"
RUNS="${1:-1}"
if [[ $# -gt 1 || ! "$RUNS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Usage: scripts/run-benchmarks.sh [positive-run-count] (default: 1)" >&2
    exit 2
fi
for tool in cargo rustc zig; do
    command -v "$tool" >/dev/null || {
        echo "$tool missing; run scripts/setup-toolchains.sh first." >&2
        exit 1
    }
done
# Plonky3 selects its SIMD implementation at compile time. Use the actual host CPU.
export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native}"
mkdir -p benchmark-results
LOG="$(mktemp "$LATTICA_ROOT/benchmark-results/$(date -u +%Y%m%dT%H%M%SZ).log.XXXXXX")"

run_benchmarks() {
    echo "Lattica benchmarks — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Host: $(uname -s) $(uname -m)"
    rustc -vV
    echo "Zig: $(zig version)"
    echo "RUSTFLAGS: $RUSTFLAGS"
    echo "Runs: $RUNS; Zig ReleaseFast; Rust release; timings exclude compilation"
    zig build -Doptimize=ReleaseFast
    cargo build --locked --release --manifest-path lattica-prover-p3/Cargo.toml --bins
    for ((run = 1; run <= RUNS; run++)); do
        echo "== Run $run/$RUNS: on-chain hashing =="
        ./zig-out/bin/lattica-wallet bench
        echo "== Run $run/$RUNS: production join-split =="
        cargo run --locked --release --manifest-path lattica-prover-p3/Cargo.toml --bin lattica-prover-p3
        echo "== Run $run/$RUNS: field comparison =="
        cargo run --locked --release --manifest-path lattica-prover-p3/Cargo.toml --bin field_compare
    done
}
run_benchmarks 2>&1 | tee "$LOG"
echo "Results saved to $LOG"
