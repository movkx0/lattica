#!/usr/bin/env bash
# Exercise the REAL cross-language prove/verify path end to end — the seam `zig build test` cannot
# cover, because this host's Zig linker can't link the libc-dependent Rust staticlib (the .sframe crt
# issue). The fix: compile the Zig side to a relocatable object and let the SYSTEM toolchain (cc) do
# the final link, which handles gcc's crt fine.
#
# Two checks:
#   (1) C FFI harness — Rust prove_demo -> Rust verify -> tamper-reject -> double-spend-reject.
#   (2) In-node integration — the live Zig node (node.zig) driving the REAL Rust prover/verifier:
#       Zig builds the witness -> Rust proves -> Zig reconstructs the public inputs -> Rust verifies
#       -> node applies; replay + tampered output are rejected by the real verifier.
#
# Usage: scripts/run-real-integration.sh   (exits non-zero on any failure)
# LATTICA_PROVING_POLICY=gpu-required selects native GPU lifecycle + node proving.
# Run through run-wallet-gpu-worker.py to assign the GPU, backend and budget.
# LATTICA_GPU_BACKEND selects opencl (default) or cuda for gpu-required builds.
# LATTICA_PROVER_LIBRARY can select a prebuilt library; otherwise build offline.
# LATTICA_INTEGRATION_OUT can select a durable output directory.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/with-toolchain.sh
OUT="${LATTICA_INTEGRATION_OUT:-${TMPDIR:-/tmp}/lattica-real-integration}"
mkdir -p "$OUT"
DEVICE_CFLAGS=()

case "${LATTICA_PROVING_POLICY:-compatible}" in
    gpu-required)
        case "${LATTICA_GPU_BACKEND:-opencl}" in
            opencl)
                FEATURES=(--features block-v2-wide-lanes)
                DEVICE_LIBS=(-lOpenCL)
                ;;
            cuda)
                FEATURES=(--no-default-features --features block-v2-wide-lanes,stream,gpu-cuda)
                DEVICE_LIBS=()
                DEVICE_CFLAGS=(-DLATTICA_TEST_CUDA=1)
                ;;
            *)
                echo "LATTICA_GPU_BACKEND must be opencl or cuda" >&2
                exit 2
                ;;
        esac
        C_FIXTURE=lattica-prover-p3/tests/gpu_lifecycle.c
        INTEGRATION_ROOT=src/integration_node_gpu.zig
        ;;
    compatible|cpu-required)
        FEATURES=(--no-default-features --features block-v2-wide-lanes,stream)
        DEVICE_LIBS=()
        C_FIXTURE=lattica-prover-p3/tests/ffi_integration.c
        INTEGRATION_ROOT=src/integration_node.zig
        ;;
    *)
        echo "LATTICA_PROVING_POLICY must be compatible, cpu-required or gpu-required" >&2
        exit 2
        ;;
esac

if [[ -n "${LATTICA_PROVER_LIBRARY:-}" ]]; then
    LIB="$LATTICA_PROVER_LIBRARY"
else
    echo "== building the prover staticlib (release) =="
    ( cd lattica-prover-p3 && cargo build --offline --release --lib "${FEATURES[@]}" )
    LIB="lattica-prover-p3/target/release/liblattica_prover_p3.a"
fi
[[ -f "$LIB" ]] || { echo "Prover library not found: $LIB" >&2; exit 2; }

echo "== (1) C FFI harness =="
cc "${DEVICE_CFLAGS[@]}" "$C_FIXTURE" "$LIB" "${DEVICE_LIBS[@]}" -lpthread -ldl -lm -o "$OUT/ffi_it"
"$OUT/ffi_it"

echo "== (2) in-node integration (live node + REAL Rust prove/verify) =="
# -fno-stack-check: omit __zig_probe_stack so the system linker (not Zig's) resolves all symbols.
zig build-obj "$INTEGRATION_ROOT" -OReleaseSafe -lc -fno-stack-check -femit-bin="$OUT/it_node.o"
cc "$OUT/it_node.o" "$LIB" "${DEVICE_LIBS[@]}" -lpthread -ldl -lm -o "$OUT/it_node"
"$OUT/it_node"

echo "== real integration: ALL PASS =="
