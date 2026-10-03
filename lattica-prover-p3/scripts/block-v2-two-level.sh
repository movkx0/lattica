#!/usr/bin/env bash
# Research only. Public proof artifacts are temporary; wallet witnesses never leave
# the fixture. Kernel cgroup limits cover every subprocess within each serial stage.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
BIN="${LATTICA_V2_RUNNER:-$ROOT/target/release/block-v2-recursion-probe}"
AUDIT="${LATTICA_V2_AUDITOR:-$ROOT/target/release/block-v2-artifact-audit}"
RESUME=0
if [[ "${1:-}" == --resume-registered && $# == 3 ]]; then
    RESUME=1
    DIR="$2"
    PROFILE="$3"
elif [[ $# -le 1 && "${1:-}" != --* ]]; then
    DIR="${1:-$ROOT/target/block-v2-two-level-$(date +%s)-$$}"
else
    echo 'Usage: block-v2-two-level.sh [NEW_DIRECTORY] | --resume-registered DIRECTORY PINNED_PROFILE_HEX' >&2
    exit 1
fi
if [[ ! -x "$BIN" || ! -x "$AUDIT" ]]; then
    echo 'Build first: cargo build --offline --release --features block-v2,stream --bin block-v2-recursion-probe --bin block-v2-artifact-audit' >&2
    exit 1
fi
echo "job_directory=$DIR"
sha256sum "$BIN" "$AUDIT"
STAGE=0
case "${LATTICA_CACHE_PREPROCESSING:-0}" in
    0|1) ;;
    *) echo 'LATTICA_CACHE_PREPROCESSING must be 0 or 1' >&2; exit 1 ;;
esac
monitor_check() {
    # Optional guard supplied by the bounded GPU trial launcher. Check both
    # sides of every stage: systemd can report a SIGTERM as a clean service stop.
    if [[ -n "${LATTICA_V2_GPU_MONITOR_PID:-}" || -n "${LATTICA_V2_GPU_MONITOR_FAILURE:-}" ]]; then
        if [[ ! "${LATTICA_V2_GPU_MONITOR_PID:-}" =~ ^[0-9]+$ \
            || -z "${LATTICA_V2_GPU_MONITOR_FAILURE:-}" \
            || -e "$LATTICA_V2_GPU_MONITOR_FAILURE" ]] \
            || ! kill -0 "$LATTICA_V2_GPU_MONITOR_PID" 2>/dev/null; then
            echo 'GPU monitoring failed; refusing another proving stage.' >&2
            exit 1
        fi
    fi
}
job() {
    monitor_check
    STAGE=$((STAGE + 1))
    local unit="lattica-v2-$$-$STAGE.service"
    local -a accounting=()
    case "${LATTICA_V2_CAPTURE_ACCOUNTING:-0}" in
        0) ;;
        1)
            accounting=(
                "--property=ExecStopPost=/usr/bin/python3 -B \"$ROOT/scripts/block-v2-accounting.py\""
                "--setenv=LATTICA_V2_ACCOUNTING_UNIT=$unit"
            )
            ;;
        *) echo 'LATTICA_V2_CAPTURE_ACCOUNTING must be 0 or 1' >&2; exit 1 ;;
    esac
    systemd-run --user --wait --pipe --collect --unit="lattica-v2-$$-$STAGE" \
        "${accounting[@]}" \
        --property=MemoryAccounting=yes --property=MemoryHigh=40G --property=MemoryMax=44G \
        --property=MemorySwapMax=0 --property=RuntimeMaxSec=7200 --property=LimitCORE=0 \
        --setenv=RAYON_NUM_THREADS=8 --setenv=LATTICA_FFT_TRACE=1 \
        --setenv="LATTICA_PROFILE=${LATTICA_PROFILE:-0}" \
        --setenv="LATTICA_PROFILE_TIMELINE=${LATTICA_PROFILE_TIMELINE:-0}" \
        --setenv="LATTICA_V2_GPU_HASH=${LATTICA_V2_GPU_HASH:-0}" \
        --setenv="LATTICA_V2_GPU_PIPELINE=${LATTICA_V2_GPU_PIPELINE:-0}" \
        --setenv="LATTICA_V2_GPU_RETAIN_TREES=${LATTICA_V2_GPU_RETAIN_TREES:-0}" \
        --setenv="LATTICA_V2_GPU_DEVICE=${LATTICA_V2_GPU_DEVICE:-0}" \
        --setenv="LATTICA_SPILL_DIR=$DIR/scratch" \
        --setenv=LATTICA_SPILL_MAX_BYTES=128849018880 \
        "$@"
    monitor_check
}
probe() { job "$BIN" "$@"; }
if [[ $RESUME == 0 ]]; then
    probe prepare "$DIR"
    for mode in 1 2 3; do probe register "$DIR" "$mode"; done
    probe finish-registry "$DIR"
    PROFILE="$(<"$DIR/profile.hex")"
fi
# Check the independent pin, all wallet proofs, expected root, and every existing
# node before resuming. Each new proof also recomputes and checks its program key.
probe check-registered "$DIR" "$PROFILE"
if [[ "${LATTICA_CACHE_PREPROCESSING:-0}" == 1 ]]; then
    # Serial proofs; one preprocessing workspace per process, never parallel
    # 40-GiB provers. Each command verifies the independently pinned registry.
    probe wrap-all "$DIR" "$PROFILE"
    probe merge-all "$DIR" "$PROFILE"
else
    for index in 0 1 2 3; do
        if [[ ! -e "$DIR/node.0.$index" ]]; then probe wrap "$DIR" "$index"; fi
    done
    for index in 0 1; do
        if [[ ! -e "$DIR/node.1.$index" ]]; then probe merge "$DIR" 1 "$index"; fi
    done
    if [[ ! -e "$DIR/node.2.0" ]]; then probe merge "$DIR" 2 0; fi
fi
probe remove-inners "$DIR"
probe verify-root "$DIR" "$PROFILE"
job "$AUDIT" root "$DIR" "$PROFILE"
echo "verified_root_artifact=$DIR/node.2.0"
