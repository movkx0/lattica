#!/usr/bin/env bash
# Research-only NVIDIA/OpenCL trial. Run this controller in a <=3 GiB, swap-free
# user service; the serial proving stages use their own <=44 GiB sibling services.
# Inputs are trusted public proof fixtures, never wallet witnesses.
set -euo pipefail
umask 077

if [[ $# != 3 || ! "$3" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo 'Usage: block-v2-gpu-trial.sh REGISTERED_PUBLIC_FIXTURE NEW_JOB_DIRECTORY INDEPENDENT_PROFILE_HEX' >&2
    exit 1
fi
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
FIXTURE="$(realpath -e -- "$1")"
DIR="$(realpath -m -- "$2")"
PROFILE="$3"
BIN="$(realpath -e -- "${LATTICA_V2_RUNNER:-$ROOT/target/release/block-v2-recursion-probe}")"
AUDIT="$(realpath -e -- "${LATTICA_V2_AUDITOR:-$ROOT/target/release/block-v2-artifact-audit}")"
export LATTICA_V2_RUNNER="$BIN" LATTICA_V2_AUDITOR="$AUDIT"
[[ -x "$BIN" && -x "$AUDIT" && -d "$FIXTURE" && ! -e "$DIR" ]]
[[ "$DIR" != *$'\n'* && "$FIXTURE" != *$'\n'* ]]

# Enforce the auxiliary part of the 48 GiB aggregate RAM budget. The controller
# and all of its monitoring processes share this cgroup; systemd-run's proving
# services are siblings, not children of it.
CGROUP="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
MEMORY_MAX="$(<"/sys/fs/cgroup$CGROUP/memory.max")"
SWAP_MAX="$(<"/sys/fs/cgroup$CGROUP/memory.swap.max")"
if [[ ! "$MEMORY_MAX" =~ ^[0-9]+$ ]] || (( MEMORY_MAX > 3221225472 )) || [[ "$SWAP_MAX" != 0 ]]; then
    echo 'Controller requires cgroup MemoryMax<=3G and MemorySwapMax=0.' >&2
    exit 1
fi

# Serialize complete trials (including gaps between the engine's per-process
# GPU leases). This cooperative lock does not cover unrelated applications/users.
LEASE="/tmp/lattica-v2-gpu-trial-$(id -u)"
mkdir -m 700 -- "$LEASE" 2>/dev/null || [[ -d "$LEASE" ]]
[[ ! -L "$LEASE" && "$(stat -c '%u:%a' -- "$LEASE")" == "$(id -u):700" ]]
[[ ! -L "$LEASE/exclusive.lock" ]]
exec 9>>"$LEASE/exclusive.lock"
[[ -f /proc/self/fd/9 && "$(stat -Lc '%u:%a' /proc/self/fd/9)" == "$(id -u):600" ]]
flock -n 9 || { echo 'Another GPU trial controller holds the lease.' >&2; exit 1; }

for file in wallet.{0,1,2,3} key.{1,2,3} expected height profile.hex; do
    [[ -f "$FIXTURE/$file" && ! -L "$FIXTURE/$file" ]]
    [[ "$(stat -c %s -- "$FIXTURE/$file")" -le 2097152 ]]
done
[[ "$(<"$FIXTURE/profile.hex")" == "$PROFILE" ]]
mkdir -m 700 -- "$DIR" "$DIR/scratch"
cp --no-clobber -- "$FIXTURE"/wallet.{0,1,2,3} "$FIXTURE"/key.{1,2,3} \
    "$FIXTURE"/expected "$FIXTURE"/height "$FIXTURE"/profile.hex "$DIR/"
sha256sum "$BIN" "$AUDIT" "$DIR"/wallet.{0,1,2,3}
BIN_SHA="$(sha256sum "$BIN")"
AUDIT_SHA="$(sha256sum "$AUDIT")"

VRAM="$DIR/vram.csv"
FAIL="$DIR/vram-failure.log"
DONE="$DIR/monitor-complete"
printf 'utc_epoch_ns,pid,used_mib\n' > "$VRAM"
scoped_pid() {
    local pid="$1"
    local executable
    executable="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    [[ "$executable" == "$BIN" || "$executable" == "$BIN (deleted)" ]] || return 1
    local -a args=()
    [[ -r "/proc/$pid/cmdline" ]] || return 1
    mapfile -d '' -t args < "/proc/$pid/cmdline" || return 1
    [[ "${args[2]:-}" == "$DIR" ]]
}
stop_provers() {
    local exe pid
    for exe in /proc/[0-9]*/exe; do
        pid=${exe#/proc/}; pid=${pid%/exe}
        scoped_pid "$pid" || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
}
fail_monitor() {
    local first=0
    if [[ ! -e "$FAIL" ]]; then
        printf '%s\n' "$*" > "$FAIL"
        first=1
    fi
    if (( first )); then kill -TERM "$$" 2>/dev/null || true; fi
    stop_provers
    return 1
}
watch_gpu() {
    local rows stamp sum uuid pid used errors=0
    # Unexpected monitor errors are failures, too, not merely absent samples.
    trap 'if [[ ! -e "$DONE" ]]; then fail_monitor "VRAM monitor exited before completion" || true; fi' EXIT
    while [[ ! -e "$DONE" ]]; do
        if ! rows=$(timeout 5s nvidia-smi --query-compute-apps=gpu_uuid,pid,used_gpu_memory --format=csv,noheader,nounits 2>&1); then
            errors=$((errors + 1))
            if (( errors >= 3 )); then
                fail_monitor "VRAM monitoring failed: $rows"
                return 1
            fi
            sleep 0.5
            continue
        fi
        errors=0
        stamp=$(date -u +%s%N)
        sum=0
        while IFS=, read -r uuid pid used; do
            pid=${pid// /}
            used=${used// /}
            [[ "$pid" =~ ^[0-9]+$ ]] || continue
            scoped_pid "$pid" || continue
            if [[ ! "$used" =~ ^[0-9]+$ ]]; then
                fail_monitor "Unavailable VRAM reading for prover $pid: $used"
                return 1
            fi
            printf '%s,%s,%s\n' "$stamp" "$pid" "$used" >> "$VRAM"
            sum=$((sum + used))
            if (( sum > 12288 )); then
                fail_monitor "Prover GPU memory $sum MiB exceeds 12 GiB"
                return 1
            fi
        done <<< "$rows"
        sleep 0.5
    done
}
WATCH=''
PIPELINE=''
cleanup() {
    local result=$?
    trap - EXIT INT TERM
    if [[ -n "$WATCH" ]]; then touch "$DONE"; fi
    if (( result != 0 )); then
        if [[ -n "$PIPELINE" ]]; then
            kill -TERM "$PIPELINE" 2>/dev/null || true
            systemctl --user stop "lattica-v2-$PIPELINE-*.service" 2>/dev/null || true
        fi
        stop_provers
    fi
    if [[ -n "$WATCH" ]]; then
        wait "$WATCH" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
watch_gpu &
WATCH=$!

export LATTICA_PROFILE=1 LATTICA_CACHE_PREPROCESSING=1 LATTICA_V2_GPU_HASH=1
export LATTICA_V2_GPU_DEVICE="${LATTICA_V2_GPU_DEVICE:-0}"
export LATTICA_V2_GPU_MONITOR_PID="$WATCH" LATTICA_V2_GPU_MONITOR_FAILURE="$FAIL"
bash "$ROOT/scripts/block-v2-two-level.sh" --resume-registered "$DIR" "$PROFILE" &
PIPELINE=$!
wait "$PIPELINE"
PIPELINE=''
touch "$DONE"
wait "$WATCH"
WATCH=''
[[ ! -e "$FAIL" && $(wc -l < "$VRAM") -gt 1 ]]
[[ "$(sha256sum "$BIN")" == "$BIN_SHA" && "$(sha256sum "$AUDIT")" == "$AUDIT_SHA" ]]
echo 'bounded_gpu_recursive_trial=PASS'
