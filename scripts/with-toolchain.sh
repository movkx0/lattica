#!/usr/bin/env bash
# Use checkout-local compilers when installed; otherwise use the caller's PATH.
# This file can also be sourced by the other Bash scripts.
set -euo pipefail
LATTICA_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$LATTICA_ROOT/.tools/cargo/bin/cargo" ]]; then
    export CARGO_HOME="$LATTICA_ROOT/.tools/cargo"
    export RUSTUP_HOME="$LATTICA_ROOT/.tools/rustup"
    export PATH="$CARGO_HOME/bin:$PATH"
fi
if [[ -x "$LATTICA_ROOT/.tools/zig/zig" ]]; then
    export PATH="$LATTICA_ROOT/.tools/zig:$PATH"
fi
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$LATTICA_ROOT/.tools/zig-cache}"

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ $# -eq 0 ]]; then
        echo "Usage: scripts/with-toolchain.sh COMMAND [ARG ...]" >&2
        exit 2
    fi
    exec "$@"
fi
