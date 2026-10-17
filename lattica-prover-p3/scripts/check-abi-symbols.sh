#!/usr/bin/env bash
# ABI gate: the DEFAULT staticlib exposes EXACTLY the current `lattica_*` node-seam externs and
# ZERO recursion symbols — turning "recursion is feature-gated out of production" into checkable evidence.
# The recursion module (src/recursion) is behind `--features recursion`; a default build must not include it.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "building the default-feature staticlib (no --features)…"
cargo build --locked --release --lib >/dev/null 2>&1
LIB="${CARGO_TARGET_DIR:-target}/release/liblattica_prover_p3.a"
[ -n "$LIB" ] && [ -f "$LIB" ] || { echo "FAIL: staticlib not found under target/release/"; exit 1; }

# The current development node seam. Any add/remove is a deliberate wire change — update this list in the SAME commit.
EXPECTED="$(cat <<'EOF'
lattica_batch_prove
lattica_batch_verify
lattica_htlc_batch_prove
lattica_htlc_batch_verify
lattica_htlc_prove
lattica_htlc_prove_demo
lattica_htlc_verify
lattica_joinsplit_tree_prove
lattica_joinsplit_tree_verify
lattica_joinsplit_prove
lattica_joinsplit_prove_demo
lattica_joinsplit_verify
EOF
)"
EXPECTED="$(echo "$EXPECTED" | sort -u)"

# The #[no_mangle] extern "C" entries appear verbatim (unmangled); the crate's own mangled symbols are
# Rust-mangled names do not match the anchored unmangled-symbol pattern below.
# Check ALL unmangled lattica_* exports; a new prefix must not evade the gate.
GOT="$(nm -j -g --defined-only "$LIB" 2>/dev/null | grep -E '^lattica_[a-zA-Z0-9_]+$' | sort -u)"

if [ "$GOT" != "$EXPECTED" ]; then
  echo "FAIL: lattica_* extern set drifted from the current node seam:"
  diff <(echo "$EXPECTED") <(echo "$GOT") || true
  exit 1
fi
echo "OK: exactly $(echo "$GOT" | grep -c .) lattica_* externs (the current development node seam)."

# The research tree-aggregation extern `lattica_tree_root` (W7 C-ABI) is feature-gated (`tree`) OUT of the
# default build. It lives in a DISTINCT namespace (`lattica_tree*`) the frozen-seam grep above ignores, so
# assert its absence explicitly — a future accidental un-gating must fail here, not slip through.
TREE_EXT="$(nm -g --defined-only "$LIB" 2>/dev/null | grep -cE 'lattica_tree[a-z_]*' || true)"
if [ "${TREE_EXT:-0}" -ne 0 ]; then
  echo "FAIL: $TREE_EXT lattica_tree* research externs in the DEFAULT staticlib (must be behind --features tree):"
  nm -g --defined-only "$LIB" 2>/dev/null | grep -E 'lattica_tree' | head
  exit 1
fi
echo "OK: zero lattica_tree* research externs in the default staticlib (feature-gated; enable with --features tree)."

# ZERO recursion symbols (the module is feature-gated out of the default build). Rust mangling embeds the
# module path, so gated-out recursion code contributes no `..recursion..`/`..monolith..` symbols.
REC="$(nm "$LIB" 2>/dev/null | grep -icE '[0-9a-z_]recursion|[0-9]monolith|_aggregat' || true)"
if [ "${REC:-0}" -ne 0 ]; then
  echo "FAIL: $REC recursion-related symbols in the DEFAULT staticlib (recursion must be feature-gated out):"
  nm "$LIB" 2>/dev/null | grep -iE 'recursion|monolith|aggregat' | head
  exit 1
fi
echo "OK: zero recursion symbols in the default staticlib (feature-gated out; enable with --features recursion)."

V2="$(nm "$LIB" 2>/dev/null | grep -ic 'block_v2' || true)"
if [ "${V2:-0}" -ne 0 ]; then
  echo "FAIL: $V2 candidate block-v2 symbols in DEFAULT staticlib."
  exit 1
fi
echo "OK: zero candidate block-v2 symbols in default staticlib."

# ZERO deep-tree research symbols (tip5/lookup/wrap/tree — the W3–W7 wrap research, all feature-gated out of
# the default build). Crate-ANCHORED (`lattica_prover_p3<len><module>`) so a dependency's own `lookup`/`tree`
# symbol (hashbrown, p3, …) can't false-positive — only THIS crate's gated-out modules are checked. The v0/
# legacy mangling embeds the crate name then the length-prefixed module, so a gated-out module emits none.
RES="$(nm "$LIB" 2>/dev/null | grep -icE 'lattica_prover_p3[0-9]+(tip5|lookup|wrap|tree)' || true)"
if [ "${RES:-0}" -ne 0 ]; then
  echo "FAIL: $RES deep-tree research symbols in the DEFAULT staticlib (wrap/tree/lookup/tip5 must be feature-gated out):"
  nm "$LIB" 2>/dev/null | grep -iE 'lattica_prover_p3[0-9]+(tip5|lookup|wrap|tree)' | head
  exit 1
fi
echo "OK: zero deep-tree research symbols in the default staticlib (feature-gated out; enable with --features tree,lookup,tip5)."
