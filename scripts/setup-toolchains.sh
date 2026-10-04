#!/usr/bin/env bash
# Install the documented versions locally, without changing shell profiles or system tools.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/.tools"
ZIG_VERSION=0.16.0
RUST_VERSION=1.96.0

case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)
        ZIG_TARGET=aarch64-macos; RUST_TARGET=aarch64-apple-darwin
        ZIG_SHA=b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489 ;;
    Darwin/x86_64)
        ZIG_TARGET=x86_64-macos; RUST_TARGET=x86_64-apple-darwin
        ZIG_SHA=0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7 ;;
    Linux/aarch64|Linux/arm64)
        ZIG_TARGET=aarch64-linux; RUST_TARGET=aarch64-unknown-linux-gnu
        ZIG_SHA=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17 ;;
    Linux/x86_64)
        ZIG_TARGET=x86_64-linux; RUST_TARGET=x86_64-unknown-linux-gnu
        ZIG_SHA=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 ;;
    *) echo "Unsupported host: $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

for tool in curl tar shasum cc; do
    command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done
mkdir -p "$TOOLS/downloads"

download() {
    curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 \
        "$1" -o "$2.part"
    mv "$2.part" "$2"
}

ZIG_DIR="zig-$ZIG_TARGET-$ZIG_VERSION"
if [[ ! -x "$TOOLS/$ZIG_DIR/zig" ]]; then
    ARCHIVE="$TOOLS/downloads/$ZIG_DIR.tar.xz"
    [[ -f "$ARCHIVE" ]] || download "https://ziglang.org/download/$ZIG_VERSION/$ZIG_DIR.tar.xz" "$ARCHIVE"
    printf '%s  %s\n' "$ZIG_SHA" "$ARCHIVE" | shasum -a 256 -c -
    tar -xJf "$ARCHIVE" -C "$TOOLS"
fi
ln -sfn "$ZIG_DIR" "$TOOLS/zig"

export CARGO_HOME="$TOOLS/cargo"
export RUSTUP_HOME="$TOOLS/rustup"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
    INSTALLER="$TOOLS/downloads/rustup-init"
    BASE="https://static.rust-lang.org/rustup/dist/$RUST_TARGET"
    download "$BASE/rustup-init" "$INSTALLER"
    download "$BASE/rustup-init.sha256" "$INSTALLER.sha256"
    (cd "$TOOLS/downloads" && shasum -a 256 -c rustup-init.sha256)
    chmod +x "$INSTALLER"
    "$INSTALLER" -y --no-modify-path --profile minimal \
        --default-host "$RUST_TARGET" --default-toolchain "$RUST_VERSION"
else
    if ! "$CARGO_HOME/bin/rustup" run "$RUST_VERSION" rustc --version >/dev/null 2>&1; then
        "$CARGO_HOME/bin/rustup" toolchain install "$RUST_VERSION" --profile minimal
    fi
    "$CARGO_HOME/bin/rustup" default "$RUST_VERSION"
fi

"$ROOT/scripts/with-toolchain.sh" rustc --version
"$ROOT/scripts/with-toolchain.sh" zig version
echo "Ready: scripts/run-benchmarks.sh"
