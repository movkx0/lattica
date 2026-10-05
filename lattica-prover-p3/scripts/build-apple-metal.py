#!/usr/bin/env python3
"""Build isolated CPU audit/proving tools and the opt-in Metal worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("requires Apple Silicon macOS")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", type=Path, default=ROOT / "target")
    args = parser.parse_args()
    target_root = args.target_root.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "RUSTFLAGS": "-C target-cpu=native"}
    metadata = {"rustc": subprocess.check_output(["rustc", "-vV"], text=True),
                "cargo": subprocess.check_output(["cargo", "-V"], text=True),
                "rustflags": env["RUSTFLAGS"], "builds": [], "binaries": {}}
    sources = [ROOT/"Cargo.toml", ROOT/"Cargo.lock", ROOT/"build.rs", *sorted((ROOT/"src").rglob("*"))]
    sources = [p for p in sources if p.is_file() and p.name != ".DS_Store"]
    source_hashes = lambda: {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    metadata["source_hashes"] = source_hashes()
    metadata["git_commit"] = subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    for kind, features, target, binaries in [
        ("cpu", "block-v2-wide-lanes,stream", target_root/"cpu",
         ["block-v2-grouped-probe", "block-v2-grouped-artifact-audit", "block-v2-grouped-publics"]),
        ("metal", "block-v2-wide-lanes,stream,gpu-metal", target_root, ["block-v2-metal-grouped-probe"]),
    ]:
        command = ["cargo", "build", "--offline", "--locked", "--release", "--no-default-features", "--features", features]
        for binary in binaries:
            command += ["--bin", binary]
        subprocess.run(command, env={**env,"CARGO_TARGET_DIR":str(target)}, cwd=ROOT, check=True)
        metadata["builds"].append({"kind":kind,"command":command,"target":str(target)})
        for name in binaries:
            path=target/"release"/name
            metadata["binaries"][name]={"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    if source_hashes() != metadata["source_hashes"]:
        raise RuntimeError("proof sources changed during compilation")
    metadata["cargo_lock_sha256"] = hashlib.sha256((ROOT/"Cargo.lock").read_bytes()).hexdigest()
    (target_root/"metal-build-metadata.json").write_text(json.dumps(metadata,indent=2)+"\n")

if __name__ == "__main__":
    main()
