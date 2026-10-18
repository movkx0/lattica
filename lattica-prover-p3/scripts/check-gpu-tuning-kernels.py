#!/usr/bin/env python3
"""Compile the actual OpenCL sources without requiring an OpenCL device.

This checks syntax only. Numerical correctness and performance require the
ignored Rust GPU tests and independently audited proof benchmarks.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def sources(crate):
    gpu = (crate / "src/gpu.rs").read_text().split("const KERNEL_SRC:", 1)[1]
    base = re.search(r'r#"(.*?)"#', gpu, re.S).group(1)
    cached = (crate / "src/gpu/ntt_cached.cl").read_text()
    engine = crate / "src/block_v2/gpu_hash/engine"
    tuned = ("\n#define LATTICA_TUNED_NTT 1\n"
             "#define ntt_tile_cached ntt_tile_cached_tuned\n" + cached +
             "\n#undef ntt_tile_cached\n#undef LATTICA_TUNED_NTT\n")
    portable = base + cached + (engine / "scale_shared.cl").read_text() + tuned
    return {
        "baseline": base + cached,
        "portable-tuning": portable,
        "nvidia-tuning": portable + (engine / "commitment_shuffle.cl").read_text(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()
    crate = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="lattica-opencl-check-") as directory:
        for name, source in sources(crate).items():
            path = Path(directory) / (name + ".cl")
            path.write_text(source)
            # NVIDIA's OpenCL compiler accepts `asm`; Clang spells the same
            # extension `__asm__`. Syntax checking does not assemble the PTX.
            subprocess.run([args.clang, "-x", "cl", "-cl-std=CL1.2", "-Dasm=__asm__",
                            "-Werror", "-fsyntax-only", str(path)], check=True)
            print(name + ": OpenCL syntax PASS", flush=True)


if __name__ == "__main__":
    main()
