#!/usr/bin/env python3
"""Install the pinned CUDA development components locally; never modify drivers."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

BASE = "https://developer.download.nvidia.com/compute/cuda/redist/"
COMPONENTS = {
    "cuda_nvcc": ("12.9.86", "7a1a5b652e5ef85c82b721d10672fc9a2dbaab44e9bd3c65a69517bf53998c35"),
    "cuda_nvrtc": ("12.9.86", "82913658363892dbc0f2638b070476234476e06e084fed60db861cb7e161a6af"),
    "cuda_cudart": ("12.9.79", "1f6ad42d4f530b24bfa35894ccf6b7209d2354f59101fd62ec4a6192a184ce99"),
    "cuda_cccl": ("12.9.27", "8b1a5095669e94f2f9afd7715533314d418179e9452be61e2fde4c82a3e542aa"),
    "cuda_sanitizer_api": ("12.9.79", "e23aad21132ff58b92a22aad372a7048793400b79c625665d325d4ecec6979bf"),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    prefix = args.prefix.resolve()
    prefix.mkdir(parents=True, exist_ok=True)
    downloads = prefix / "downloads"
    downloads.mkdir(exist_ok=True)
    records = []
    for name, (version, expected) in COMPONENTS.items():
        filename = f"{name}-linux-x86_64-{version}-archive.tar.xz"
        url = BASE + f"{name}/linux-x86_64/{filename}"
        archive = downloads / filename
        if not archive.exists() or digest(archive) != expected:
            partial = archive.with_suffix(archive.suffix + ".partial")
            print("DOWNLOAD", name, version, flush=True)
            with urllib.request.urlopen(url, timeout=60) as source, partial.open("wb") as target:
                shutil.copyfileobj(source, target)
            if digest(partial) != expected:
                raise RuntimeError("NVIDIA archive checksum mismatch: " + name)
            partial.replace(archive)
        with tempfile.TemporaryDirectory(prefix="extract-", dir=prefix) as temporary:
            extracted = Path(temporary)
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
            roots = list(extracted.iterdir())
            if len(roots) != 1 or not roots[0].is_dir():
                raise RuntimeError("Unexpected NVIDIA archive layout")
            for entry in roots[0].iterdir():
                if entry.is_dir():
                    shutil.copytree(entry, prefix / entry.name, dirs_exist_ok=True, symlinks=True)
                else:
                    notices = prefix / "component-notices" / name
                    notices.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(entry, notices / entry.name, follow_symlinks=False)
        records.append({"component": name, "version": version, "url": url, "sha256": expected})
        print("INSTALLED", name, version, flush=True)
    (prefix / "lattica-toolchain.json").write_text(json.dumps({
        "toolkit_release": "12.9.1", "platform": "linux-x86_64",
        "source_manifest": BASE + "redistrib_12.9.1.json", "components": records,
    }, indent=2) + "\n")
    print("Toolchain:", prefix, flush=True)


if __name__ == "__main__":
    main()
