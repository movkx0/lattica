#!/usr/bin/env python3
"""Package the pinned Apple repetition recipe and public proof fixture."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
COMMIT = "094cade18a59d38d7d65bd805511a7809b348a9e"
FIXTURE_NAMES = ["height", "key.1", "key.2", "key.3", *[f"wallet.{i}" for i in range(8)]]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def resolve_revision(revision):
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
        cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected an exact Git commit")
    return commit


def revision_memory_policy(commit):
    path = 'lattica-prover-p3/src/bin/apple_benchmark_memory.json'
    present = subprocess.check_output(['git', 'ls-tree', '--name-only', commit, '--', path],
                                     cwd=ROOT, text=True).strip()
    if not present:
        # The original 094cade workers enforce this compiled legacy limit.
        return {'schema': 'lattica-apple-benchmark-memory-v1',
                'worker_rss_limit_bytes': 44 << 30, 'aggregate_rss_limit_bytes': None}
    policy = json.loads(subprocess.check_output(['git', 'show', f'{commit}:{path}'], cwd=ROOT, text=True))
    if policy.get('schema') != 'lattica-apple-benchmark-memory-v1':
        raise ValueError('invalid pinned Apple memory policy')
    for name in ('worker_rss_limit_bytes', 'aggregate_rss_limit_bytes'):
        value = policy[name]
        if value is not None and (type(value) is not int or not 0 < value < 1 << 64):
            raise ValueError('invalid pinned Apple RSS limit')
    return policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new package directory; archive written alongside")
    parser.add_argument("--revision", default=COMMIT,
                        help="Git revision to freeze; use HEAD for current committed optimizations")
    args = parser.parse_args()
    out = args.out.resolve()
    archive_path = out.with_name(out.name + ".tar.gz")
    if out.exists() or archive_path.exists():
        parser.error("package directory and archive must both be new")
    commit = resolve_revision(args.revision)
    rss_policy = revision_memory_policy(commit)
    reference_path = ROOT / "docs/evidence/block-v2-gpu-default-ram-bench-2026-10-02.json"
    reference = json.loads(reference_path.read_text())["benchmark_plan"]
    for name in FIXTURE_NAMES:
        path = args.fixture / name
        if path.is_symlink() or not path.is_file() or digest(path) != reference["source_artifacts"][name]["sha256"]:
            parser.error("public fixture pin mismatch: " + name)
    out.mkdir(parents=True)
    (out / "fixture").mkdir()
    for name in FIXTURE_NAMES:
        shutil.copy2(args.fixture / name, out / "fixture" / name)
    (out / "overlays").mkdir()
    (out / "overlays/apple_benchmark_memory.json").write_text(json.dumps(rss_policy, indent=2) + "\n")
    shutil.copy2(SCRIPTS / "bench-apple-metal.py", out / "overlays/bench-apple-metal.py")
    shutil.copy2(SCRIPTS / "run-apple-benchmark-package.py", out / "run-apple-benchmark-package.py")
    shutil.copy2(SCRIPTS / "apple-benchmark-package-README.txt", out / "README.txt")
    if commit != COMMIT:
        instructions = (out / "README.txt").read_text().replace(COMMIT, commit)
        instructions = instructions.replace("revision 094cade", "revision " + commit[:7])
        instructions = instructions.replace("fetch origin codex/mac-metal", "fetch origin main")
        rss = rss_policy['worker_rss_limit_bytes']
        label = "observed without a fixed cap" if rss is None else f"sampled {rss / (1 << 30):g} GiB limit"
        instructions = instructions.replace("Worker RSS: sampled 44 GiB\nlimit.", f"Worker RSS: {label}.")
        (out / "README.txt").write_text(instructions)
    fixture_reference = {"schema": "lattica-public-fixture-reference-v1",
        "purpose": "Pin one public proving workload for development measurements on Apple Silicon.",
        "source": {"path": str(reference_path.relative_to(ROOT)), "sha256": digest(reference_path)},
        "benchmark_plan": {"config": {"external": reference["config"]["external"]},
                           "source_artifacts": {name: reference["source_artifacts"][name] for name in FIXTURE_NAMES}}}
    (out / "fixture-reference.json").write_text(json.dumps(fixture_reference, indent=2) + "\n")
    spec = importlib.util.spec_from_file_location("package_runner", SCRIPTS / "run-apple-benchmark-package.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    manifest = {"schema": "lattica-apple-benchmark-package-v1", "source_commit": commit,
        "source_revision_requested": args.revision,
        "rust_toolchain": "1.96.0", "python_minimum": "3.11", "platform": "Darwin arm64",
        "overlays": ["overlays/bench-apple-metal.py"], "fixture_files": FIXTURE_NAMES,
        "rss_policy_overlay": "overlays/apple_benchmark_memory.json",
        "schedule_at_18_threads": runner.schedule(18),
        "memory_policy": {"minimum_unified_bytes": 64 << 30, "mapped_scratch_bytes": 34 << 30,
                          "managed_metal_bytes": 8 << 30, "sampled_worker_rss_bytes": rss_policy['worker_rss_limit_bytes'],
                          "aggregate_rss_limit_bytes": rss_policy['aggregate_rss_limit_bytes'],
                          "stage_timeout_seconds": 7200, "swap": "observed, not prohibited"},
        "scope": "Selected committed proof sources plus hashed controller and revision-matched RSS policy overlays for three fresh repetitions. All compilation and hardware qualification precede timing. CPU audits follow each root.",
        "production_ready": False,
        "payload_sha256": {str(p.relative_to(out)): digest(p) for p in sorted(out.rglob("*")) if p.is_file()}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    runner.verify_package(out)
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(out, arcname=out.name)
    print(json.dumps({"archive": str(archive_path), "archive_sha256": digest(archive_path),
                      "manifest_sha256": digest(out / "manifest.json"),
                      "bytes": archive_path.stat().st_size, "source_commit": commit}, indent=2))


if __name__ == "__main__":
    main()
