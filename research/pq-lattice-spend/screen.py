#!/usr/bin/env python3
"""Bounded, fail-closed parameter screening. This never generates a proof."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
PROFILES = {
    "latest": ("UPSTREAM.json", "labrador"),
    "toolkit": ("UPSTREAM-toolkit.json", "labrador-toolkit"),
}
CASES = (104, 404, 512, 1024)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources(profile):
    manifest, directory = PROFILES[profile]
    record = json.loads((ROOT / manifest).read_text())
    vendor = ROOT / "vendor" / directory
    actual = {str(p.relative_to(vendor)): sha256(p)
              for p in vendor.rglob("*") if p.is_file()}
    if actual != record["source_files"]:
        raise ValueError("upstream source census or hash mismatch")
    return record["revision"]


def validate_case(record, count, revision):
    required = {
        "schema": "lattice-parameter-screen-v2",
        "backend_revision": revision,
        "binary_polynomials": count,
        "degree": 256,
        "modulus": 274877906837,
        "backend_status": 0,
        "zero_knowledge_requested": True,
        "zero_knowledge_stage_selected": True,
        "proof_generated": False,
        "serialized_bytes_measured": False,
        "full_ringct_relation": False,
        "security_equivalence_established": False,
    }
    for key, expected in required.items():
        if type(record.get(key)) is not type(expected) or record[key] != expected:
            raise ValueError(f"invalid screening field: {key}")
    for key in ("estimated_proof_bits", "estimated_proof_bytes_ceil", "reduction_rounds"):
        if type(record.get(key)) is not int or not 0 < record[key] < 2**40:
            raise ValueError(f"invalid positive count: {key}")
    if record["estimated_proof_bytes_ceil"] != (record["estimated_proof_bits"] + 7) // 8:
        raise ValueError("inconsistent estimated byte count")


def run(profile, binary, destination):
    revision = verify_sources(profile)
    binary = binary.resolve(strict=True)
    binary_hash = sha256(binary)
    destination.mkdir(parents=True, exist_ok=False)
    cases = []
    for count in CASES:
        log = destination / f"case-{count}.log"
        # Logs stream to disk: unexpected backend output cannot grow host buffers.
        with log.open("xb") as output:
            result = subprocess.run([str(binary), str(count)], stdout=output,
                                    stderr=subprocess.STDOUT, timeout=60)
        if result.returncode:
            raise RuntimeError(f"backend failed ({result.returncode}); retained {log}")
        if log.stat().st_size > 1024 * 1024:
            raise ValueError("screen output exceeds 1 MiB")
        records = [json.loads(line) for line in log.read_text().splitlines()
                   if line.startswith("{")]
        if len(records) != 1:
            raise ValueError("unexpected result census")
        validate_case(records[0], count, revision)
        cases.append(records[0])
        print(json.dumps(records[0]), flush=True)
    if sha256(binary) != binary_hash or verify_sources(profile) != revision:
        raise ValueError("screen inputs changed during execution")
    report = {
        "schema": "lattice-parameter-screen-batch-v2",
        "profile": profile, "revision": revision,
        "binary_sha256": binary_hash, "cases": cases,
        "logs": {p.name: sha256(p) for p in sorted(destination.glob("*.log"))},
        "scope": "Public parameter estimates only; no full relation, witness, proof or wire artifact.",
        "screening_target_bytes": 24000,
        "size_screen_passed": all(c["estimated_proof_bytes_ceil"] <= 24000 for c in cases),
        "replacement_qualified": False,
    }
    with (destination / "report.json").open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.profile, args.binary, args.output)
