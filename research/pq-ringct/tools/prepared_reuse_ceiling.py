#!/usr/bin/env python3
"""Audit a necessary idle-device condition for the accepted wide RingCT path.

This is a lower bound on two retained preprocessing allocations, not a full
footprint or peak. Small states remain unadmitted. Legacy receipts bound core
setup only; they do not time subsequent verifier-metadata construction.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

IDLE_LIMIT = 512 << 20
REPORT_LIMIT = 64 << 20
OBSERVED_HEIGHTS = frozenset((4096, 65536, 131072, 262144))
FULL_SCOPE = "single_serial_context_fresh_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io_shutdown"
SOURCE = {
    "preprocessing_width": "machine/program.rs LANES=23, EXT_LANES=7; machine/air.rs PREPROCESSED_WIDTH=8*LANES+2*EXT_LANES+2=200",
    "doubled_degree": "src/gpu_hiding.rs TraceCommitShape::preprocessing/plan doubles trace rows with unchanged preprocessing width",
    "retained_prefix": "gpu_hash/engine/lde_execute.rs captures device_capture_shapes(...,0); engine/device/storage.rs capture_specs retains the full degree-sized matrix",
    "retained_tree": "gpu_hash/engine.rs retained_layout stores (2*LDE_height-1) nodes of four 8-byte fields",
    "coownership": "gpu_hash/salt_data.rs finish_salted_commit stores owned prefixes and tree together in ProverData::DeviceOnly",
    "profile": "block_v2/profile.rs LOG_BLOWUP=4; LDE_height=2*trace_rows*16",
}


def device_lower_bound(rows):
    if type(rows) is not int or rows < 8 or rows & (rows - 1):
        raise ValueError("invalid trace rows")
    prefix = 2 * rows * 200 * 8
    tree = (2 * (2 * rows * 16) - 1) * 4 * 8
    return prefix, tree


def receipts(lines):
    counts, times = Counter(), Counter()
    pending = None
    for line in lines:
        if line.startswith("proving_stage_report "):
            receipt = json.loads(line.split(" ", 1)[1])
            if receipt.get("entry_point") == "block_v2_preprocessing":
                if pending is not None or receipt.get("succeeded") is not True:
                    raise ValueError("unpaired or failed preprocessing receipt")
                pending = receipt.get("elapsed_ns")
                if type(pending) is not int or pending < 0:
                    raise ValueError("invalid preprocessing duration")
        elif line.startswith("bounded_cached_prover_metadata "):
            match = re.search(r"\brows=(\d+) device_salts=true\b", line)
            if pending is None or match is None:
                raise ValueError("cached metadata lacks its successful device-salt preprocessing receipt")
            rows = int(match[1])
            device_lower_bound(rows)
            counts[rows] += 1
            times[rows] += pending
            pending = None
    if pending is not None:
        raise ValueError("unfinished preprocessing receipt")
    return counts, times


def assess(document, counts, times):
    context = document["context"]
    measurement = document["measurement"]
    if document.get("passed") is not True or context.get("session_closed") is not True:
        raise ValueError("requires accepted terminal evidence")
    if (document.get("blowup") != 16 or document.get("num_queries") != 128
            or document.get("hiding") is not True or document.get("original_profile") is not True
            or context.get("policy") != "gpu_required" or context.get("busy") is not False
            or context.get("prepared_entries") != 0):
        raise ValueError("requires closed original GPU-required profile")
    if measurement.get("schema") != "pq-opencl-fresh-workflow-timing-v2" or measurement.get("scope") != FULL_SCOPE:
        raise ValueError("requires complete-workflow timing scope")
    if (not counts or not counts.keys() <= OBSERVED_HEIGHTS
            or type(context["registrations"]) is not int
            or any(type(n) is not int or n <= 0 for n in counts.values())
            or any(type(ns) is not int or ns < 0 for ns in times.values())
            or sum(counts.values()) != context["registrations"] or counts.keys() != times.keys()):
        raise ValueError("registration/receipt count mismatch")
    core = context["registration_seconds"]
    wall = measurement["run_wall_seconds"]
    measured = sum(times.values()) / 1e9
    if (type(core) not in (int, float) or type(wall) not in (int, float)
            or not math.isfinite(core) or not math.isfinite(wall)
            or core < measured or not 0 < wall or core > wall):
        raise ValueError("inconsistent setup/workflow timing")
    shapes = []
    small_seconds = 0.0
    small_count = 0
    for rows in sorted(counts):
        prefix, tree = device_lower_bound(rows)
        ruled_out = prefix + tree > IDLE_LIMIT
        shapes.append({"rows": rows, "observed_registrations": counts[rows],
                       "core_preprocessing_seconds": times[rows] / 1e9,
                       "retained_preprocessing_prefix_bytes": prefix,
                       "retained_preprocessing_tree_bytes": tree,
                       "retained_device_lower_bound_bytes": prefix + tree,
                       "exceeds_idle_device_cap": ruled_out})
        if not ruled_out:
            small_count += counts[rows]
            small_seconds += times[rows] / 1e9
    # Context core-registration time encloses each receipt. Allocate every bit
    # of aggregate outside-receipt core time to the small shapes, conservatively.
    small_core_ceiling = small_seconds + core - measured
    threshold = 0.05 * measurement["run_wall_seconds"]
    return {"schema": "pq-prepared-reuse-necessary-condition-v1",
            "scope": "accepted wide device-only preprocessing; two retained allocations only",
            "source_derivation": SOURCE, "idle_device_limit_bytes": IDLE_LIMIT,
            "profile_assumption": "wide machine lanes23/ext7 as in the accepted source/build; receipt rows alone do not authenticate this lane layout",
            "formula_bytes": "(2*rows*200*8) + ((2*(2*rows*16)-1)*4*8) = 5248*rows-32",
            "excludes": "public salts, prepared schedule/source, all host bytes, driver/context, and active/temporary proving storage",
            "shapes": shapes, "registrations_not_ruled_out": small_count,
            "small_core_setup_seconds_upper_bound": small_core_ceiling,
            "small_core_setup_workflow_fraction_upper_bound": small_core_ceiling / measurement["run_wall_seconds"],
            "five_percent_workflow_seconds": threshold,
            "additional_small_setup_seconds_needed_for_five_percent": max(0, threshold - small_core_ceiling),
            "whole_setup_timing_available": False, "prepared_reuse_enabled": False,
            "disposition": "inconclusive_for_small_shapes; large_shapes_exceed_idle_device_cap",
            "limitation": "Legacy timing excludes verifier metadata construction. This is neither a full prepared footprint nor a memory admission or measured workflow speedup."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("log", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with args.report.open("rb") as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    if len(raw) > REPORT_LIMIT:
        raise ValueError("report exceeds reader allowance")
    log_hash = hashlib.sha256()
    def lines():
        with args.log.open("rb") as stream:
            while line := stream.readline(8 << 20):
                if len(line) == 8 << 20 and not line.endswith(b"\n"):
                    raise ValueError("log line exceeds reader allowance")
                log_hash.update(line)
                yield line.decode("utf-8")
    counts, times = receipts(lines())
    result = assess(json.loads(raw), counts, times)
    result["evidence"] = {"report": str(args.report.resolve()), "report_sha256": hashlib.sha256(raw).hexdigest(),
                          "log": str(args.log.resolve()), "log_sha256": log_hash.hexdigest()}
    encoded = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
