#!/usr/bin/env python3
"""Replay bounded public-registration observations without admitting a cache.

Usage: registration_replay.py RESULT.json [--output ASSESSMENT.json]
Legacy reports establish setup's total-time ceiling, but aggregate hit counts
cannot recover access order. Current telemetry cannot establish the complete
prepared footprint or phase temporary bounds, so it never authorizes retention.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import OrderedDict
from pathlib import Path

PUBLIC_LIMIT = 64 << 20
RECEIPT_LIMIT = 1 << 20
FULL_SCOPE = "single_serial_context_fresh_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io_shutdown"
FIELDS = [
    "registration", "manifest", "host_allowance_bytes", "setup_seconds", "outcome",
    "reuse_distance", "released_after", "public_host_bytes", "managed_device_live_bytes",
    "metadata_payload_bytes", "metadata_hit", "receipt_hit", "callback_ok", "active_rows", "padded_rows",
]


def natural(value, label, maximum=None):
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"invalid {label}")
    return value


def seconds(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"invalid {label}")
    return value


def parse_trace(trace):
    if trace.get("schema") != "pq-registration-access-trace-v1" or trace.get("fields") != FIELDS:
        raise ValueError("unsupported registration trace encoding")
    if trace.get("enabled") is not True or trace.get("complete") is not True:
        raise ValueError("registration sequence disabled, truncated or unfinished")
    limit = natural(trace.get("maximum_accesses"), "maximum accesses", 4096)
    rows = trace.get("rows")
    if not isinstance(rows, list) or len(rows) > limit:
        raise ValueError("invalid bounded trace rows")
    for key in ("attempted_accesses", "recorded_accesses"):
        if natural(trace.get(key), key, 4096) != len(rows):
            raise ValueError("trace count mismatch")
    if natural(trace.get("dropped_accesses"), "dropped accesses") != 0:
        raise ValueError("registration sequence was truncated")
    previous = {}
    payloads = {}
    events = []
    for index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != len(FIELDS):
            raise ValueError("malformed registration row")
        event = dict(zip(FIELDS, row))
        for key in ("registration", "manifest"):
            value = event[key]
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("invalid exact program identity")
        natural(event["host_allowance_bytes"], "host allowance", 32 << 30)
        if not event["host_allowance_bytes"]:
            raise ValueError("zero host allowance")
        seconds(event["setup_seconds"], "setup duration")
        if event["outcome"] not in (1, 2) or type(event["outcome"]) is not int or event["callback_ok"] is not True:
            raise ValueError("failed or unfinished registration/callback cannot qualify a replay")
        if event["released_after"] is not None:
            natural(event["released_after"], "release reason", 5)
        if event["reuse_distance"] is not None:
            natural(event["reuse_distance"], "reuse distance")
        for key in ("metadata_hit", "receipt_hit"):
            if type(event[key]) is not bool:
                raise ValueError(f"invalid {key}")
        natural(event["public_host_bytes"], "public bytes", PUBLIC_LIMIT)
        if event["managed_device_live_bytes"] is not None:
            natural(event["managed_device_live_bytes"], "managed device observation")
        natural(event["metadata_payload_bytes"], "metadata payload")
        active = natural(event["active_rows"], "active rows")
        padded = natural(event["padded_rows"], "padded rows")
        if not padded or active > padded or padded & (padded - 1):
            raise ValueError("invalid registered row geometry")
        identity = (event["registration"], event["manifest"])
        prepared_identity = (*identity, event["host_allowance_bytes"])
        distance = index - previous[prepared_identity] - 1 if prepared_identity in previous else None
        if event["reuse_distance"] != distance:
            raise ValueError("reuse distance does not match the ordered exact identity trace")
        previous[prepared_identity] = index
        if identity in payloads and payloads[identity] != event["metadata_payload_bytes"]:
            raise ValueError("immutable metadata footprint changed for one exact identity")
        payloads[identity] = event["metadata_payload_bytes"]
        events.append(event)
    return events


def metadata_replay(events, capacity, receipt_bytes, entry_bytes, observation_bytes):
    fixed = receipt_bytes + capacity * entry_bytes + observation_bytes
    if fixed > PUBLIC_LIMIT:
        raise ValueError("fixed public storage exceeds shared allowance")
    cache = OrderedDict()
    payload_bytes = hits = capacity_evictions = byte_evictions = oversized = 0
    peak = fixed
    for event in events:
        if event["outcome"] == 2:  # Prepared hits perform no metadata lookup.
            continue
        identity = (event["registration"], event["manifest"])
        payload = event["metadata_payload_bytes"]
        if identity in cache:
            cache.move_to_end(identity)
            hits += 1
            continue
        if payload > PUBLIC_LIMIT - fixed:
            oversized += 1
            continue
        while len(cache) == capacity or fixed + payload_bytes + payload > PUBLIC_LIMIT:
            if len(cache) == capacity:
                capacity_evictions += 1
            else:
                byte_evictions += 1
            _, removed = cache.popitem(last=False)
            payload_bytes -= removed
        cache[identity] = payload
        payload_bytes += payload
        peak = max(peak, fixed + payload_bytes)
    return {"entries": capacity, "hits": hits, "capacity_evictions": capacity_evictions,
            "byte_evictions": byte_evictions, "oversized_rejections": oversized,
            "peak_accounted_public_bytes": peak, "remaining_entries": len(cache),
            "projected_time_saving_seconds": None}


def assess(document):
    context = document.get("context", document)
    if not isinstance(context, dict):
        raise ValueError("missing context object")
    measurement = document.get("measurement", {})
    wall = measurement.get("run_wall_seconds") if measurement.get("schema") == "pq-opencl-fresh-workflow-timing-v2" and measurement.get("scope") == FULL_SCOPE else None
    if wall is not None:
        seconds(wall, "complete workflow duration")
        if not wall:
            raise ValueError("zero complete workflow duration")
    setup = context.get("registration_setup_seconds", context.get("registration_seconds"))
    if setup is not None:
        seconds(setup, "registration setup total")
    result = {
        "schema": "pq-registration-replay-assessment-v1",
        "prepared_reuse_enabled": False,
        "prepared_reuse_gate": "inconclusive",
        "complete_workflow_seconds": wall,
        "observed_registration_seconds": setup,
        "all_setup_fraction_upper_bound": setup / wall if setup is not None and wall else None,
        "observed": {key: context.get(key) for key in (
            "registrations", "prepared_cache_hits", "metadata_cache_hits", "metadata_evictions",
            "identity_hint_hits", "identity_receipt_entries")},
        "limitations": [
            "No complete per-identity immutable prepared host/device footprint is available.",
            "No planner-issued active and temporary phase memory bounds are available.",
            "Aggregate setup or hypothetical hit counts do not establish a measured 5% workflow improvement.",
        ],
    }
    trace = context.get("registration_telemetry")
    if trace is None:
        result["sequence_status"] = "not_observed"
        result["limitations"].insert(0, "Legacy aggregate counters cannot recover an ordered exact-identity access sequence.")
        return result
    try:
        events = parse_trace(trace)
    except ValueError as exc:
        result["sequence_status"] = "unusable"
        result["limitations"].insert(0, str(exc))
        return result
    result["sequence_status"] = "complete"
    seen = set()
    ideal_seconds = 0.0
    ideal_hits = 0
    for event in events:
        key = (event["registration"], event["manifest"], event["host_allowance_bytes"])
        if key in seen and event["outcome"] == 1:
            ideal_hits += 1
            ideal_seconds += event["setup_seconds"]
        seen.add(key)
    result["unadmitted_prepared_upper_bound"] = {
        "additional_hits": ideal_hits, "observed_setup_seconds": ideal_seconds,
        "workflow_fraction": ideal_seconds / wall if wall else None,
        "ignores": "memory admission, phase clearing, eviction cost and retention effects",
        "eligible_for_promotion": False,
    }
    receipt = natural(context.get("identity_receipt_cache_bytes"), "receipt backing", RECEIPT_LIMIT)
    entry = natural(context.get("metadata_entry_size_bytes"), "metadata entry size")
    reserved = natural(context.get("registration_telemetry_reserved_bytes"), "observation reservation", PUBLIC_LIMIT)
    result["metadata_replay"] = [metadata_replay(events, capacity, receipt, entry, reserved) for capacity in (256, 512)]
    if wall and ideal_seconds / wall < 0.05:
        result["prepared_reuse_gate"] = "rejected_by_optimistic_time_ceiling"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.report.stat().st_size > 64 << 20:
        parser.error("report exceeds 64 MiB reader allowance")
    raw = args.report.read_bytes()
    result = assess(json.loads(raw))
    result["source"] = {"path": str(args.report.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}
    encoded = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
