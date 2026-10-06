"""Lossless structured measurements, without importing wallet/proof contents."""
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import re

from .model import exact, reference, relative

FIELD = re.compile(r'([A-Za-z_][A-Za-z0-9_.-]*)=(?:"((?:\\.|[^"\\])*)"|([^\s]+))')
PREFIXES = ("performance_", "host_timeline_", "gpu_timeline_", "bounded_gpu_",
            "bounded_heap_", "bounded_coset_", "heap_lde_", "grouped_node_",
            "grouped_stage_", "node_complete", "stage_cgroup_", "cache_bench_",
            "proof_verified", "proof_start", "spill_", "metal_")
TIME_KEYS = {"start_ns", "end_ns", "utc_ns", "time_ns", "started_ns", "finished_ns"}


def scalar(value, key=""):
    if value == "true":
        return True
    if value == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return str(int(value)) if key in TIME_KEYS else exact(int(value))
    try:
        if re.fullmatch(r"-?\d+\.\d+(?:[eE][+-]?\d+)?", value):
            return float(value)
    except ValueError:
        pass
    return value


def fields(line):
    result = {}
    for m in FIELD.finditer(line):
        key, quoted, plain = m.groups()
        if quoted is not None:
            try:
                result[key] = json.loads('"' + quoted + '"')
            except json.JSONDecodeError:
                result[key] = quoted
        else:
            result[key] = scalar(plain, key)
    return result


class Table:
    def __init__(self, kind, source, clock):
        self.kind, self.source, self.clock = kind, source, clock
        self.columns, self.indices, self.rows = [], {}, []

    def add(self, data):
        for key in data:
            if key not in self.indices:
                self.indices[key] = len(self.columns)
                self.columns.append(key)
        row = [None] * len(self.columns)
        for key, value in data.items():
            row[self.indices[key]] = value
        self.rows.append(row)

    def finish(self):
        rows = [r + [None] * (len(self.columns) - len(r)) for r in self.rows]
        dictionaries = {}
        for i, name in enumerate(self.columns):
            values = [r[i] for r in rows if r[i] is not None]
            # Encode only homogeneous text. Keep numeric strings exact and avoid
            # interpreting an earlier numeric value as a dictionary index.
            if (values and all(isinstance(v, str) for v in values)
                    and not any(re.fullmatch(r"-?\d+(?:\.\d+)?", v) for v in values)):
                unique = list(dict.fromkeys(values))
                if len(unique) < len(values):
                    dictionaries[name] = unique
                    indices = {v: n for n, v in enumerate(unique)}
                    for row in rows:
                        if row[i] is not None:
                            row[i] = indices[row[i]]
        return {"kind": self.kind, "source": self.source, "clock": self.clock,
                "columns": self.columns, "dictionaries": dictionaries, "rows": rows}


def unpack(table):
    for row in table["rows"]:
        result = {}
        for i, name in enumerate(table["columns"]):
            value = row[i]
            if value is not None and name in table.get("dictionaries", {}):
                value = table["dictionaries"][name][value]
            result[name] = value
        yield result


def flatten(data, prefix="", result=None):
    result = {} if result is None else result
    for key, value in data.items():
        key = prefix + key
        if isinstance(value, dict):
            flatten(value, key + ".", result)
        else:
            if key == "gpu_processes" and isinstance(value, list):
                for process in value:
                    if isinstance(process, dict) and all(k in process for k in ("uuid", "pid", "bytes")):
                        result[f"gpu_processes.{process['uuid']}.{process['pid']}.bytes"] = exact(process["bytes"])
            if key.endswith(("cpu.stat", "memory.events", "memory.stat")) and isinstance(value, str):
                pairs = [line.split() for line in value.splitlines()]
                if all(len(p) == 2 and p[1].isdigit() for p in pairs):
                    for name, n in pairs:
                        result[key + "." + name] = int(n)
                    continue
            result[key] = str(value) if key in TIME_KEYS and value is not None else exact(value)
    return result


def collect(paths, root, typed_construction=None):
    tables, sources, warnings, proofs = [], [], [], []
    hashes = set()
    timeline_count = resource_count = 0
    for path in sorted(set(Path(p) for p in paths)):
        if not path.is_file():
            warnings.append("Missing measurement source: " + relative(path, root))
            continue
        ref = reference(path, root)
        sources.append(ref)
        if ref["sha256"] in hashes:
            continue
        hashes.add(ref["sha256"])
        source = ref["path"]
        if path.suffix in (".jsonl", ".csv"):
            table = Table("resource_samples", source, "utc_ns")
            with path.open(errors="replace", newline="") as stream:
                reader = csv.DictReader(stream) if path.suffix == ".csv" else stream
                for i, line in enumerate(reader, 1):
                    try:
                        data = line if isinstance(line, dict) else json.loads(line)
                        if not isinstance(data, dict):
                            raise ValueError("sample is not an object")
                        row = flatten(data)
                        row["_source_line"] = i + int(path.suffix == ".csv")
                        table.add(row)
                    except (ValueError, TypeError, json.JSONDecodeError) as error:
                        warnings.append(f"{source}:{i}: {error}")
            tables.append(table.finish())
            resource_count += len(table.rows)
            continue
        grouped = {}
        checkpoint = None
        with path.open(errors="replace") as stream:
            for line_no, line in enumerate(stream, 1):
                if line.startswith("{"):
                    # Typed workers emit public node timings as JSON. Import
                    # only these bounded fields, never arbitrary JSON payloads.
                    try:
                        event = json.loads(line)
                        if event.get("event") != "fresh_typed_node":
                            continue
                        key_count = {"reference": 5, "finalizer": 6, "paired": 12}.get(typed_construction, 6)
                        bounds = {"level": (0, 6), "index": (0, 63), "mode": (1, key_count),
                                  "count": (0, 64), "bytes": (1, 2 * 1024 * 1024)}
                        if any(type(event.get(key)) is not int or not low <= event[key] <= high
                               for key, (low, high) in bounds.items()):
                            raise ValueError("invalid typed node dimensions")
                        terminal = 12 if typed_construction == "paired" else 6
                        if event["mode"] == terminal and (event["level"] != 6 or event["index"] != 0 or event["count"] > 32):
                            raise ValueError("invalid terminal finalizer node")
                        if typed_construction == "paired" and event["mode"] not in (2, 3, 12):
                            if event["level"] != 1 or event["index"] >= 32 or event["count"] not in (1, 2):
                                raise ValueError("invalid paired wrapper node")
                        elapsed = event["seconds"]
                        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
                            raise ValueError("invalid typed node duration")
                        optional = {"cache_setups": "setups", "cache_hits": "cache_hits",
                                    "input_verification_ms": "input_verification_ms", "proving_ms": "proving_ms",
                                    "serialization_ms": "serialization_ms",
                                    "worker_pid": "worker_pid", "accepted_ms": "accepted_ms"}
                        extra = {}
                        for key, target in optional.items():
                            if key in event:
                                if type(event[key]) is not int or not 0 <= event[key] <= 2**63 - 1:
                                    raise ValueError(f"invalid typed node counter: {key}")
                                extra[target] = event[key]
                        if "gpu_uuid" in event:
                            if not isinstance(event["gpu_uuid"], str) or not re.fullmatch(
                                    r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", event["gpu_uuid"]):
                                raise ValueError("invalid typed node GPU identity")
                            extra["gpu_uuid"] = event["gpu_uuid"]
                        line = (f"node_complete artifact=node.{event['level']}.{event['index']} "
                                f"elapsed_ms={elapsed * 1000} mode={event['mode']} "
                                f"count={event['count']} bytes={event['bytes']} resumed=false")
                        line += "".join(f" {key}={value}" for key, value in extra.items())
                    except (ValueError, TypeError, KeyError, AttributeError) as error:
                        warnings.append(f"{source}:{line_no}: {error}")
                        continue
                prefix = line.split(" ", 1)[0].split("=", 1)[0].strip()
                if not prefix.startswith(PREFIXES):
                    continue
                data = fields(line)
                if not data:
                    continue
                if prefix == "performance_checkpoint":
                    checkpoint = data.get("label")
                if prefix in ("performance_span", "performance_phase_counter", "host_timeline_interval", "gpu_timeline_interval"):
                    data["_checkpoint"] = checkpoint
                data["_source_line"] = line_no
                clock = ("host_monotonic_relative" if prefix.startswith("host_timeline") else
                         (str(data.get("clock", "opencl_device")) + "_unaligned") if prefix.startswith("gpu_timeline") else "reported")
                if prefix not in grouped:
                    grouped[prefix] = Table(prefix, source, clock)
                grouped[prefix].add(data)
                if prefix in ("host_timeline_interval", "gpu_timeline_interval"):
                    timeline_count += 1
                if prefix in ("grouped_node_complete", "node_complete") and "elapsed_ms" in data:
                    proofs.append({"artifact": data.get("artifact", data.get("node", "unknown")),
                                   "elapsed_seconds": float(data["elapsed_ms"]) / 1000,
                                   "cache_hits": data.get("cache_hits"), "setups": data.get("setups"),
                                   "resumed": data.get("resumed"), "source": source, "source_line": line_no})
                    proofs[-1].update({key: data[key] for key in ("gpu_uuid", "worker_pid", "accepted_ms")
                                       if key in data})
                if "checkpoint" in prefix:
                    for key in ("dropped", "spans_dropped", "spans_open", "malformed", "open_frames", "events_dropped"):
                        if isinstance(data.get(key), (int, float)) and data[key] > 0:
                            warnings.append(f"{prefix}: {key}={data[key]} in {source}")
        tables.extend(t.finish() for t in grouped.values())
    return {"tables": tables, "timeline_events": timeline_count, "resource_samples": resource_count}, sources, sorted(set(warnings)), proofs
