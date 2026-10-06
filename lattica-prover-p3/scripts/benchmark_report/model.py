"""Versioned, platform-neutral records. No GPU or operating-system probes."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

VERSION = 1
SAFE_INTEGER = 2**53 - 1
DEFAULT_ROOT = Path(__file__).resolve().parents[3]
ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def identity(value):
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def exact(value):
    """JSON/JavaScript must not round timestamps or 64-bit counters."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and abs(value) > SAFE_INTEGER:
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite measurement")
    if isinstance(value, dict):
        return {str(k): exact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [exact(v) for v in value]
    return value


def encode(value, depth=0):
    """Readable metadata and one compact row per sample/event."""
    pad = "  " * depth
    if isinstance(value, dict):
        if not value:
            return "{}"
        return "{\n" + ",\n".join(
            pad + "  " + json.dumps(k, ensure_ascii=False) + ": " + encode(v, depth + 1)
            for k, v in sorted(value.items())
        ) + "\n" + pad + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(v, (dict, list)) for v in value):
            return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return "[\n" + ",\n".join(pad + "  " + encode(v, depth + 1) for v in value) + "\n" + pad + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def json_bytes(value):
    return (encode(exact(value)) + "\n").encode()


def atomic_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == data:
        return False
    fd, name = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        return True
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read(path):
    return json.loads(Path(path).read_text(), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def relative(path, root=DEFAULT_ROOT):
    path = Path(path)
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def reference(path, root=DEFAULT_ROOT):
    path = Path(path)
    return {"path": relative(path, root), "sha256": digest(path), "bytes": path.stat().st_size}


def number(value):
    if isinstance(value, bool):
        return None
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (ValueError, TypeError):
        return None


def seconds(value, factor=1):
    n = number(value)
    return n / factor if n is not None else None


def blank_run(run_id, label, kind="solving"):
    return {
        "schema_version": VERSION, "run_id": run_id, "label": label, "kind": kind,
        "status": "unknown", "track": "unknown", "platform": {}, "revision": {},
        "measurement_scope": "unknown",
        "workload": {"user_transactions": None, "issuance_transactions": None,
                     "fixture_reuse": None, "count_evidence": None},
        "timing": {"elapsed_seconds": None, "recursive_seconds": None},
        "verification": {"cpu_audited": None, "root_bytes": None, "root_sha256": None},
        "configuration": {}, "stages": [], "proofs": [],
        "measurements": {"tables": [], "timeline_events": 0, "resource_samples": 0},
        "sources": [], "limitations": [],
    }


def reject_payloads(value):
    """Records retain public measurements and digests, never wallet secrets."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in ("private_key", "secret_key", "seed_phrase", "mnemonic",
                               "proof_payload", "wallet_material", "private_inputs",
                               "witness", "witnesses", "raw_proof"):
                raise ValueError("benchmark records must not contain secret or proof payload fields")
            reject_payloads(item)
    elif isinstance(value, list):
        for item in value:
            reject_payloads(item)


def validate_run(run):
    if run.get("schema_version") != VERSION:
        raise ValueError("unsupported run schema_version")
    if not ID_PATTERN.fullmatch(run.get("run_id", "")):
        raise ValueError("invalid run_id")
    for key in ("label", "status", "track", "measurement_scope"):
        if not isinstance(run.get(key), str) or not run[key]:
            raise ValueError("missing run " + key)
    if run.get("kind") not in ("solving", "registration", "component", "diagnostic", "summary"):
        raise ValueError("invalid run kind")
    for key in ("platform", "revision", "workload", "timing", "verification", "configuration", "measurements"):
        if not isinstance(run.get(key), dict):
            raise ValueError("missing run " + key)
    for key in ("stages", "proofs", "sources", "limitations"):
        if not isinstance(run.get(key), list):
            raise ValueError("missing run " + key)
    if run.get("adapter") == "typed-worker" and run.get("status") == "succeeded":
        recorded = run["configuration"].get("recorded_fresh_proofs")
        if recorded is not None and (type(recorded) is not int or recorded < 0 or recorded != len(run["proofs"])):
            raise ValueError("fresh proof timings do not match the successful typed worker result")
    for field in ("user_transactions", "issuance_transactions"):
        n = run["workload"].get(field)
        if n is not None and (type(n) is not int or n < 0):
            raise ValueError("invalid transaction count")
    count = run["workload"].get("user_transactions")
    if count is not None and not run["workload"].get("count_evidence"):
        raise ValueError("transaction counts require evidence")
    for field, value in run["timing"].items():
        if field.endswith("_seconds") and value is not None and (type(value) not in (int, float) or number(value) is None or value < 0):
            raise ValueError("invalid duration")
    if run["verification"].get("cpu_audited") is not None and type(run["verification"]["cpu_audited"]) is not bool:
        raise ValueError("cpu_audited must be boolean or null")
    reject_payloads(run)
    tables = run["measurements"].get("tables")
    if not isinstance(tables, list):
        raise ValueError("measurements.tables must be a list")
    for key in ("timeline_events", "resource_samples"):
        value = run["measurements"].get(key)
        if type(value) is not int or value < 0:
            raise ValueError("invalid measurement count: " + key)
    for source in run["sources"]:
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise ValueError("invalid source path")
        if not re.fullmatch(r"[a-f0-9]{64}", source.get("sha256", "")):
            raise ValueError("invalid source sha256")
        if type(source.get("bytes")) is not int or source["bytes"] < 0:
            raise ValueError("invalid source byte count")
    for table in run["measurements"].get("tables", []):
        if not isinstance(table, dict) or any(not isinstance(table.get(k), str) or not table[k]
                                              for k in ("kind", "source", "clock")):
            raise ValueError("measurement table needs kind, source and clock")
        columns, rows = table["columns"], table["rows"]
        if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns) or not isinstance(rows, list):
            raise ValueError("invalid measurement columns or rows")
        if len(columns) != len(set(columns)):
            raise ValueError("duplicate measurement columns")
        if any(len(row) != len(columns) for row in rows):
            raise ValueError("malformed measurement row")
        for col, values in table.get("dictionaries", {}).items():
            if col not in columns or not isinstance(values, list):
                raise ValueError("invalid measurement dictionary")
            pos = columns.index(col)
            if any(row[pos] is not None and (type(row[pos]) is not int or not 0 <= row[pos] < len(values)) for row in rows):
                raise ValueError("invalid dictionary index")
    actual_events = sum(len(t["rows"]) for t in tables if t["kind"] in
                        ("host_timeline_interval", "gpu_timeline_interval"))
    actual_samples = sum(len(t["rows"]) for t in tables if t["kind"] == "resource_samples")
    if actual_events != run["measurements"]["timeline_events"] or actual_samples != run["measurements"]["resource_samples"]:
        raise ValueError("measurement counts do not match retained rows")
    exact(run)


def successful(run):
    return run["kind"] == "solving" and run["status"] == "succeeded" and run["verification"].get("cpu_audited") is True


def transaction_rate(run):
    if run.get('configuration', {}).get('coordinator_recovery', {}).get('cached_native_continuation'):
        return None
    n = run["workload"].get("user_transactions")
    elapsed = run["timing"].get("elapsed_seconds")
    if not successful(run) or n is None or not elapsed or run["measurement_scope"] == "unknown":
        return None
    return n * 60 / elapsed


def observed_throughput(runs, windows):
    """A measured window can contain concurrent jobs; count its wall time once."""
    by_id = {r["run_id"]: r for r in runs}
    seen, count, elapsed, scopes = set(), 0, 0.0, set()
    for window in windows:
        duration = window.get("elapsed_seconds")
        if not duration or number(duration) is None or duration <= 0:
            raise ValueError("invalid measurement window")
        ids = list(dict.fromkeys(window["run_ids"]))
        if any(i in seen for i in ids):
            raise ValueError("attempt appears in multiple measurement windows")
        seen.update(ids)
        elapsed += duration
        for rid in ids:
            r = by_id[rid]
            scopes.add(r["measurement_scope"])
            if r["measurement_scope"] == "unknown" or len(scopes) > 1:
                raise ValueError("incompatible measurement scopes")
            n = r["workload"].get("user_transactions")
            if successful(r):
                if n is None:
                    return None
                count += n
    if elapsed == 0:
        return None
    return {"processed_user_transactions": count, "measured_seconds": elapsed,
            "transactions_per_minute": count * 60 / elapsed,
            "transactions_per_second": count / elapsed}


def summary(run):
    fields = ("run_id", "label", "kind", "status", "track", "platform", "measurement_scope",
              "workload", "timing", "verification", "revision", "limitations", "configuration")
    out = {k: run[k] for k in fields}
    out.update(proof_count=len(run["proofs"]), timeline_events=run["measurements"].get("timeline_events", 0),
               resource_samples=run["measurements"].get("resource_samples", 0),
               transactions_per_minute=transaction_rate(run))
    out["path"] = "runs/" + run["run_id"] + ".json"
    return out
