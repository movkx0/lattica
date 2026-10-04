"""Deterministic dataset and standalone HTML generation."""

import base64
from contextlib import contextmanager
import gzip
import json
from pathlib import Path

from .history import (comparison_windows, discover, enrich_multi, load_campaigns,
                      measurement_files, safe_metadata)
from .model import (DEFAULT_ROOT, VERSION, atomic_bytes, digest, exact, json_bytes,
                    observed_throughput, read, reference, summary, validate_run)


MILESTONES = [
    ("P0", "Measurement interface and baseline", "in progress",
     "Retained runs and reporting are available. End-to-end service measurement is still required."),
    ("P1", "GPU proving pipeline", "in progress",
     "CPU-audited recursive GPU runs are recorded. Full-tree qualification remains open."),
    ("P2", "Local DAG and durable state", "in progress",
     "Local DAG, persistence and worker evidence exist. Integrated recovery qualification remains open."),
    ("P3", "Remote subtree pool", "planned",
     "No remote-pool qualification is established by the retained benchmark evidence."),
    ("P4", "Capacity and cadence profiles", "planned",
     "512/4,096 capacity and cadence profiles, recursive closure and host activation remain unqualified."),
    ("P5", "Qualification and staged rollout", "blocked",
     "Production and four-wallet activation remain gated by integrated qualification."),
]


def initial_catalog():
    return {
        "schema_version": VERSION, "title": "Lattica solving observatory",
        "purpose": "Measure transaction throughput and engineering milestones.",
        "service_target": {
            "user_transactions_per_minute": 4, "attainment": "not established",
            "definition": "Valid, unique user transactions durably applied to canonical host-chain state per wall-clock minute. Include outages and recovery; exclude payouts, duplicates, invalids and failed or abandoned candidates. Report reorg reversals separately.",
            "source": "docs/recursive-proving-performance-analysis.md",
        },
        "milestone_source": "docs/high-throughput-proving-plan.md#8-engineering-project-plan",
        "milestones": [{"id": i, "label": label, "status": status, "note": note}
                       for i, label, status, note in MILESTONES],
        "tracks": [
            {"id": "linux-opencl", "label": "Linux · OpenCL", "status": "retained research evidence"},
            {"id": "apple-silicon", "label": "Apple silicon", "status": "awaiting imported measurements"},
            {"id": "unknown", "label": "Unspecified / diagnostic", "status": "metadata incomplete"},
        ],
        "campaigns": [], "runs": [], "comparisons": [], "archive_documents": [],
        "coverage": {}, "limitations": [
            "No hardware ranking. Compare progress only within compatible workload and measurement scopes.",
            "Aggregation of reused fixtures does not measure unique delivered-chain transactions.",
            "Missing telemetry stays unavailable. Historical files may already have been pruned.",
            "Configured memory budgets are not observed peaks. Unified memory is a shared pool.",
            "Inclusive phase totals are non-additive. Host and device timelines have separate clocks.",
        ],
    }


@contextmanager
def dataset_lock(output):
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".export-lock"
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise RuntimeError(f"another export holds {lock}; remove only after confirming it has stopped") from error
    try:
        yield
    finally:
        lock.rmdir()


def store_run(output, run, existing=None):
    validate_run(run)
    payload = json_bytes(run)
    path = output / "runs" / (run["run_id"] + ".json")
    if existing and path.is_file() and path.read_bytes() != payload:
        raise ValueError(f"run_id collision: {run['run_id']}; use a new run_id for a new measurement")
    atomic_bytes(path, payload)
    item = summary(run)
    item.update(file="runs/" + path.name, sha256=digest(path), bytes=path.stat().st_size,
                sources=run["sources"], campaign_ids=run.get("campaign_ids", []),
                milestones=run.get("milestones", []), adapter=run.get("adapter"))
    return item


def inventory(root, inputs):
    entries = []
    roots = inputs or sorted((root / "lattica-prover-p3/target").glob("block-v2-*"))
    for directory in roots:
        if not Path(directory).is_dir():
            continue
        for name in ("summary.json", "plan.json", "experiment.json", "run-state.json", "ledger.json"):
            for p in sorted(Path(directory).rglob(name)):
                data = safe_metadata(p)
                if data:
                    entries.append({"source": reference(p, root), "document": data})
    return entries


def update_coverage(catalog):
    runs = catalog["runs"]
    for track in {r["track"] for r in runs}:
        match = next((t for t in catalog["tracks"] if t["id"] == track), None)
        if not match:
            catalog["tracks"].append({"id": track, "label": track, "status": "measurements imported"})
        elif track == "apple-silicon":
            match["status"] = "measurements imported"
    sources = {s["path"]: s for r in runs for s in r["sources"]}
    catalog["coverage"] = {
        "runs": len(runs), "campaigns": len(catalog["campaigns"]),
        "timeline_events": sum(r["timeline_events"] for r in runs),
        "resource_samples": sum(r["resource_samples"] for r in runs),
        "source_files": len(sources), "source_bytes": sum(s["bytes"] for s in sources.values()),
        "cpu_audited_runs": sum(r["verification"].get("cpu_audited") is True for r in runs),
        "missing_pinned_sources": sum(p["availability"] == "missing"
                                      for c in catalog["campaigns"] for p in c["pins"]),
        "unavailable_references": sorted({p for c in catalog["campaigns"]
                                         for p in c.get("unavailable_references", [])}),
        "mismatched_pins": [p for c in catalog["campaigns"] for p in c["pins"] if p["matches"] is False],
        "documentary_only_campaigns": [c["id"] for c in catalog["campaigns"] if not c["run_ids"]],
        "retention": "All discovered structured performance records and resource samples are retained. Original documentary evidence is embedded. Proof payloads, wallet stores and arbitrary log text are excluded.",
    }
    for m in catalog["milestones"]:
        m["evidence"] = [c["id"] for c in catalog["campaigns"] if c["milestone"] == m["id"]]


def import_history(output, root=DEFAULT_ROOT, inputs=None):
    old = read(output / "catalog.json") if (output / "catalog.json").exists() else initial_catalog()
    catalog = initial_catalog()
    catalog["campaigns"] = load_campaigns(root) if inputs is None else old["campaigns"]
    campaigns = catalog["campaigns"]
    for c in campaigns:
        if inputs is None:
            c["run_ids"] = []
    latest = next((c for c in campaigns if c["id"] == "block-v2-multi-gpu-2026-10-04"), None)
    # Keep portable imports and previously exported records even if target was pruned.
    by_id = {r["run_id"]: r for r in old["runs"]}
    worker_sources = {s["path"]: r["run_id"] for r in old["runs"] if r.get("adapter") == "worker"
                      for s in r["sources"] if s["path"].endswith(("/attempt.json", "/result.json"))}
    retired_files = []
    imported = []
    for run in discover(root, inputs, campaigns):
        enrich_multi(run, latest)
        if run.get("adapter") == "worker":
            for source in run["sources"]:
                previous = worker_sources.get(source["path"])
                if previous and previous != run["run_id"] and previous in by_id:
                    retired_files.append(output / by_id.pop(previous)["file"])
        item = store_run(output, run)
        by_id[item["run_id"]] = item
        imported.append(item)
    catalog["runs"] = sorted(by_id.values(), key=lambda r: r["run_id"])
    windows = comparison_windows(root, inputs, catalog["runs"])
    comparisons = {c["id"]: c for c in old["comparisons"]}
    for group, values in windows.items():
        result = observed_throughput(catalog["runs"], values) if all(w["complete_mapping"] for w in values) else None
        comparisons[group] = {"id": group, "label": group.split("/")[-1],
                              "scope": "recursive_aggregation", "windows": values,
                              "aggregate": result,
                              "note": "Completed, CPU-audited fixture transactions divided by pair wall time. Each concurrent window is counted once."}
    catalog["comparisons"] = list(comparisons.values())
    documents = {d["source"]["path"]: d for d in old.get("archive_documents", [])}
    for d in inventory(root, inputs):
        documents[d["source"]["path"]] = d
    catalog["archive_documents"] = [documents[k] for k in sorted(documents)]
    # Restore links to retained records whose original source has since disappeared.
    for c in campaigns:
        c["run_ids"] = sorted({r["run_id"] for r in catalog["runs"] if c["id"] in r.get("campaign_ids", [])})
    update_coverage(catalog)
    atomic_bytes(output / "catalog.json", json_bytes(catalog))
    for path in retired_files:
        path.unlink(missing_ok=True)
    return catalog


def ingest(output, input_path, root=DEFAULT_ROOT):
    if input_path.is_dir():
        return import_history(output, root, [input_path])
    data = read(input_path)
    if "run_id" not in data:
        raise ValueError("portable input must be a versioned run record; use a directory for controller archives")
    validate_run(data)
    catalog = read(output / "catalog.json") if (output / "catalog.json").exists() else initial_catalog()
    by_id = {r["run_id"]: r for r in catalog["runs"]}
    by_id[data["run_id"]] = store_run(output, data, existing=data["run_id"] in by_id)
    catalog["runs"] = sorted(by_id.values(), key=lambda r: r["run_id"])
    for track in {r["track"] for r in catalog["runs"]}:
        match = next((t for t in catalog["tracks"] if t["id"] == track), None)
        if match:
            match["status"] = "measurements imported"
        else:
            catalog["tracks"].append({"id": track, "label": track, "status": "measurements imported"})
    update_coverage(catalog)
    atomic_bytes(output / "catalog.json", json_bytes(catalog))
    return catalog


def packed(data):
    return base64.b64encode(gzip.compress(data, compresslevel=6, mtime=0)).decode("ascii")


def render(output):
    catalog = read(output / "catalog.json")
    template = Path(__file__).with_name("page.html").read_text()
    payloads = ['<script id="catalog-data" type="application/octet-stream">' +
                packed(json.dumps(exact(catalog), separators=(",", ":"), ensure_ascii=False).encode()) + '</script>']
    for run in catalog["runs"]:
        path = output / run["file"]
        if digest(path) != run["sha256"]:
            raise ValueError("dataset hash mismatch: " + run["file"])
        payloads.append('<script id="data-' + run["run_id"] + '" type="application/octet-stream">' +
                        packed(path.read_bytes()) + '</script>')
    html = template.replace("<!-- DATA -->", "\n".join(payloads))
    atomic_bytes(output / "index.html", html.encode())
    return len(html.encode())


def check(output):
    catalog = read(output / "catalog.json")
    if catalog["schema_version"] != VERSION:
        raise ValueError("unsupported catalog version")
    seen = set()
    for item in catalog["runs"]:
        if item["run_id"] in seen:
            raise ValueError("duplicate run ID")
        seen.add(item["run_id"])
        path = output / item["file"]
        if path.resolve().parent != (output / "runs").resolve():
            raise ValueError("run path must be directly inside runs/")
        if digest(path) != item["sha256"]:
            raise ValueError("run hash mismatch: " + item["file"])
        run = read(path)
        validate_run(run)
        if run["run_id"] != item["run_id"]:
            raise ValueError("run ID mismatch")
        for k, v in summary(run).items():
            if item.get(k) != v:
                raise ValueError("stale summary: " + item["run_id"] + ":" + k)
    for c in catalog["campaigns"]:
        if any(r not in seen for r in c["run_ids"]):
            raise ValueError("unknown campaign run")
    for c in catalog["comparisons"]:
        if c["aggregate"] is not None:
            result = observed_throughput(catalog["runs"], c["windows"])
            if result != c["aggregate"]:
                raise ValueError("stale comparison")
    return {"runs": len(seen), "campaigns": len(catalog["campaigns"]), "status": "valid"}
