"""Adapters for retained research evidence. Never infer transactions from proofs."""

from collections import defaultdict
from pathlib import Path
import re

from .measurements import collect
from .model import blank_run, digest, identity, read, reference, relative, seconds


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)


def resolve(value, root):
    if not isinstance(value, str) or "\n" in value:
        return None
    if value.startswith("lattica-prover-p3/target/") or value.startswith("docs/evidence/"):
        return root / value
    if value.startswith("/tmp/") or value.startswith(str(root) + "/"):
        return Path(value)
    return None


def milestone(name):
    if any(s in name for s in ("local-dag", "journal", "artifact-store", "supervisor",
                                "worker", "fencing", "reservations", "cpu-admission",
                                "cpu-arrivals", "cpu-process", "cpu-preparation")):
        return "P2"
    if any(s in name for s in ("perf-cache", "cache-bench", "scalability")):
        return "P0"
    return "P1"


def load_campaigns(root):
    campaigns = []
    for p in sorted((root / "docs/evidence").glob("*.json")):
        data = read(p)
        paths = sorted({relative(q, root) for v in strings(data)
                        if (q := resolve(v, root)) is not None})
        pins = []
        for obj in objects(data):
            if isinstance(obj.get("path"), str) and isinstance(obj.get("sha256"), str):
                q = resolve(obj["path"], root)
                if q:
                    pins.append({"path": relative(q, root), "expected_sha256": obj["sha256"],
                                 "availability": "retained" if q.is_file() else "missing",
                                 "matches": digest(q) == obj["sha256"] if q.is_file() else None})
        campaigns.append({"id": p.stem, "label": p.stem.removeprefix("block-v2-"),
                          "milestone": milestone(p.stem), "source": reference(p, root),
                          "recorded_status": data.get("status"),
                          "document": data, "referenced_paths": paths, "pins": pins,
                          "run_ids": []})
        campaigns[-1]["unavailable_references"] = [s for s in paths if not (root / s).exists()]
    return campaigns


def measurement_files(directory):
    # File contents from proof, key, wallet and job stores are deliberately not read.
    return sorted(p for p in directory.rglob("*") if p.is_file()
                  and (p.suffix == ".log" or
                       (p.suffix in (".jsonl", ".csv") and
                        any(k in p.name for k in ("telemetry", "vram", "host", "resource")))))


def safe_metadata(path):
    """Only recognized controller/accounting formats, never arbitrary job JSON."""
    try:
        data = read(path)
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def classify(data, path):
    if path.name == "result.json" and "cpu_audited" in data and "budget" in data:
        return "worker"
    if path.name == "attempt.json" and all(k in data for k in ("budget", "config", "job")):
        return "worker"
    if path.name == "manifest.json" and "config" in data and isinstance(data.get("attempts"), list):
        if "recursive_command_ms" in data or "pins" in data:
            return "grouped"
    if "recursive_command_ms" in data and "nodes" in data and "job_directory" in data:
        return "legacy"
    return None


def apply_metadata(run, data, adapter):
    run["retained_metadata"] = data
    run["adapter"] = adapter
    run["measurement_scope"] = "recursive_aggregation"
    run["track"] = "linux-opencl"
    run["platform"] = {"os": "linux", "backend": "opencl", "memory_model": "discrete"}
    run["limitations"] = [
        "Research evidence; does not establish production or four-wallet readiness.",
        "Wallet proof creation and canonical chain acceptance are outside this measurement.",
        "Inclusive phase and GPU counters are non-additive; process checkpoints may reset.",
        "Host and OpenCL clocks are separate unless an explicit anchor was recorded.",
    ]
    run["timing"]["recursive_seconds"] = seconds(data.get("recursive_command_ms"), 1000)
    run["timing"]["elapsed_seconds"] = seconds(data.get("elapsed_seconds", data.get("controller_wall_seconds")))
    run["configuration"] = data.get("config", data.get("budget", {}))
    if adapter == "worker":
        run["status"] = data.get("status", "incomplete")
        if run["status"] not in ("succeeded", "failed", "incomplete"):
            run["status"] = "unknown"
        run["verification"].update(cpu_audited=data.get("cpu_audited"),
                                   root_bytes=data.get("root_bytes"),
                                   root_sha256=data.get("artifacts", {}).get("node.3.0"))
        budget = data.get("budget", {})
        run["platform"]["gpu"] = budget.get("admission_recheck", {}).get("gpu", budget.get("gpu"))
        run["platform"]["host"] = budget.get("admission_recheck", {}).get("host")
        run["revision"] = {k: data[k] for k in ("binary_sha256", "profile_sha256") if k in data}
    elif adapter == "grouped":
        status = data.get("status", "")
        run["status"] = ("succeeded" if status == "GPU_PROOF_VERIFIED_RESEARCH_ONLY"
                         else "failed" if "FAIL" in status.upper() else "incomplete")
        if "KEYS_MATCH" in status:
            run["kind"] = "registration"
            run["status"] = "succeeded"
            run["measurement_scope"] = "key_registration"
        root = data.get("root", {})
        run["verification"].update(cpu_audited=True if status == "GPU_PROOF_VERIFIED_RESEARCH_ONLY" else None,
                                   root_bytes=root.get("bytes"), root_sha256=root.get("sha256"))
        run["stages"] = data["attempts"]
        run["revision"] = {"pins": data.get("pins", {})}
    elif adapter == "legacy":
        # These controller summaries have no explicit CPU-audit result.
        run["status"] = "completed" if data.get("root_sha256") else "incomplete"
        run["verification"].update(root_bytes=data.get("root_bytes"), root_sha256=data.get("root_sha256"))
        run["configuration"] = {k: data[k] for k in
                                ("mode", "gpu_transfer_mode", "gpu_tree_retention_enabled") if k in data}
        run["stages"] = data.get("stages", [])
        if isinstance(run["stages"], dict):
            run["stages"] = [{"name": k, "recorded": v} for k, v in run["stages"].items()]


def discover(root, inputs=None, campaigns=None):
    """Partition every retained measurement source into one concrete run."""
    campaigns = campaigns or []
    roots = inputs or sorted((root / "lattica-prover-p3/target").glob("block-v2-*"))
    roots = [Path(p).resolve() for p in roots if Path(p).exists()]
    all_files = set()
    metadata = set()
    for directory in roots:
        if directory.is_dir():
            all_files.update(measurement_files(directory))
            metadata.update(directory.rglob("manifest.json"))
            metadata.update(directory.rglob("result.json"))
            metadata.update(p for p in directory.rglob("attempt.json")
                            if not p.with_name("result.json").exists())
            metadata.update(directory.glob("pair-*.json"))
        elif directory.suffix == ".json":
            metadata.add(directory)
        else:
            all_files.add(directory)
    # Documentary references can include surviving /tmp logs outside target.
    if inputs is None:
        for c in campaigns:
            for s in c["referenced_paths"]:
                p = resolve(s, root)
                if p and p.is_file() and p.suffix in (".log", ".csv", ".jsonl"):
                    all_files.add(p.resolve())
    records, ownership = {}, {}
    for p in sorted(metadata):
        data = safe_metadata(p)
        adapter = classify(data, p) if data else None
        if not adapter:
            continue
        key = relative(p.with_name("result.json") if adapter == "worker" else p, root)
        run = blank_run("run-" + identity(key), p.parent.name if adapter != "legacy" else p.stem)
        apply_metadata(run, data, adapter)
        run["sources"] = [reference(p, root)]
        run["_files"] = set()
        run["_base"] = p.parent
        if adapter == "legacy":
            owned = {p.with_suffix(".log")}
            job = resolve(data["job_directory"], root)
            if job and job.is_dir():
                owned.update(measurement_files(job))
        else:
            owned = set(measurement_files(p.parent))
            for name in ("attempt.json", "accounting.json", "budget.json"):
                extra = p.with_name(name)
                if extra.is_file():
                    value = safe_metadata(extra)
                    run.setdefault("controller_metadata", {})[name] = value
                    run["sources"].append(reference(extra, root))
            if adapter == "worker":
                for name in ("check", "pairs", "merges", "check-all"):
                    start, end = p.with_name(name + "-started.json"), p.with_name(name + "-finished.json")
                    if start.is_file() and end.is_file():
                        a, b = read(start)["started_ns"], read(end)["finished_ns"]
                        run["stages"].append({"name": name, "started_ns": str(a), "finished_ns": str(b),
                                              "wall_seconds": (b - a) / 1e9})
                attempt = run.get("controller_metadata", {}).get("attempt.json") or {}
                run["configuration"] = {"budget": data.get("budget"), "config": attempt.get("config"),
                                        "job": attempt.get("job")}
        records[key] = run
        for f in owned:
            if f.is_file():
                # A more deeply nested manifest owns its logs.
                old = ownership.get(f)
                if old is None or len(str(p.parent)) > len(str(records[old]["_base"])):
                    ownership[f] = key
                    all_files.add(f)
    # Orphan files remain inspectable diagnostics, without invented success/counts.
    for p in sorted(all_files):
        key = ownership.get(p)
        if key is None:
            key = relative(p.parent, root) + "/diagnostic"
            if key not in records:
                run = blank_run("run-" + identity(key), p.parent.name, "diagnostic")
                run["measurement_scope"] = "diagnostic"
                run["_files"], run["_base"] = set(), p.parent
                records[key] = run
            ownership[p] = key
        records[key]["_files"].add(p)
    # Exact file duplicates get source aliases, without re-counting their events.
    hashes = {}
    for key, run in sorted(records.items(), key=lambda item: (item[1]["kind"] == "diagnostic", item[0])):
        files = []
        aliases = []
        local_hashes = {}
        for p in sorted(run.pop("_files")):
            sha = digest(p)
            previous = local_hashes.get(sha)
            if run["kind"] == "diagnostic":
                previous = previous or hashes.get(sha)
            if previous:
                alias = reference(p, root)
                alias["identical_to"] = previous
                aliases.append(alias)
            else:
                ref = {"run_id": run["run_id"], "path": relative(p, root)}
                local_hashes[sha] = ref
                hashes.setdefault(sha, ref)
                files.append(p)
        measurements, sources, warnings, proofs = collect(files, root)
        run["measurements"], run["proofs"] = measurements, proofs
        run["sources"].extend(sources + aliases)
        run["limitations"].extend(warnings)
        base = relative(run.pop("_base"), root)
        linked = []
        for c in campaigns:
            refs = c["referenced_paths"]
            if any(s == base or s.startswith(base + "/") or base.startswith(s + "/") for s in refs):
                linked.append(c["id"])
                c["run_ids"].append(run["run_id"])
        run["campaign_ids"] = linked
        run["milestones"] = sorted({c["milestone"] for c in campaigns if c["id"] in linked})
        if run["kind"] == "diagnostic":
            run["limitations"].append("No recognized complete run manifest; retained measurements only.")
        explicit = run.get("controller_metadata", {}).get("attempt.json", {}) or {}
        workload = explicit.get("config", {}).get("benchmark_workload")
        if workload and run.get("adapter") == "worker":
            run["workload"].update(workload)
        yield run


def enrich_multi(run, campaign):
    """The frozen campaign explicitly establishes eight non-issuance inputs."""
    if not campaign or run.get("adapter") != "worker":
        return
    known = ("block-v2-multi-pairs-20261003-e", "block-v2-multi-bootstrap-20261003-b",
             "block-v2-multi-qualification-20261003-c", "block-v2-multi-qualification-20261003-d")
    if not any(any(k in s["path"] for k in known) for s in run["sources"]):
        return
    run["workload"] = {
        "user_transactions": 8, "issuance_transactions": 0, "fixture_reuse": True,
        "count_evidence": campaign["source"]["path"],
        "description": "Eight already-created non-issuance wallet proofs, seven recursive proofs, CPU root audit.",
    }
    run["platform"]["recorded_campaign_hardware"] = campaign["document"].get("hardware")
    run["milestones"] = sorted(set(run["milestones"] + ["P0", "P1"]))


def comparison_windows(root, input_paths, summaries):
    by_source = {s["path"]: r["run_id"] for r in summaries for s in r.get("sources", [])}
    groups = defaultdict(list)
    paths = input_paths or list((root / "lattica-prover-p3/target").glob("block-v2-*"))
    for directory in paths:
        if not Path(directory).is_dir():
            continue
        for p in sorted(Path(directory).rglob("*-result.json")):
            data = safe_metadata(p)
            if not data or "pair_makespan_seconds" not in data:
                continue
            arm_dir = p.with_name(p.name.removesuffix("-result.json"))
            ids = [by_source[relative(q, root)] for q in sorted(arm_dir.glob("*/result.json"))
                   if relative(q, root) in by_source]
            # A partial window is retained, but never given a successful rate.
            groups[relative(p.parent, root) + ":" + data["arm"]].append({
                "run_ids": ids, "elapsed_seconds": data["pair_makespan_seconds"],
                "source": reference(p, root), "recorded": data,
                "complete_mapping": ((len(ids) == len(data.get("individual_seconds", [])) and len(ids) > 0)
                                     or data.get("status") == "failed"),
            })
    return dict(groups)
