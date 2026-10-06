"""Adapters for retained research evidence. Never infer transactions from proofs."""

from collections import defaultdict
import math
from pathlib import Path
import re

from .measurements import collect
from . import typed, query
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
    if adapter := typed.classify(data, path):
        return adapter
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
    if adapter.startswith("typed-"):
        if adapter == "typed-worker":
            apply_metadata(run, data, "worker")
        typed.metadata(run, data, adapter)
        return
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
            metadata.update(directory.rglob("worker-result.json"))
            metadata.update(p for p in directory.rglob('summary.json')
                            if not (p.parent / 'owner/result.json').is_file())
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
        key = relative(p.with_name("result.json") if adapter in ("worker", "typed-worker", "typed-attempt") else p, root)
        run = blank_run("run-" + identity(key), p.parent.name if adapter != "legacy" else p.stem)
        apply_metadata(run, data, adapter)
        run["sources"] = [reference(p, root)]
        typed.enrich(run, data, p, root)
        run["_files"] = set()
        run["_base"] = p.parent
        if adapter == "legacy":
            owned = {p.with_suffix(".log")}
            job = resolve(data["job_directory"], root)
            if job and job.is_dir():
                owned.update(measurement_files(job))
        else:
            owned = set(measurement_files(p.parent))
            if adapter == "typed-worker" and data.get("schema") == typed.SHARED_SCHEMA:
                owned.update(measurement_files(p.parent.parent))
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
        measurements, sources, warnings, proofs = collect(files, root,
            typed_construction=run.get("configuration", {}).get("construction"))
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


def pinned_comparison_source(root, source):
    """Only resolve recorded benchmark inputs inside this repository."""
    if not isinstance(source, dict) or not source.get("path"):
        return None
    path = (root / source["path"]).resolve()
    if (not path.is_relative_to(root.resolve()) or not path.is_file()
            or digest(path) != source.get("sha256")):
        return None
    return path


def typed_fleet_windows(root, path, data, by_source):
    trials = data.get("trials", [])
    requested = data.get("requested_pairs")
    complete = (data.get("status") == "succeeded" and type(requested) is int and requested > 0
                and len(data.get("pairs", [])) == requested and len(trials) == 2 * requested)
    if complete:
        expected = {(number, mode) for number in range(1, requested + 1)
                    for mode in ("sequential", "concurrent")}
        complete = ({(t.get("pair"), t.get("mode")) for t in trials} == expected
                    and {p.get("pair") for p in data["pairs"]} == set(range(1, requested + 1)))
    windows = []
    for trial in trials:
        mode = trial.get("mode")
        if mode not in ("sequential", "concurrent"):
            continue
        fleet = pinned_comparison_source(root, trial.get("source"))
        workers = trial.get("trials", [])
        recorded = safe_metadata(fleet) if fleet else None
        consistent = (recorded is not None and recorded.get("schema") == "lattica-typed-fleet-v1"
            and recorded.get("status") == "succeeded" and recorded.get("mode") == mode
            and recorded.get("construction") == data.get("construction")
            and recorded.get("count_per_root") == data.get("count_per_root")
            and recorded.get("execution_elapsed_seconds") == trial.get("execution_elapsed_seconds")
            and recorded.get("trials") == workers
            and recorded.get("cpu_audited_roots") == trial.get("cpu_audited_roots") == len(workers)
            and recorded.get("fresh_recursive_proofs") == trial.get("fresh_recursive_proofs"))
        sources = [pinned_comparison_source(root, worker.get("result_source")) for worker in workers]
        ids = [by_source[relative(source, root)] for source in sources
               if source is not None and relative(source, root) in by_source]
        windows.append((relative(path.parent, root) + ":" + mode, {
            "run_ids": ids, "elapsed_seconds": trial.get("execution_elapsed_seconds"),
            "source": reference(fleet or path, root), "campaign_source": reference(path, root),
            "recorded": {"arm": mode, "pair": trial.get("pair"),
                "individual_seconds": [worker.get("worker_seconds") for worker in workers],
                "construction": data.get("construction"), "count_per_root": data.get("count_per_root"),
                "series_status": data.get("status"), "requested_pairs": requested,
                "repeat_qualified": complete and requested >= 5 and data.get("repeat_qualified") is True,
                "first_worker_sample_ns": str(trial.get("first_worker_sample_ns", "")),
                "last_worker_sample_ns": str(trial.get("last_worker_sample_ns", "")),
                "adopted": trial.get("adopted", False)},
            # Incomplete campaigns have unmeasured or failed windows. Retain their
            # completed trials without promoting a partial denominator to a rate.
            "source_consistent": consistent,
            "complete_mapping": bool(complete and consistent and workers and all(sources)
                and len(ids) == len(workers) == len(set(ids))),
        }))
    return windows


def typed_construction_windows(root, path, data, by_source):
    """Keep matched single-worker comparisons separate from fleet windows."""
    baseline, candidate = data.get("baseline_construction", "reference"), data.get("candidate_construction", "finalizer")
    if baseline == candidate or any(c not in ("reference", "finalizer", "paired")
                                    for c in (baseline, candidate)):
        return []
    trials, pairs = data.get("trials", []), data.get("pairs", [])
    requested = data.get("requested_pairs")
    complete = (data.get("status") == "succeeded" and type(requested) is int
                and requested > 0 and len(pairs) == requested and len(trials) == 2 * requested)
    if complete:
        expected = [(number, construction) for number in range(1, requested + 1)
                    for construction in ((baseline, candidate) if number % 2 else (candidate, baseline))]
        complete = ([(t.get("pair"), t.get("construction")) for t in trials] == expected
                    and [p.get("pair") for p in pairs] == list(range(1, requested + 1)))
    if complete:
        for pair in pairs:
            rows = [t for t in trials if t["pair"] == pair["pair"]]
            seconds = {t["construction"]: t.get("worker_seconds") for t in rows}
            valid_times = all(type(value) in (int, float) and math.isfinite(value) and value > 0
                              for value in seconds.values())
            reduction = pair.get("worker_reduction_percent")
            complete = bool(complete and valid_times and pair.get("worker_seconds") == seconds
                and pair.get("order") == [t["construction"] for t in rows]
                and type(reduction) in (int, float) and math.isfinite(reduction)
                and math.isclose(reduction, (1 - seconds[candidate] / seconds[baseline]) * 100,
                                 rel_tol=1e-12, abs_tol=1e-9))
    assignment = pinned_comparison_source(root, data.get("resource_assignment"))
    windows = []
    for trial in trials:
        construction = trial.get("construction")
        if construction not in (baseline, candidate):
            continue
        result_path = pinned_comparison_source(root, trial.get("result_source"))
        summary_path = pinned_comparison_source(root, trial.get("summary_source"))
        result = safe_metadata(result_path) if result_path else None
        summary = safe_metadata(summary_path) if summary_path else None
        consistent = bool(assignment and result is not None and summary is not None
            and result.get("schema") == typed.GPU_SCHEMA and summary.get("schema") == typed.GPU_SCHEMA
            and result.get("status") == summary.get("status") == "succeeded"
            and summary.get("result") == result and result.get("construction") == construction
            and result.get("count") == data.get("count") and result.get("cpu_audited") is True
            and trial.get("cpu_audited") is True
            and result.get("fresh_proofs") == trial.get("fresh_proofs")
            and result.get("elapsed_seconds") == trial.get("worker_seconds")
            and result.get("resource_assignment_sha256") == data["resource_assignment"].get("sha256")
            and result.get("artifacts", {}).get("node.6.0") == trial.get("root_sha256"))
        ids = ([by_source[relative(result_path, root)]]
               if result_path and relative(result_path, root) in by_source else [])
        pair = next((p for p in pairs if p.get("pair") == trial.get("pair")), {})
        windows.append((relative(path.parent, root) + ":" + construction, {
            "run_ids": ids, "elapsed_seconds": trial.get("worker_seconds"),
            "source": reference(summary_path or path, root), "campaign_source": reference(path, root),
            "recorded": {"arm": construction, "pair": trial.get("pair"),
                "individual_seconds": [trial.get("worker_seconds")],
                "construction": construction, "count_per_root": data.get("count"),
                "baseline_construction": baseline, "candidate_construction": candidate,
                "series_status": data.get("status"), "requested_pairs": requested,
                "worker_reduction_percent": pair.get("worker_reduction_percent"),
                "timing_boundary": data.get("timing_boundary")},
            "source_consistent": consistent,
            "complete_mapping": bool(consistent and len(ids) == 1),
        }))
    ids = [rid for _, window in windows for rid in window["run_ids"]]
    complete = bool(complete and len(windows) == len(trials) and len(ids) == len(set(ids))
                    and all(window["complete_mapping"] for _, window in windows))
    for _, window in windows:
        window["complete_mapping"] = complete
        window["recorded"]["repeat_qualified"] = bool(complete and requested >= 5)
    return windows


def comparison_windows(root, input_paths, summaries):
    by_source = {s["path"]: r["run_id"] for r in summaries for s in r.get("sources", [])}
    groups = defaultdict(list)
    paths = input_paths or list((root / "lattica-prover-p3/target").glob("block-v2-*"))
    for directory in paths:
        if not Path(directory).is_dir():
            continue
        for p in sorted(Path(directory).rglob("summary.json")):
            data = safe_metadata(p)
            if data and data.get("schema") == "lattica-typed-fleet-comparison-v1":
                for group, window in typed_fleet_windows(root, p, data, by_source):
                    groups[group].append(window)
            if data and data.get("schema") == "lattica-typed-query-comparison-v1":
                for group, window in query.windows(root, p, data, by_source):
                    groups[group].append(window)
            if data and data.get("schema") == "lattica-typed-comparison-v1":
                for group, window in typed_construction_windows(root, p, data, by_source):
                    groups[group].append(window)
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
