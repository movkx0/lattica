#!/usr/bin/env python3
"""One fresh twelve-transaction Metal job and a separate CPU root audit.

Wallet fixture creation and compilation are reported separately from aggregation.
No repetitions, thread matrix, fixed RSS cap, or total execution deadline.
"""
import argparse
import html
import importlib.util
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import socket
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apple_screen", ROOT / "scripts/bench-apple-throughput.py")
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)
baseline = screen.baseline
digest = screen.digest
OPTIONS = {"pipeline": "reference", "poseidon_diagonal": "specialized", "ntt_tables": "on",
           "ntt_tile_log2": "12", "quotient": "cpu", "prefix_store": "separate"}
KEYS = ("height", "key.1", "key.2", "key.3")
NODES = [*(f"node.1.{i}" for i in range(6)), "node.2.3",
         *(f"node.2.{i}" for i in range(3)), "node.3.0", "node.3.1", "node.4.0"]


def expectation(path):
    rows = [line.split(" ", 1)[1] for line in path.read_text().splitlines()
            if line.startswith("twelve_expectation ")]
    if len(rows) != 1:
        raise RuntimeError("missing unique CPU-derived twelve expectation")
    value = json.loads(rows[0])
    if (value["level"], value["count"], value["fresh_recursive_proofs"]) != (4, 12, 13):
        raise RuntimeError("wrong twelve fixture geometry")
    return value


def render(report, path):
    rows = []
    ref = report.get("reference_eight", {})
    if ref:
        rows.append(("8 transactions · prior measured run", ref["seconds"], 8, ref["peak_rss_gib"], 7))
    if report.get("status") == "VERIFIED":
        rows.append(("12 transactions · new measured run", report["seconds"], 12,
                     report["aggregate_peak_rss_bytes"] / screen.GIB, 13))
    max_seconds = max((r[1] for r in rows), default=1)
    max_rate = max((r[2] * 3600 / r[1] for r in rows), default=1)
    def bars(rate=False):
        result = []
        for label, seconds, count, _, _ in rows:
            value = count * 3600 / seconds if rate else seconds
            scale = max_rate if rate else max_seconds
            unit = "tx-equivalents/hour" if rate else "seconds"
            result.append(f'<div class="bar-row"><div>{html.escape(label)}</div><div class="track"><div class="bar" style="width:{value/scale*100:.3f}%"></div></div><strong>{value:.2f} {unit}</strong></div>')
        return "".join(result)
    table = "".join(f"<tr><td>{html.escape(label)}</td><td>{proofs}</td><td>{seconds:.3f}</td><td>{3600/seconds:.2f}</td><td>{count*3600/seconds:.2f}</td><td>{memory:.2f}</td></tr>"
                    for label, seconds, count, memory, proofs in rows)
    encoded = json.dumps(report, indent=2).replace("<", "\\u003c")
    status = html.escape(report.get("status", "UNKNOWN"))
    failure = f'<p class="failure">{html.escape(report["failure"])}</p>' if report.get("failure") else ""
    comparison_note = ""
    if report.get("status") == "VERIFIED":
        swap_mib = report["swap_growth_bytes"] / 2**20
        pressure = "observed" if report["memory_pressure_incident"] else "not observed"
        comparison_note = (
            f'<p><strong>Proof validation passed.</strong> Swap growth: {swap_mib:.2f} MiB; '
            f'system memory-pressure incidents: {pressure}.</p>'
        )
        if not report["valid_comparison"]:
            comparison_note += (
                '<p><strong>Comparison caveat:</strong> This trial did not meet the strict '
                'zero-swap, normal-pressure comparison rule. Treat the comparison with the '
                'historical eight-transaction run as approximate.</p>'
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lattica: 12-transaction Apple benchmark</title>
<style>body{{font:16px/1.55 system-ui,sans-serif;color:#182632;background:#f5f7fa;max-width:1050px;margin:auto;padding:28px}}h1{{line-height:1.15}}.card{{background:white;padding:24px;border-radius:14px;margin:20px 0;border:1px solid #dce4ec}}.bar-row{{display:grid;grid-template-columns:260px 1fr 190px;gap:15px;align-items:center;margin:22px 0}}.track{{background:#e7edf3;border-radius:5px;height:28px}}.bar{{background:#256b97;border-radius:5px;height:100%;min-width:2px}}table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #dce4ec}}.scroll{{overflow:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}.failure{{color:#9c2222}}@media(max-width:720px){{body{{padding:16px}}.bar-row{{grid-template-columns:1fr;gap:5px}}.card{{padding:16px}}}}</style>
<h1>12-transaction proving on Apple Silicon</h1><p>Status: <strong>{status}</strong> · Apple M5 Pro · 64 GiB unified memory · 18 CPU threads · one Metal worker</p>{failure}{comparison_note}
<div class="card"><h2>Aggregation latency</h2><p>Startup through a separate CPU audit of the root-only proof bundle. Lower is faster.</p>{bars()}</div>
<div class="card"><h2>Aggregation throughput</h2><p>Extrapolated from one completed job per size, with existing wallet proofs. Higher is faster.</p>{bars(True)}</div>
<div class="card scroll"><table><thead><tr><th>Measured job</th><th>Fresh recursive proofs</th><th>Seconds</th><th>Jobs/hour</th><th>Tx-equivalents/hour</th><th>Peak RSS GiB</th></tr></thead><tbody>{table}</tbody></table></div>
<div class="card"><h2>What was proved</h2><p>Twelve distinct wallet spends sharing one anchor; six paired wrappers, one canonical empty subtree for slots 12–15, and six merges. The root is level 4 with count 12 and capacity 16. The four empty slots are not counted as transactions.</p><p>Metal shared buffers, specialized Poseidon diagonal and cached NTT tables; reference storage pipeline and CPU quotient. GPU work must be observed. Separate CPU audit binds the external profile, chain and ordered expected root, and rejects mutations.</p><p>Fixture generation and builds are excluded from aggregation timing. The eight-transaction result is historical; the fixture anchor differs. Each size has one measured sample, so this is not a statistical comparison or an isolated test of unified-memory architecture. These research proofs are not production block activation or confirmed chain throughput.</p><p>No benchmark time limit or fixed worker RSS ceiling. Existing system-memory-pressure monitoring remains active. Host and GPU memory overlap and are not added together.</p></div>
<details class="card"><summary>Full evidence, provenance and configuration</summary><pre id="evidence"></pre></details><script type="application/json" id="data">{encoded}</script><script>document.getElementById('evidence').textContent=JSON.stringify(JSON.parse(document.getElementById('data').textContent),null,2);</script></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("requires Apple Silicon")
    with screen.coordinator_lease():
        run(args)


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    build = json.loads(args.build.read_text())
    reference = json.loads(args.reference.read_text())
    ref = reference["windows"][1]
    if ref["status"] != "VERIFIED" or not ref["valid_comparison"]:
        raise RuntimeError("historical comparison must be verified")
    for name, sha in build["source_hashes"].items():
        if digest(ROOT / name) != sha:
            raise RuntimeError("source differs from frozen build: " + name)
    (out / "bin").mkdir()
    binaries = {}
    for role, name in [("cpu", "block-v2-grouped-probe"), ("metal", "block-v2-metal-grouped-probe"),
                       ("audit", "block-v2-grouped-artifact-audit")]:
        entry = build["binaries"][name]
        if digest(entry["path"]) != entry["sha256"]:
            raise RuntimeError("binary differs from build")
        binaries[role] = out / "bin" / name
        shutil.copy2(entry["path"], binaries[role])
    with tarfile.open(out / "source.tar.gz", "w:gz") as archive:
        for name in build["source_hashes"]:
            archive.add(ROOT / name, arcname=name)
        for path in (ROOT / "scripts").glob("*.py"):
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    report = {"schema": "apple-twelve-benchmark-v1", "status": "PREPARING", "build": build,
              "controller_sha256": digest(__file__), "source_archive_sha256": digest(out / "source.tar.gz"),
              "threads": 18, "workers": 1, "trials": 1, "transactions": 12, "fresh_recursive_proofs": 13,
              "candidate_options": OPTIONS, "reference_path": str(args.reference.resolve()),
              "reference_sha256": digest(args.reference), "source_changes_from_eight": sorted(
                  name for name, sha in build["source_hashes"].items()
                  if reference["build"]["source_hashes"].get(name) != sha),
              "reference_eight": {"seconds": ref["seconds"], "transactions": 8,
                  "tx_equivalents_per_hour": 8 * 3600 / ref["seconds"],
                  "peak_rss_gib": ref["aggregate_peak_rss_bytes"] / screen.GIB},
              "timing_boundary": "startup, public-input checks, 13 fresh recursive proofs, separate CPU root audit",
              "wallet_proof_generation_included": False, "production_ready": False}
    def save():
        screen.save(out / "result.json", report)
        render(report, args.html)
    save()
    fixture = out / "fixture"
    prep_scratch = out / "preparation-scratch"
    prep_scratch.mkdir()
    cpu_env = baseline.environment(baseline.arm("cpu", 18), prep_scratch, False)
    started = time.monotonic()
    try:
        with (out / "preparation-resources.jsonl").open("w") as resource_log:
            owned = screen.OwnedProcesses(resource_log)
            try:
                with (out / "prepare.log").open("w") as log:
                    print("PREPARING twelve distinct wallet proofs; excluded from aggregation timing", flush=True)
                    owned.wait(owned.spawn([binaries["cpu"], "prepare-twelve", fixture], cpu_env, log))
                source = args.reference.parent / "fixture"
                for name in KEYS:
                    if digest(source / name) != reference["fixture_sha256"][name]:
                        raise RuntimeError("historical registry artifact changed")
                    shutil.copy2(source / name, fixture / name)
                with (out / "describe.log").open("w") as log:
                    owned.wait(owned.spawn([binaries["cpu"], "describe-twelve", fixture], cpu_env, log))
                expected = expectation(out / "describe.log")
            finally:
                owned.close()
        report["preparation_seconds"] = time.monotonic() - started
        report["expected"] = expected
        report["fixture_sha256"] = {p.name: digest(p) for p in fixture.iterdir() if p.is_file()}
        external = [expected[k] for k in ("profile", "chain", "root")]
        job = out / "job"
        shutil.copytree(fixture, job)
        report["status"] = "RUNNING"
        save()
        env = screen.policy(1, True, job / "scratch", "reference", 256, options=OPTIONS)
        cpu_env = baseline.environment(baseline.arm("cpu", 18), job / "scratch", False)
        report["explicit_environment"] = {k: v for k, v in env.items() if k.startswith(("LATTICA_", "RAYON_"))}
        started = time.monotonic()
        with (out / "resources.jsonl").open("w") as resource_log:
            owned = screen.OwnedProcesses(resource_log)
            parent = child = None
            try:
                with (job / "check.log").open("w") as log:
                    owned.wait(owned.spawn([binaries["cpu"], "describe-twelve", job], cpu_env, log))
                if expectation(job / "check.log") != expected:
                    raise RuntimeError("job public inputs differ from the independently prepared fixture")
                parent, child = socket.socketpair()
                env["LATTICA_V2_METAL_CONTROL_FD"] = str(child.fileno())
                with (job / "worker.log").open("w") as log:
                    worker = owned.spawn([binaries["metal"], "--metal-worker"], env, log,
                                         pass_fds=(child.fileno(),), role="worker")
                    child.close()
                    parent.sendall((json.dumps({"sequence": 0, "args": ["aggregate-twelve", str(job), *external]}) + "\n").encode())
                    parent.setblocking(False)
                    with selectors.DefaultSelector() as ready:
                        ready.register(parent, selectors.EVENT_READ)
                        frame = b""
                        completed = -1
                        while b"\n" not in frame:
                            owned.sample()
                            text = (job / "worker.log").read_text()
                            count = text.count("grouped_node_complete ")
                            if count != completed:
                                completed = count
                                report["completed_recursive_proofs"] = count
                                report["elapsed_seconds"] = time.monotonic() - started
                                save()
                                print(f"PROGRESS {count}/13 recursive proofs completed", flush=True)
                            for _, _ in ready.select(timeout=0.25):
                                data = parent.recv(16384)
                                if not data:
                                    raise RuntimeError("Metal worker closed before reporting completion")
                                frame += data
                            if len(frame) > 16384:
                                raise RuntimeError("oversize worker response")
                        response = json.loads(frame)
                    if response.get("status") != "PROVED" or response.get("sequence") != 0:
                        raise RuntimeError("Metal worker did not complete the requested job")
                    parent.setblocking(True)
                    parent.sendall(b'{"stop":true}\n')
                    owned.wait(worker)
                text = (job / "worker.log").read_text()
                screen.verify_tuning(text, env)
                nodes = screen.re.findall(r"grouped_node_complete artifact=(\S+) resumed=(\S+)", text)
                if nodes != [(n, "false") for n in NODES]:
                    raise RuntimeError("job did not produce exactly the thirteen fresh planned proofs")
                bundle = out / "root-only"
                bundle.mkdir()
                for name in (*KEYS, "node.4.0"):
                    shutil.copy2(job / name, bundle / name)
                print("PROGRESS 13/13 proofs complete; independent CPU root audit running", flush=True)
                with (job / "audit.log").open("w") as log:
                    owned.wait(owned.spawn([binaries["audit"], "root-twelve", bundle, *external], cpu_env, log))
                audit = (job / "audit.log").read_text()
                if "grouped_artifact_audit=PASS kind=level4-count12-padded16" not in audit:
                    raise RuntimeError("twelve CPU audit marker missing")
                seconds = time.monotonic() - started
                report.update(status="VERIFIED", seconds=seconds, proof_seconds=response["seconds"],
                    completed_recursive_proofs=13, jobs_per_hour=3600 / seconds,
                    tx_equivalents_per_hour=12 * 3600 / seconds, aggregate_peak_rss_bytes=owned.peak,
                    worker_peak_rss_bytes=owned.worker_peaks.get(str(worker.pid), 0),
                    swap_growth_bytes=max(0, owned.swap_peak - owned.before["swap_used_bytes"]),
                    memory_pressure_incident=owned.pressure_incident,
                    root_bytes=(bundle / "node.4.0").stat().st_size,
                    root_sha256=digest(bundle / "node.4.0"), audit_log=audit,
                    worker_log_sha256=digest(job / "worker.log"), audit_log_sha256=digest(job / "audit.log"),
                    gpu_telemetry=[line for line in text.splitlines() if line.startswith(("metal_checkpoint ", "metal_tuning ", "metal_worker_memory "))])
                report["valid_comparison"] = not report["swap_growth_bytes"] and not report["memory_pressure_incident"]
            finally:
                report.setdefault("aggregate_peak_rss_bytes", owned.peak)
                report.setdefault("swap_growth_bytes", max(0, owned.swap_peak-owned.before["swap_used_bytes"]))
                report.setdefault("memory_pressure_incident", owned.pressure_incident)
                owned.close()
                for sock in (parent, child):
                    if sock is not None:
                        sock.close()
        for name, sha in build["source_hashes"].items():
            if digest(ROOT / name) != sha:
                raise RuntimeError("proof sources changed during the benchmark")
        report["resources_sha256"] = digest(out / "resources.jsonl")
        print(f'VERIFIED {report["seconds"]:.3f}s; {report["tx_equivalents_per_hour"]:.2f} tx-equivalents/hour; peak RSS {report["aggregate_peak_rss_bytes"]/screen.GIB:.2f} GiB', flush=True)
    except BaseException as error:
        report.update(status="FAILED", failure=str(error), elapsed_seconds=time.monotonic()-started)
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
