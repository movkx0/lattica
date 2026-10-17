#!/usr/bin/env python3
"""Two fresh eight-transaction jobs: optimized baseline versus direct readback."""
import argparse
import html
import importlib.util
import json
from pathlib import Path
import platform
import re
import shutil
import signal
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apple_screen", ROOT / "scripts/bench-apple-throughput.py")
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)
OPTIONS = dict(pipeline="reference", poseidon_diagonal="specialized", ntt_tables="on",
               ntt_tile_log2="12", quotient="cpu", prefix_store="separate",
               direct_readback="0", denominator_cache="0", query_gather="0")


def render(report, path):
    windows = report["windows"]
    scale = max((w["seconds"] for w in windows), default=1)
    bars = "".join(f'<article><h2>{html.escape(w["label"])}</h2><div class="track"><div class="bar" '
        f'style="width:{100*w["seconds"]/scale:.2f}%"></div></div><p><b>{w["seconds"]:.2f} seconds</b> · '
        f'{8*w["verified_jobs_per_hour"]:.1f} transaction equivalents/hour · '
        f'{w["aggregate_peak_rss_bytes"]/screen.GIB:.2f} GiB peak RSS</p>'
        f'<p>CPU audit passed. Swap growth: {w["swap_growth_bytes"]/(1<<20):.2f} MiB. '
        f'Clean resource comparison: {w["valid_comparison"]}.</p></article>' for w in windows)
    change = report.get("latency_reduction_percent")
    finding = f"Observed latency reduction: {change:.2f}%." if change is not None else "Comparison pending."
    retention = ("Both arms retain compact prefixes and gather reconstructed query rows on GPU."
                 if report.get("compact_data") else "Both arms retain full expanded host matrices.")
    path.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · Apple single-job latency</title><style>body{{font:17px system-ui;color:#162a3b;background:#eef3f7;margin:0}}
main{{max-width:980px;margin:auto;padding:36px 22px}}h1{{font-size:2.2rem}}h2{{font-size:1.2rem}}article{{background:white;padding:20px 24px;margin:20px 0;border-radius:12px}}
.track{{height:26px;background:#e4ebf1;border-radius:5px;overflow:hidden}}.bar{{height:100%;background:#147d92}}p{{line-height:1.55}}code{{overflow-wrap:anywhere}}a{{color:#075b79}}</style>
<main><p>LATTICA · APPLE SILICON · 6 OCTOBER 2026</p><h1>Single-job latency</h1><p>Status: <b>{html.escape(report["status"])}</b>. {finding}</p>
<p>One worker, 18 threads, shared Metal buffers, specialized Poseidon and cached NTT tables. CPU quotient. {retention} The candidate changes only direct LDE readback. Shorter bars indicate lower latency.</p>{bars}
<p>Each arm aggregates eight pre-existing wallet proofs using seven fresh recursive proofs, then independently audits the root on CPU. Timing includes worker startup and audit; it excludes wallet-proof generation and builds. One sample per arm is a screening result, not a statistically established speedup or confirmed chain throughput.</p>
<p>No total benchmark timeout or fixed worker RSS cap. System memory pressure remains monitored. GPU allocations overlap process memory.</p>
<p>Source commit: <code>{html.escape(report["build"]["git_commit"])}</code>, plus the archived source changes. <a href="result.json">Full evidence and hashes</a>.</p>
<p>{html.escape(report.get("failure", ""))}</p></main></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--order", choices=("baseline-first", "direct-first"), default="baseline-first",
                        help="execution order; recorded to make order effects explicit")
    parser.add_argument("--compact-data", action="store_true",
                        help="retain compact prefixes and use query gather in both arms")
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("requires Apple Silicon macOS")
    build = json.loads(args.build.read_text())
    qualification = json.loads(args.qualification.read_text())
    for name, sha in build["source_hashes"].items():
        if screen.digest(ROOT / name) != sha:
            raise RuntimeError("build source changed: " + name)
    if qualification["status"] != "PASS" or qualification["proof_source_sha256"] != build["source_hashes"]:
        raise RuntimeError("qualification does not match the build")
    if args.compact_data and not {"proof-direct-gather", "proof-banded-gather"}.issubset(
            row["label"] for row in qualification["tests"] if row["status"] == "PASS"):
        raise RuntimeError("compact screen requires full proof equivalence with both readback layouts and query gather")
    linux = json.loads(args.linux.read_text())
    external = linux["benchmark_plan"]["config"]["external"]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "bin").mkdir()
    binaries = {}
    for role, name in {"cpu": "block-v2-grouped-probe", "audit": "block-v2-grouped-artifact-audit", "metal": "block-v2-metal-grouped-probe"}.items():
        entry = build["binaries"][name]
        if screen.digest(entry["path"]) != entry["sha256"]:
            raise RuntimeError("binary hash mismatch: " + name)
        binaries[role] = out / "bin" / name
        shutil.copy2(entry["path"], binaries[role])
    with tarfile.open(out / "source.tar.gz", "w:gz") as archive:
        for source in [*(ROOT / name for name in build["source_hashes"]), *sorted((ROOT / "scripts").glob("*.py"))]:
            archive.add(source, arcname=str(source.relative_to(ROOT)))
    report = {"schema": "apple-single-job-latency-v1", "status": "RUNNING", "windows": [],
              "build": build, "qualification": qualification, "external": external,
              "source_archive_sha256": screen.digest(out / "source.tar.gz"),
              "controller_sha256": screen.digest(__file__), "transactions": 8,
              "workers": 1, "threads": 18, "trials_per_arm": 1,
              "execution_order": args.order,
              "compact_data": args.compact_data,
              "benchmark_timeout_seconds": None, "worker_rss_limit_bytes": None,
              "production_ready": False, "performance_promotion": False}
    def save():
        screen.save(out / "result.json", report)
        render(report, out / "report.html")
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"controller signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    save()
    try:
        arms = [("Compact baseline" if args.compact_data else "Optimized baseline", "0"), ("Direct readback", "1")]
        if args.order == "direct-first":
            arms.reverse()
        for label, direct in arms:
            directory = out / ("baseline" if direct == "0" else "direct")
            directory.mkdir()
            (directory / "fixture").mkdir()
            for name in screen.baseline.FIXTURE_NAMES:
                source = args.fixture / name
                if source.is_symlink() or not source.is_file():
                    raise RuntimeError("invalid fixture: " + name)
                if screen.digest(source) != linux["benchmark_plan"]["source_artifacts"][name]["sha256"]:
                    raise RuntimeError("fixture differs from pinned source: " + name)
                shutil.copy2(source, directory / "fixture" / name)
            options = {**OPTIONS, "direct_readback": direct}
            if args.compact_data:
                options.update(compact_data="1", query_gather="1")
            run_args = argparse.Namespace(workers=1, kernel_variant="reference", workgroup=256,
                                          diagnostic_profile=False, **{"candidate_" + k: v for k, v in options.items()})
            print("START", label, flush=True)
            window = screen.run_window(run_args, directory, binaries, external, True)
            log = (directory / window["label"] / "job-0" / "worker.log").read_text()
            layouts = re.findall(r"bounded_lde_readback_layout layout=(\w+)", log)
            expected = "Direct" if direct == "1" else "Banded"
            if not layouts or set(layouts) != {expected}:
                raise RuntimeError("observed readback layout differs from requested layout")
            if args.compact_data and not re.search(r"bounded_gpu_query_checkpoint .*gather=true calls=[1-9]", log):
                raise RuntimeError("compact query gather did not perform work")
            window.update(label=label, options=options, observed_readback_layout=expected, readback_calls=len(layouts))
            report["windows"].append(window)
            save()
            print("VERIFIED", label, f'{window["seconds"]:.2f}s', flush=True)
        baseline = next(w for w in report["windows"] if w["options"]["direct_readback"] == "0")
        direct = next(w for w in report["windows"] if w["options"]["direct_readback"] == "1")
        report["latency_reduction_percent"] = 100 * (1 - direct["seconds"] / baseline["seconds"])
        report["valid_comparison"] = all(w["valid_comparison"] for w in report["windows"])
        for name, sha in build["source_hashes"].items():
            if screen.digest(ROOT / name) != sha:
                raise RuntimeError("proof sources changed during the screen: " + name)
        report["status"] = "COMPLETE_VERIFIED_SCREEN" if report["valid_comparison"] else "INVALID_RESOURCE_COMPARISON"
    except BaseException as error:
        report.update(status="FAILED", failure=str(error))
        report["failed_windows"] = [json.loads(path.read_text()) for path in out.glob("*/*/result.json")]
        raise
    finally:
        save()


if __name__ == "__main__":
    with screen.coordinator_lease():
        main()
