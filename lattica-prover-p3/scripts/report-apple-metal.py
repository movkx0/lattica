#!/usr/bin/env python3
"""Render an offline HTML benchmark report with embedded Matplotlib SVGs."""
import argparse
import base64
import hashlib
import html
import io
import json
from pathlib import Path
import re
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLORS = {"cpu": "#5276ce", "shared": "#168777", "copy": "#d39237", "linux": "#8290a5"}
LEVELS = {"baseline": "Baseline", "readback": "Parallel readback", "fusion": "CPU quotient fusion", "quotient": "GPU quotient transforms"}

def median(values):
    return statistics.median(values)

def graph(rows, mobile=False, relative=False):
    width = 4.8 if mobile else 10.8
    fig, ax = plt.subplots(figsize=(width, (.60 if mobile else .49) * len(rows) + 1.25))
    fig.patch.set_facecolor("#ffffff")
    values = [r[1] for r in rows]
    maximum = max(max(v) for v in values)
    for index, (label, values, kind) in enumerate(rows):
        center = median(values)
        ax.barh(index, center, color=COLORS[kind], height=.52, zorder=2)
        ax.plot([min(values), max(values)], [index, index], color="#213044", linewidth=1.1, zorder=3)
        for repeat, value in enumerate(values):
            ax.scatter(value, index + (repeat - 1) * .08, s=17, color="white", edgecolors="#213044", linewidths=.7, zorder=4)
        ax.text(max(values) + maximum * .025, index, f"{center:.3f}×" if relative else f"{center:.1f} s",
                va="center", fontsize=11 if mobile else 10, color="#213044")
    ax.set_yticks(range(len(rows)), [row[0] for row in rows], fontsize=12 if mobile else 11)
    ax.invert_yaxis()
    ax.set_xlim(0, maximum * 1.27)
    ax.set_xlabel("Time relative to Apple CPU at the same thread count · lower is faster" if relative else "Seconds · lower is faster", fontsize=12 if mobile else 11, labelpad=12)
    if relative and mobile:
        ax.set_xlabel("Relative to Apple CPU at the same threads\nLower is faster", fontsize=11, labelpad=12)
    ax.grid(axis="x", color="#e5eaf0", linewidth=.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0, pad=9)
    ax.tick_params(axis="x", labelsize=9, colors="#536276")
    for spine in ax.spines.values(): spine.set_visible(False)
    fig.tight_layout(pad=.9)
    buffer = io.StringIO()
    fig.savefig(buffer, format="svg", metadata={"Date": None})
    plt.close(fig)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue().encode()).decode()

def picture(rows, caption, relative=False):
    desktop = graph(rows, relative=relative)
    mobile = graph(rows, mobile=True, relative=relative)
    return f'<picture><source media="(max-width: 600px)" srcset="{mobile}"><img src="{desktop}" alt="{html.escape(caption)}"></picture>'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--additional-results", type=Path, action="append", default=[])
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    sources = [(path, json.loads(path.read_text())) for path in [args.results, *args.additional_results]]
    primary = sources[0][1]
    if primary["status"] != "COMPLETE_VERIFIED_COMPARISON":
        raise SystemExit("final report requires the completed, CPU-verified comparison")
    primary_sha = hashlib.sha256(args.results.read_bytes()).hexdigest()
    for path, series in sources:
        if path != args.results:
            if series["status"] != "COMPLETE_VERIFIED_EXTENSION" or series["reused_pilots"]["reference_sha256"] != primary_sha:
                raise SystemExit("additional series does not reference this completed comparison")
            for key in ("binary_sha256", "fixture_sha256", "external", "memory_policy", "timing_boundary", "hardware", "platform"):
                if series[key] != primary[key]: raise SystemExit("extension mismatch: " + key)
            proof_sources = lambda data: {name: sha for name, sha in data["source_hashes"].items() if not name.startswith("scripts/")}
            if proof_sources(series) != proof_sources(primary): raise SystemExit("extension proof sources differ")
        if hashlib.sha256(path.with_name("source.tar.gz").read_bytes()).hexdigest() != series["source_archive_sha256"]:
            raise SystemExit("source archive digest mismatch: " + str(path))
        for trial in series["trials"]:
            root = path.parent / (trial["label"] + "-root-only") / "node.3.0"
            if root.stat().st_size != trial["root_bytes"] or hashlib.sha256(root.read_bytes()).hexdigest() != trial["root_sha256"]:
                raise SystemExit("verified root digest mismatch: " + trial["label"])
    result = dict(primary)
    for key in ("trials", "stages", "observations", "schedule"):
        result[key] = [item for _, series in sources for item in series[key]]
    result["source_series"] = [{"path":str(path), "result_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
        "source_archive_sha256":series["source_archive_sha256"], "controller_sha256":series["controller_sha256"]} for path, series in sources]
    trials = [t for t in result["trials"] if t["phase"] == "measured"]
    pilots = [t for t in result["trials"] if t["phase"] == "pilot"]
    if len(pilots) != 2 or not all(t["verified"] for t in result["trials"]):
        raise SystemExit("incomplete trial/audit matrix")
    linux = json.loads(args.results.with_name("linux-reference.json").read_text())
    validation = json.loads(args.validation.read_text())
    qualification = json.loads(args.results.with_name("hardware-qualification.json").read_text())
    if qualification["status"] != "PASS" or not all(t["passed"] for t in qualification["tests"]):
        raise SystemExit("hardware qualification did not pass")
    if len(qualification["tests"]) != validation["metal_hardware"]["passed"]:
        raise SystemExit("qualification count differs from validation record")
    groups = {}
    for trial in trials:
        groups.setdefault((trial["backend"], trial["threads"], trial["level"]), []).append(trial)
    pipeline_threads = sorted({t["threads"] for t in trials if t["level"] != "baseline"})
    expected = {(mode, count, "baseline") for count in (8, 16, 18, 24) for mode in ("cpu", "shared", "copy")}
    expected |= {(mode, count, level) for count in pipeline_threads for mode in ("shared", "copy") for level in ("readback", "fusion", "quotient")}
    if 24 not in pipeline_threads or set(groups) != expected or any(len(group) != 3 or {t["repeat"] for t in group} != {1,2,3} for group in groups.values()):
        raise SystemExit("expected complete CPU/shared/copy baselines at 8/16/18/24 threads and three repetitions per configuration")
    main_rows, relative_rows = [], []
    table = []
    for threads in (8, 16, 18, 24):
        cpu_reference = median(t["recursive_seconds"] for t in groups[("cpu", threads, "baseline")])
        for mode, label in [("cpu", "Apple CPU"), ("shared", "Metal shared"), ("copy", "Metal copy"), ("linux", "Linux RTX 5080†")]:
            if mode == "linux":
                if f"ram{threads}" not in linux["arms"]: continue
                values = [r["recursive_seconds"] for r in linux["arms"][f"ram{threads}"]["runs"]]
            else:
                values = [t["recursive_seconds"] for t in groups[(mode, threads, "baseline")]]
            name = f"{label} · {threads}t"
            main_rows.append((name, values, mode))
            relative_rows.append((name, [v/cpu_reference for v in values], mode))
            table.append([name, *[f"{v:.3f}" for v in values], f"{median(values):.3f}"])
    pipeline_figures = []
    pipeline_table = []
    for count in pipeline_threads:
        pipeline_rows = []
        for level, label in LEVELS.items():
            for mode in ("shared", "copy"):
                values = [t["recursive_seconds"] for t in groups[(mode,count,level)]]
                pipeline_rows.append((f"{label}\nMetal {mode}", values, mode))
                pipeline_table.append([f"{count}t · {label} · {mode}", *[f"{v:.3f}" for v in values], f"{median(values):.3f}"])
        pipeline_figures.append(f'<div class="pipeline-case" data-threads="{count}"><h3>{count} threads</h3>' + picture(pipeline_rows, f"{count}-thread Metal timings with readback and quotient optimizations enabled in sequence.") + "</div>")
    shared = median(t["recursive_seconds"] for t in groups[("shared",24,"baseline")])
    copy = median(t["recursive_seconds"] for t in groups[("copy",24,"baseline")])
    percent = (copy-shared)/copy*100
    direction = "less" if percent >= 0 else "more"
    headline = f"Shared mode took {abs(percent):.1f}% {direction} time at 24 threads"
    evidence = {"results": result, "series": [series for _, series in sources], "linux_reference": linux, "validation": validation,
                "hardware_qualification": qualification, "derived_worker_memory": []}
    for stage in result["stages"]:
        path = Path(stage["log"])
        if stage["status"] != "PASS" or hashlib.sha256(path.read_bytes()).hexdigest() != stage["log_sha256"]:
            raise SystemExit("stage status or log digest mismatch: " + str(path))
        if stage.get("gpu"):
            matches = re.findall(r"metal_worker_memory peak_rss_bytes=(\d+) peak_footprint_bytes=(\d+)", path.read_text())
            if len(matches) != 1: raise SystemExit("missing worker memory accounting")
            evidence["derived_worker_memory"].append({"stage":stage["label"], "phase":stage["configuration"]["phase"], "peak_rss_bytes":int(matches[0][0]), "peak_footprint_bytes":int(matches[0][1])})
    rss = max(t["peak_rss_bytes"] for t in trials)/(1<<30)
    mapped = max(t["peak_mapped_bytes"] for t in trials)/(1<<30)
    footprint = max(r["peak_footprint_bytes"] for r in evidence["derived_worker_memory"] if r["phase"] == "measured")/(1<<30)
    metal_peak = max(int(t[stage]["managed_peak_bytes"]) for t in trials for stage in ("pairs_metal","merges_metal") if t[stage])/(1<<30)
    data = json.dumps(evidence, separators=(",", ":")).replace("<", "\\u003c")
    rows_html = "".join("<tr>"+"".join(f"<td>{html.escape(cell)}</td>" for cell in row)+"</tr>" for row in table)
    pipeline_html = "".join("<tr>"+"".join(f"<td>{html.escape(cell)}</td>" for cell in row)+"</tr>" for row in pipeline_table)
    source = "<br>".join(html.escape(item["source_archive_sha256"]) for item in result["source_series"])
    build = html.escape(result["build"]["rustc"].splitlines()[0])
    substitutions = {
        "@@HEADLINE@@": headline, "@@SHARED@@": f"{shared:.3f}", "@@COPY@@": f"{copy:.3f}",
        "@@MAIN@@": picture(main_rows,"Median proof time with individual trial markers. Exact values are in the results table."),
        "@@RELATIVE@@": picture(relative_rows,"Proof time relative to the Apple CPU at each thread setting.",relative=True),
        "@@PIPELINE@@": "".join(pipeline_figures),
        "@@PIPELINE_THREADS@@": " and ".join(map(str, pipeline_threads)),
        "@@PIPELINE_ARGS@@": " ".join(map(str, pipeline_threads)),
        "@@PILOT_LEVEL@@": pilots[0]["level"],
        "@@RESTART_NOTE@@": html.escape(validation.get("full_size_restart", {}).get("summary", "")),
        "@@TRIAL_COUNT@@": str(len(trials)), "@@PROOF_COUNT@@": str(len(trials) * 7),
        "@@EXTENSION_NOTE@@": "The 18-thread measurements were requested after the original schedule was frozen and ran afterward as a separate series, using the same preserved binaries and fixtures. The original two verified pilots were reused; every added measurement produced fresh proofs." if len(sources) > 1 else "",
        "@@ROWS@@": rows_html, "@@DATA@@": data, "@@RSS@@": f"{rss:.2f}", "@@MAPPED@@": f"{mapped:.2f}",
        "@@FOOTPRINT@@": f"{footprint:.2f}", "@@METAL@@": f"{metal_peak:.2f}", "@@SOURCE@@": source,
        "@@BUILD@@": build, "@@BASE@@": result["git_base"], "@@HARDWARE@@": html.escape(result["hardware"]),
        "@@PIPELINE_ROWS@@": pipeline_html,
        "@@HARDWARE_CHECKS@@": str(validation["metal_hardware"]["passed"]),
        "@@IMPLEMENTATION@@": validation["implementation_commit"],
        "@@SWAP@@": html.escape(result["observations"][0]["swap"]["output"].strip() + "\n" + result["observations"][-1]["swap"]["output"].strip()),
        "@@DATES@@": html.escape(result["observations"][0]["utc"] + " to " + result["observations"][-1]["utc"]),
    }
    document = TEMPLATE
    for key, value in substitutions.items(): document = document.replace(key, value)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(document)
    print(args.out, args.out.stat().st_size, "bytes")

TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apple Silicon Metal benchmark · Lattica</title>
<style>
:root{color-scheme:light;--ink:#213044;--muted:#536276;--line:#dce5ec;--teal:#168777}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--ink);font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1160px;margin:auto;padding:48px 28px}header{padding-bottom:24px}.eyebrow{font-size:12px;letter-spacing:.16em;font-weight:750;color:var(--teal);text-transform:uppercase}h1{font-size:clamp(30px,4.5vw,49px);line-height:1.14;letter-spacing:-.035em;margin:12px 0 18px}h2{font-size:24px;line-height:1.3;margin:0 0 12px}h3{font-size:17px;margin:24px 0 8px}p{margin:10px 0;color:var(--muted)}.intro{font-size:19px;max-width:880px}.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:12px;margin-right:6px;background:#fff}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0 28px}.card,section{background:white;border:1px solid var(--line);border-radius:15px}.card{padding:20px}.number{font-size:32px;line-height:1.2;font-weight:750;letter-spacing:-.03em}.caption{font-size:13px;color:var(--muted);margin-top:6px}section{padding:28px;margin:20px 0}section picture,section img{display:block;width:100%;height:auto}.control{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}select,button{font:inherit;border:1px solid #b8c6d2;border-radius:8px;background:#fff;color:var(--ink);padding:9px 13px}button{background:var(--ink);color:white;cursor:pointer}.legend{display:flex;flex-wrap:wrap;gap:16px;margin:15px 0;font-size:13px}.key:before{content:"";display:inline-block;width:11px;height:11px;background:var(--color);border-radius:3px;margin-right:6px}.note{font-size:13px}.callout{background:#edf7f4;border-left:3px solid var(--teal);padding:14px 18px;border-radius:0 8px 8px 0;color:var(--ink)}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:right;padding:11px 12px;border-bottom:1px solid var(--line);white-space:nowrap}th:first-child,td:first-child{text-align:left}th{color:var(--muted);font-weight:650}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fa;padding:16px;border-radius:9px;font-size:12px;line-height:1.6}code{overflow-wrap:anywhere}details{border-top:1px solid var(--line);padding-top:16px;margin-top:18px}summary{cursor:pointer;font-weight:650}.fineprint{font-size:12px;color:var(--muted)}[hidden]{display:none!important}a{color:#17625b}.method-list{padding-left:22px}.method-list li{margin:10px 0}footer{padding:18px 2px;font-size:12px;color:var(--muted)}
@media(max-width:600px){main{padding:28px 12px}.cards{grid-template-columns:1fr;gap:10px}.card{padding:16px;display:flex;align-items:center;justify-content:space-between;gap:12px}.card .caption{max-width:160px;text-align:right}section{padding:20px 12px}h2{font-size:21px}.intro{font-size:16px}.number{font-size:29px}.control select{max-width:100%}th,td{padding:9px 8px}pre{font-size:11px}}
@media print{body{background:white}main{padding:0;max-width:none}section,.card{break-inside:avoid}button,select{display:none}.cards{grid-template-columns:repeat(3,1fr)}details{display:block}h1{font-size:32px}}
</style></head><body><main>
<header><div class="eyebrow">Lattica · Apple Silicon research benchmark</div><h1>@@HEADLINE@@</h1>
<p class="intro">Native Metal proving on an Apple M5 Pro. The controlled comparison uses the same GPU and kernels with shared buffers or explicit copies into private GPU buffers.</p>
<p class="note">Measurement window: @@DATES@@ (UTC).</p>
<p><span class="tag">@@TRIAL_COUNT@@ measured trials</span><span class="tag">@@PROOF_COUNT@@ fresh recursive proofs</span><span class="tag">Every root verified on CPU</span></p></header>
<div class="cards"><div class="card"><div class="number">@@SHARED@@ s</div><div class="caption">Metal shared · baseline<br>24-thread median</div></div><div class="card"><div class="number">@@COPY@@ s</div><div class="caption">Metal copy · baseline<br>24-thread median</div></div><div class="card"><div class="number">3 runs</div><div class="caption">Per configuration<br>Individual trials shown</div></div></div>
<section><div class="control"><h2>Full eight-wallet subtree</h2><label for="chart-mode">View <select id="chart-mode"><option value="seconds">Elapsed seconds</option><option value="relative">Relative to Apple CPU</option></select></label></div>
<p>Four paired wrappers and three merges. Bars show medians; dots show all three trials and the line spans their range. All optional readback and quotient optimizations are off in this comparison.</p>
<div class="legend"><span class="key" style="--color:#5276ce">Apple CPU</span><span class="key" style="--color:#168777">Metal shared</span><span class="key" style="--color:#d39237">Metal copy</span><span class="key" style="--color:#8290a5">Historical Linux GPU†</span></div>
<div id="seconds-chart">@@MAIN@@</div><div id="relative-chart" hidden>@@RELATIVE@@</div>
<p class="note">† Linux: Core Ultra 9 275HX + RTX 5080 laptop, OpenCL, October 2, 2026. It is a different machine and an earlier source snapshot. The newer Linux commit contains component tests, with full-size timings still pending; these bars remain the archived results. No 18-thread Linux measurement is available.</p>
<p class="callout">The shared/copy pair measures the effect of avoiding explicit GPU-buffer transfers in this implementation. CPU marshaling, host matrix materialization and decoding still occur. Private versus shared storage may also affect driver behavior. This does not emulate PCIe or isolate every benefit of unified memory.</p>
<details><summary>Exact baseline timings (seconds)</summary><div class="table-wrap"><table><thead><tr><th>Configuration</th><th>Trial 1</th><th>Trial 2</th><th>Trial 3</th><th>Median</th></tr></thead><tbody>@@ROWS@@</tbody></table></div></details></section>
<section><h2>Readback and quotient optimizations</h2><p>These runs use @@PIPELINE_THREADS@@ Rayon threads. Shared and copy modes have identical settings within each pair. Constraint evaluation remains on the CPU.</p>@@PIPELINE@@
<details><summary>Exact pipeline timings (seconds)</summary><div class="table-wrap"><table><thead><tr><th>Configuration</th><th>Trial 1</th><th>Trial 2</th><th>Trial 3</th><th>Median</th></tr></thead><tbody>@@PIPELINE_ROWS@@</tbody></table></div></details>
<div class="table-wrap"><table><thead><tr><th>Configuration</th><th>Parallel decode</th><th>CPU fusion</th><th>GPU quotient transforms</th></tr></thead><tbody><tr><td>Baseline</td><td>Off</td><td>Off</td><td>Off</td></tr><tr><td>Parallel readback</td><td>On</td><td>Off</td><td>Off</td></tr><tr><td>CPU quotient fusion</td><td>On</td><td>On</td><td>Off</td></tr><tr><td>GPU quotient transforms</td><td>On</td><td>On</td><td>On</td></tr></tbody></table></div><p class="note">These are research comparisons with three repetitions per configuration. No acceleration default or production policy is enabled by these results.</p></section>
<section><h2>Memory observations</h2><p>Maxima across the @@TRIAL_COUNT@@ measured trials; pilots are excluded from these figures.</p><div class="table-wrap"><table><thead><tr><th>Metric</th><th>Maximum observed</th><th>Meaning</th></tr></thead><tbody><tr><td>Worker RSS</td><td>@@RSS@@ GiB</td><td>OS process high-water mark</td></tr><tr><td>Metal worker physical footprint</td><td>@@FOOTPRINT@@ GiB</td><td>Sampled every 500 ms</td></tr><tr><td>Mapped scratch</td><td>@@MAPPED@@ GiB</td><td>Included in process memory</td></tr><tr><td>Managed Metal buffers</td><td>@@METAL@@ GiB</td><td>Logical live allocation peak</td></tr></tbody></table></div><p class="callout">These figures overlap and must not be added. Apple GPU and CPU allocations share physical memory; driver allocation counts are recorded separately in the evidence.</p><p>Limits: 34 GiB mapped scratch, 8 GiB managed Metal buffers, 44 GiB sampled worker RSS and two hours per stage. macOS swap, power and thermal observations were recorded before and after each trial. The watchdog does not provide Linux cgroup isolation or a no-swap guarantee.</p><details><summary>System-wide swap at the beginning and end</summary><pre>@@SWAP@@</pre><p class="note">These are system-wide observations, not per-worker swap measurements. The first line is before the pilots; the second is after the final trial.</p></details></section>
<section><h2>Method and verification</h2><ul class="method-list"><li>The same eight public wallet proofs, registry keys, ordered statement and geometry were used for all Apple trials. Registry hashes match the archived Linux evidence. Linux wallet-proof byte identity was not established.</li><li>Two complete pilots passed before measurement. Each measured trial produced seven fresh proofs without checkpoint reuse, pruned inner artifacts and passed the CPU-only root auditor, including its corruption and public-input binding checks.</li><li>Time is the sum of the wrapper and merge workers’ reported elapsed times, including Metal initialization and shader compilation. Compiler caches had been exercised during qualification. Fixture preparation, controller overhead and audits are reported separately.</li><li>CPU/shared/copy trials ran sequentially at 8, 16, 18 and 24 Rayon threads, with order reversed in the second repetition. Additional @@PIPELINE_THREADS@@-thread pairs compare readback, CPU fusion and GPU quotient transforms. The M5 Pro has 18 logical CPUs; 24 is a software thread count. @@EXTENSION_NOTE@@</li><li>Metal arithmetic, NTT/LDE, salted hashing, retained paths, compact openings, quotient masks and proof equivalence passed @@HARDWARE_CHECKS@@ hardware checks across both modes. CPU quotient and scratch tests, worker-policy tests, allocation checks, forced timeouts and lease recovery also passed. The OpenCL configuration compiled; Linux GPU execution was unavailable on this system.</li><li>This is an eight-wallet, level-three research subtree. It does not qualify a full 64-transaction production block. Proof parameters, formats and the CPU verifier were preserved.</li></ul>
<p class="note">@@RESTART_NOTE@@</p><details><summary>Build and reproducibility</summary><p>@@BUILD@@ · native ARM64 · <code>-C target-cpu=native</code> · release thin LTO.</p><pre>@@HARDWARE@@</pre><p>Git base: <code>@@BASE@@</code><br>Implementation commit: <code>@@IMPLEMENTATION@@</code><br>Exact modified source archive SHA-256 values: <code>@@SOURCE@@</code></p><pre># From lattica-prover-p3, with Rust/Cargo on PATH:
python3 -B scripts/build-apple-metal.py

# Metal worker feature set:
RUSTFLAGS='-C target-cpu=native' cargo build --release --locked --no-default-features \
  --features block-v2-wide-lanes,stream,gpu-metal \
  --bin block-v2-metal-grouped-probe

# Memory mode (same kernels):
LATTICA_V2_METAL_MEMORY=shared  # or copy

# Build the hardware test executable (Cargo prints its path):
RUSTFLAGS='-C target-cpu=native' cargo test --release --locked \
  --no-default-features --features block-v2-wide-lanes,stream,gpu-metal \
  --lib --no-run
python3 -B scripts/test-metal-backend.py \
  --binary PATH_PRINTED_BY_CARGO --out target/metal-qualification

# Run two pilots, then the complete @@TRIAL_COUNT@@-trial matrix:
python3 -B scripts/bench-apple-metal.py --full-matrix \
  --out PATH_TO_NEW_RESULTS_DIRECTORY \
  --pilot-level @@PILOT_LEVEL@@ \
  --threads 8 16 18 24 \
  --pipeline-threads @@PIPELINE_ARGS@@ \
  --fixture PATH_TO_PUBLIC_EIGHT_WALLET_FIXTURE \
  --linux PATH_TO_ARCHIVED_LINUX_RESULT_JSON \
  --qualification target/metal-qualification/result.json</pre><p class="note">Replace the uppercase path placeholders before running. The fixture contains <code>height</code>, <code>key.1</code> through <code>key.3</code>, and <code>wallet.0</code> through <code>wallet.7</code>. The controller validates their hashes and public statement before proving. Run one measurement series at a time with stable power and the machine otherwise idle.</p><p class="note">Metal shaders compile through the system runtime. A standalone <code>metal</code> command-line compiler is not required. The benchmark JSON includes build commands, binary and fixture hashes, raw timings, telemetry, validation records and source provenance.</p></details>
<button id="download-evidence" type="button">Download benchmark evidence JSON</button><p id="download-status" class="fineprint" aria-live="polite">All charts and evidence are embedded. This file works offline.</p></section>
<footer>Measured results, including unfavorable or overlapping comparisons, are reported without a claim of statistical significance. Three trials describe the observed run variation.</footer>
</main><script type="application/json" id="evidence">@@DATA@@</script><script>
document.getElementById('chart-mode').addEventListener('change',function(){document.getElementById('seconds-chart').hidden=this.value!=='seconds';document.getElementById('relative-chart').hidden=this.value!=='relative';});
document.getElementById('download-evidence').addEventListener('click',function(){const text=document.getElementById('evidence').textContent;const blob=new Blob([JSON.stringify(JSON.parse(text),null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='lattica-apple-metal-benchmark-evidence.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);document.getElementById('download-status').textContent='Evidence downloaded: timings, verification records, configuration and provenance.';});
</script></body></html>'''

if __name__ == "__main__":
    main()
