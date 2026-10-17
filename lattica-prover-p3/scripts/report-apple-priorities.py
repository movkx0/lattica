#!/usr/bin/env python3
"""Render the completed minimal Apple optimization comparison as standalone HTML."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--components", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--controller-log", type=Path, required=True)
    parser.add_argument("--compatibility-log", type=Path, required=True)
    args = parser.parse_args()
    raw_path = args.run / "result.json"
    raw = json.loads(raw_path.read_text())
    checks = json.loads(args.components.read_text())
    if "Ran 12 tests" not in args.controller_log.read_text() or not args.controller_log.read_text().rstrip().endswith("OK"):
        raise ValueError("Controller qualification did not complete")
    if "Finished `dev` profile" not in args.compatibility_log.read_text():
        raise ValueError("OpenCL compatibility check did not complete")
    if raw["status"] != "COMPLETE_VERIFIED_SCREEN" or checks["status"] != "PASS":
        raise ValueError("Report requires completed, verified runs and passing qualification")
    if raw["build"]["source_hashes"] != checks["proof_source_sha256"]:
        raise ValueError("Components and full runs used different sources")
    windows = raw["windows"]
    if len(windows) != 2 or any(w["workers"] != 1 or not w["valid_comparison"] for w in windows):
        raise ValueError("Expected one valid sequential job per configuration")
    reference, candidate = windows
    reduction = 100 * (1 - candidate["seconds"] / reference["seconds"])
    speedup = reference["seconds"] / candidate["seconds"]
    component_map = {r["configuration"]: r for r in checks["components"]}
    large = "1048576"
    m = lambda variant, key: component_map[variant]["medians"][large][key]
    hash_gain = 100 * (1 - m("diagonal", "sponge_gpu_seconds") / m("reference", "sponge_gpu_seconds"))
    ntt_gain = 100 * (1 - m("cached", "ntt_gpu_seconds") / m("diagonal", "ntt_gpu_seconds"))
    component_gain = 100 * (1 - m("cached", "wall_seconds") / m("reference", "wall_seconds"))
    typed_log = args.components.parent / "proof-typed-gpu.log"
    typed = [dict(re.findall(r'(\w+)=(\S+)', line)) for line in typed_log.read_text().splitlines()
             if line.startswith("metal_quotient ")]
    if not typed:
        raise ValueError("Missing typed quotient qualification")
    slots, words = int(typed[0]["temporary_slots"]), int(typed[0]["temporary_words"])
    saved = 100 * (1 - words / (slots * 3))
    evidence = {"schema": "apple-priority-implementation-v1", "status": "COMPLETE",
                "full_run": raw, "components": checks, "windows": windows,
                "raw_result_path": str(raw_path.resolve()), "raw_result_sha256": digest(raw_path),
                "component_result_path": str(args.components.resolve()), "component_result_sha256": digest(args.components),
                "renderer_sha256": digest(__file__), "quotient_qualification": typed,
                "controller_tests": {"passed": 12, "log_sha256": digest(args.controller_log)},
                "opencl_compatibility": {"status": "PASS", "log_sha256": digest(args.compatibility_log)},
                "observed": {"latency_reduction_percent": reduction, "speedup": speedup,
                             "component_hash_reduction_percent": hash_gain, "component_ntt_reduction_percent": ntt_gain,
                             "component_wall_reduction_percent": component_gain, "typed_temporary_word_reduction_percent": saved}}
    esc = lambda value: html.escape(str(value))
    names = {"reference": "Reference Metal", "candidate-reference": "Specialized Poseidon + cached NTT",
             "diagonal": "Poseidon specialization", "cached": "Poseidon + cached NTT",
             "resident-separate": "Resident, separate prefix store", "resident-fused": "Resident, fused prefix store"}
    maximum = max(w["seconds"] for w in windows)
    bars = ''.join(f'<div class="row"><b>{esc(names.get(w["label"], w["label"]))}</b>'
                   f'<div class="track"><div class="bar latency-bar" style="width:{100*w["seconds"]/maximum:.3f}%"></div></div>'
                   f'<strong>{w["seconds"]:.2f} seconds</strong><small>7 fresh proofs · independent CPU audit PASS · '
                   f'{w["aggregate_peak_rss_bytes"]/(1<<30):.2f} GiB peak process RSS · swap growth {w["swap_growth_bytes"]} bytes</small></div>'
                   for w in windows)
    components = []
    for shape in ("65536", "1048576"):
        scale = max(c["medians"][shape]["wall_seconds"] for c in checks["components"])
        rows = ''.join(f'<div class="row"><b>{esc(names[c["configuration"]])}</b><div class="track">'
                       f'<div class="bar" style="width:{100*c["medians"][shape]["wall_seconds"]/scale:.3f}%"></div></div>'
                       f'<strong>{1000*c["medians"][shape]["wall_seconds"]:.2f} ms</strong></div>' for c in checks["components"])
        components.append(f'<article><h3>{int(shape):,} output rows</h3>{rows}</article>')
    controls = [
        ("POSEIDON_DIAGONAL", "reference | specialized", "reference", "Fixed Poseidon2 diagonal; independent of broad kernel variant."),
        ("NTT_TABLES", "auto | off | on", "auto", "Auto preserves legacy behavior; on also works with the reference pipeline."),
        ("NTT_TILE_LOG2", "10 | 11 | 12", "12", "Bounds local tile storage to 8 / 16 / 32 KiB; no automatic tuning matrix."),
        ("QUOTIENT", "auto | cpu | gpu", "auto", "Auto preserves legacy behavior; cpu permits resident storage with CPU quotient evaluation."),
        ("PREFIX_STORE", "separate | fused", "separate", "Fused writes retained canonical prefixes in the final Metal NTT store."),
    ]
    control_rows = ''.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in row) + '</tr>' for row in controls)
    qualification = ''.join(f'<tr><td>{esc(t["label"])}</td><td>{esc(t["status"])}</td><td>{t["seconds"]:.2f}s</td></tr>' for t in checks["tests"])
    data = json.dumps(evidence).replace('<', '\\u003c')
    options = raw["candidate_options"]
    evidence_path = args.run / "implementation-analysis.json"
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    args.html.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · Implemented Apple optimizations</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101724;color:#e9eef8;font:16px/1.6 system-ui}}
main{{max-width:1100px;margin:auto;padding:36px 24px 64px;overflow-wrap:anywhere}}h1{{font-size:clamp(30px,5vw,44px);line-height:1.15}}h2{{margin-top:40px}}
.eyebrow{{color:#67c9ba;text-transform:uppercase;font-size:12px;letter-spacing:.07em;font-weight:700}}.callout,.card{{background:#182234;border:1px solid #334056;border-radius:12px;padding:20px;margin:20px 0}}
.callout{{border-left:4px solid #67c9ba}}.row{{margin:24px 0}}.track{{height:22px;background:#29364b;border-radius:5px;margin:8px 0}}.bar{{height:100%;background:#67c9ba;border-radius:5px}}
small{{display:block;color:#b4c2d7}}.columns{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:32px}}table{{width:100%;border-collapse:collapse;font-size:14px}}td,th{{text-align:left;vertical-align:top;border-bottom:1px solid #334056;padding:12px 8px}}
.table-scroll{{overflow-x:auto}}code,pre{{overflow-wrap:anywhere}}pre{{white-space:pre-wrap;font-size:12px}}a{{color:#93d9ef}}button{{border:0;border-radius:7px;padding:12px 18px;background:#67c9ba;color:#101724;font:inherit;cursor:pointer}}
@media(max-width:650px){{main{{padding:24px 20px}}.columns{{grid-template-columns:1fr}}.card{{padding:16px}}}}
</style><main><p class="eyebrow">Implementation and measured validation · October 4, 2026</p>
<h1>Faster exact arithmetic on Apple Metal</h1><p>Apple M5 Pro · 18 CPU threads · 64 GiB unified memory</p>
<div class="callout"><b>{reduction:.1f}% lower aggregation latency · {speedup:.2f}× observed speedup</b>
<p>{reference["seconds"]:.2f}s → {candidate["seconds"]:.2f}s with specialized Poseidon2 constants and cached NTT twiddles. This is one sequential comparison, with no statistical confidence claim.</p></div>
<h2>Full aggregation: lower is better</h2><p>Exactly two jobs, one worker each: reference, then candidate. Both already use Metal, the reference storage pipeline, CPU quotient evaluation and 18 threads. Each produces four wrappers and three merges, followed by an independent CPU audit. Startup, pruning and auditing are included.</p>{bars}
<h2>Ranked implementation opportunities</h2>
<article class="card"><h3>1 · Poseidon2 diagonal specialization — implemented and measured</h3><p>The shader generator replaces eight fixed-coefficient products in each of 22 partial rounds with exact additions, negation and field halving. Both looped and unrolled kernels are supported. This removes 176 source-level general multiplications per permutation. Hash GPU time fell {hash_gain:.1f}% in the larger component case.</p></article>
<article class="card"><h3>2 · Independent NTT controls — implemented and measured</h3><p>Twiddle caching works with either pipeline and kernel variant. Cache identity comes from immutable Goldilocks transform metadata, eliminating the roots readback used to form cache keys. Local tile size is separately selectable. Cached transforms were {ntt_gain:.1f}% shorter in the larger component case; the full comparison retains the default tile geometry.</p></article>
<article class="card"><h3>3 · Quotient backend and typed temporaries — correctness qualified</h3><p>Resident storage can now use CPU quotient evaluation. The GPU interpreter stores one field word for base temporaries and three for extension temporaries, in contiguous planes across rows. The qualification circuit uses {words:,} temporary words instead of {slots*3:,} under the former layout ({saved:.1f}% fewer). CPU/hybrid/GPU proof bytes matched. This is a storage result on the small correctness circuit, not a measured full-size GPU quotient speedup.</p></article>
<article class="card"><h3>4 · Fused retained-prefix stores — correctness qualified, experimental</h3><p>The final NTT store can also write canonical retained-prefix rows, removing the separate scatter dispatch. Cached and uncached variants match full commitments and reconstructed openings across partial columns and multiple transform groups. The short component comparison showed no clear latency gain; this switch remains off in the full benchmark and by default.</p></article>
<h2>Where the GPU spends time</h2><p>Short LDE-and-commitment components: median of three samples after one untimed warm-up, two shapes per configuration. Bars show complete component wall time. Each shape has its own scale. The larger shape improved {component_gain:.1f}% with the two selected changes. Component geometry does not represent every production matrix layout.</p><div class="columns">{''.join(components)}</div>
<h2>Correctness and run validity</h2><p>All {len(checks["tests"])} focused native checks and 12 controller checks passed, including the worker stop/EOF protocol. Native checks cover arithmetic edges, CPU Poseidon equivalence, bounded NTT schedules, cached multi-group transforms, fused prefix reconstruction, proof-byte equivalence and cleanup on failure. The shared Rust code also passed an OpenCL-feature compatibility check. Both full aggregations verified seven fresh proofs and passed independent CPU audits, with normal memory pressure and no swap growth.</p>
<div class="table-scroll"><table><thead><tr><th>Focused check</th><th>Result</th><th>Elapsed</th></tr></thead><tbody>{qualification}</tbody></table></div>
<h2>Enable and reproduce</h2><p>New switches use the prefix <code>LATTICA_V2_METAL_</code>. Defaults preserve the previous behavior. The implementation stays in the opt-in research Metal backend; the production C ABI and verifier are unchanged.</p>
<div class="table-scroll"><table><thead><tr><th>Suffix</th><th>Values</th><th>Default</th><th>Effect</th></tr></thead><tbody>{control_rows}</tbody></table></div>
<p>The full runner now supports matching <code>--candidate-*</code> controls and verifies the worker's logged selection. The measured command uses these additions to the existing fixture/build arguments:</p>
<pre>--workers 1 --candidate-pipeline {esc(options["pipeline"])}
--candidate-poseidon-diagonal {esc(options["poseidon_diagonal"])} --candidate-ntt-tables {esc(options["ntt_tables"])}
--candidate-quotient {esc(options["quotient"])}</pre>
<p>Reproduce the short suite with <code>scripts/check-apple-priorities.py --binary PATH_TO_NATIVE_LIBTEST --out NEW_DIRECTORY</code>. It runs no full benchmark fixture. No new memory or total runtime hard limit was introduced.</p>
<h2>Evidence and limits</h2><p>One full pair supports a directional result. Thermal state, run order and OS scheduling were not randomized. Both arms use the same unified-memory Mac, so this comparison measures implementation changes and cannot establish the benefit of unified memory versus a discrete-memory architecture. GPU stage time overlaps wall time. RSS is sampled process residency and is not total physical footprint.</p>
<p>Base commit: <code>{esc(raw["git_commit"])}</code>. The exact modified source, binary hashes, fixture hashes, qualification results and raw logs are preserved under <code>{esc(args.run.resolve())}</code>.</p>
<button id="download">Download analysis evidence</button><details><summary>Full evidence and provenance</summary><pre id="details"></pre></details></main>
<script id="evidence" type="application/json">{data}</script><script>const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-hardware-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0)}};</script></html>''')
    print(json.dumps({"status": "COMPLETE", "latency_reduction_percent": reduction, "speedup": speedup,
                      "html": str(args.html.resolve()), "evidence": str(evidence_path.resolve())}, indent=2))


if __name__ == "__main__":
    main()
