#!/usr/bin/env python3
"""Compare completed Apple headroom screens with a retained three-worker baseline."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re

GIB = 1 << 30


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def lines(path):
    with path.open(errors="replace") as source:
        yield from source


def resource_metrics(path):
    compressor = []
    free = []
    rows = 0
    for line in lines(path):
        row = json.loads(line)
        rows += 1
        vm = row.get('vm_stat')
        if not vm:
            continue
        page = int(re.search(r'page size of (\d+) bytes', vm)[1])
        compressor.append(int(re.search(r'Pages occupied by compressor:\s+(\d+)', vm)[1]) * page)
        free.append(int(re.search(r'Pages free:\s+(\d+)', vm)[1]) * page)
    if not compressor:
        raise ValueError('system memory snapshots missing: ' + str(path))
    return dict(samples=rows, vm_snapshots=len(compressor), compressor_initial_bytes=compressor[0],
                compressor_peak_bytes=max(compressor), compressor_growth_bytes=max(compressor)-compressor[0],
                minimum_free_bytes=min(free), resource_sha256=digest(path))


def analyze(path):
    report = json.loads(path.read_text())
    if report['workers'] != 3 or report['threads_per_worker'] != 6:
        raise ValueError('headroom comparison requires three six-thread workers')
    window = report.get('window', report.get('failed_window'))
    if window is None:
        raise ValueError('timing window missing')
    workers = []
    for launch in window['worker_launches']:
        log = path.parent / window['label'] / f'job-{launch["index"]}' / 'worker.log'
        memory = None
        proofs = 0
        for line in lines(log):
            if line.startswith('metal_worker_memory '):
                m = re.search(r'peak_rss_bytes=(\d+) peak_footprint_bytes=(\d+) sample_ms=(\d+)', line)
                if m is None or int(m[3]) != 500:
                    raise ValueError('incompatible memory sampling')
                memory = dict(peak_rss_bytes=int(m[1]), peak_footprint_bytes=int(m[2]), sample_ms=500)
            if line.startswith('grouped_node_complete '):
                proofs += 1
        workers.append(dict(index=launch['index'], pid=launch['pid'], recursive_proofs=proofs,
                            memory=memory, worker_log=str(log), worker_log_sha256=digest(log)))
    valid = (report['status'] == 'COMPLETE_VERIFIED_SCREEN' and report.get('valid_comparison') is True
             and len(window['jobs']) == 3 and all(job['verified'] for job in window['jobs'])
             and all(worker['recursive_proofs'] == 7 and worker['memory'] for worker in workers))
    peak = max((worker['memory']['peak_footprint_bytes'] for worker in workers if worker['memory']), default=None)
    return dict(result=str(path), result_sha256=digest(path), valid=valid,
                status=report['status'], failure=report.get('failure'), seconds=window['seconds'],
                transaction_equivalents_per_hour=window.get('transaction_equivalents_per_hour') if valid else None,
                worst_worker_peak_footprint_bytes=peak if valid else None,
                aggregate_peak_rss_bytes=window['aggregate_peak_rss_bytes'],
                swap_growth_bytes=window['swap_growth_bytes'], memory_pressure_incident=window['memory_pressure_incident'],
                workers=workers, resources=resource_metrics(path.parent/window['label']/'resources.jsonl'),
                query_scratch_bytes=report.get('query_scratch_bytes'), late_phase_slots=report.get('late_phase_slots'),
                memory_optimization_evidence=report.get('memory_optimization_evidence'),
                source_sha256=report['build']['source_hashes'], binary_sha256=report['binary_sha256'],
                fixture_sha256=report['fixture_sha256'], options=report['options'], raw=report)


def evaluate(baseline, candidate):
    floor = baseline['transaction_equivalents_per_hour'] * .9
    ceiling = baseline['worst_worker_peak_footprint_bytes'] * .85
    valid = candidate['valid']
    throughput = valid and candidate['transaction_equivalents_per_hour'] >= floor
    footprint = valid and candidate['worst_worker_peak_footprint_bytes'] <= ceiling
    compression = candidate['resources']['compressor_growth_bytes'] < baseline['resources']['compressor_growth_bytes']
    return dict(throughput_floor=floor, physical_footprint_ceiling_bytes=ceiling,
                throughput_met=throughput, footprint_met=footprint, compression_improved=compression,
                accepted=bool(throughput and footprint and compression),
                conditional_followup_eligible=bool(
                    candidate.get('failure') == 'memory pressure invalidates screen'
                    or (throughput and not (footprint and compression))))


def render(data, path):
    baseline, attempts = data['baseline'], data['attempts']
    accepted = [row for row in attempts if row['acceptance']['accepted']]
    final = attempts[-1]
    outcome = ('The candidate meets the memory and throughput screening targets.' if accepted
               else 'The candidate has not met both memory and throughput screening targets; retain the earlier configuration.')
    best = accepted[-1] if accepted else final
    measured_summary = (f"Measured throughput: <b>{best['transaction_equivalents_per_hour']:.2f}/hour</b> "
                        f"({100*(best['transaction_equivalents_per_hour']/baseline['transaction_equivalents_per_hour']-1):+.2f}% versus baseline). "
                        f"Worst-worker physical footprint: <b>{best['worst_worker_peak_footprint_bytes']/GIB:.2f} GiB</b>, "
                        f"{100*(1-best['worst_worker_peak_footprint_bytes']/baseline['worst_worker_peak_footprint_bytes']):.2f}% lower."
                        if best['valid'] else html.escape(best.get('failure') or 'No valid completed result.'))
    cleanup_note = ('All tracked workers, samplers and the controller exited; system pressure is normal and shared scratch was removed.'
                    if data.get('cleanup') and not data['cleanup']['remaining_processes'] and data['cleanup']['pressure'] == 1 and not data['cleanup']['shared_scratch_files']
                    else 'Post-run process cleanup is not yet recorded.')
    labels = [('Earlier three-worker baseline', baseline)] + [
        (f'Candidate {i+1} · ' + (f'{row["late_phase_slots"]} late-stage permits' if row['late_phase_slots'] else 'existing scheduling'), row)
        for i,row in enumerate(attempts)]
    def chart(key, divisor, suffix, lower=False):
        scale = max(row[key] / divisor for _,row in labels if row.get(key) is not None)
        parts = []
        for label,row in labels:
            value = row.get(key)
            if value is None:
                parts.append(f'<div class="row"><b>{html.escape(label)}</b><p class="warning">Unavailable: interrupted or invalid screen.</p></div>')
                continue
            value /= divisor
            parts.append(f'<div class="row"><div class="label"><b>{html.escape(label)}</b><strong>{value:.2f} {suffix}</strong></div>'
                         f'<div class="track"><div class="bar {"memory-bar" if lower else "throughput-bar"}" style="width:{value/scale*100:.3f}%"></div></div></div>')
        return ''.join(parts)
    worker_rows = ''.join(f'<tr><td>{html.escape(label)}</td><td>{w["index"]+1}</td><td>{w["recursive_proofs"]}/7</td>'
                          f'<td>{w["memory"]["peak_footprint_bytes"]/GIB:.2f} GiB</td></tr>' if w['memory'] else
                          f'<tr><td>{html.escape(label)}</td><td>{w["index"]+1}</td><td>{w["recursive_proofs"]}/7</td><td>Interrupted</td></tr>'
                          for label,row in labels for w in row['workers'])
    resource_rows = ''.join(f'<tr><td>{html.escape(label)}</td><td>{row["seconds"]:.2f}</td>'
                            f'<td>{row["resources"]["compressor_growth_bytes"]/GIB:.2f}</td>'
                            f'<td>{row["resources"]["compressor_peak_bytes"]/GIB:.2f}</td>'
                            f'<td>{row["swap_growth_bytes"]/(1<<20):.2f}</td>'
                            f'<td>{"Warning" if row["memory_pressure_incident"] else "Normal"}</td></tr>' for label,row in labels)
    acceptance_rows = ''.join(f'<tr><td>Candidate {i+1}</td><td>{"PASS" if r["acceptance"]["throughput_met"] else "NOT MET"}</td>'
                              f'<td>{"PASS" if r["acceptance"]["footprint_met"] else "NOT MET"}</td>'
                              f'<td>{"PASS" if r["acceptance"]["compression_improved"] else "NOT MET"}</td>'
                              f'<td>{"ACCEPT" if r["acceptance"]["accepted"] else "RETAIN BASELINE"}</td></tr>' for i,r in enumerate(attempts))
    encoded = json.dumps(data,separators=(',',':')).replace('<','\\u003c')
    path.write_text(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · Apple memory headroom</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6f9;color:#173147;font:16px/1.6 system-ui,-apple-system,sans-serif}}main{{max-width:1100px;margin:auto;padding:36px 24px 60px}}h1{{font-size:36px;line-height:1.2}}h2{{font-size:23px;line-height:1.3;margin-top:0}}section{{background:white;border:1px solid #dce4eb;border-radius:12px;margin:24px 0;padding:24px}}small,.note{{color:#52687a}}.status{{font-weight:700;color:#0a716d}}.warning{{color:#874407}}.row{{margin:23px 0}}.label{{display:flex;justify-content:space-between;gap:15px}}.track{{height:27px;background:#e6edf2;border-radius:4px;overflow:hidden;margin-top:8px}}.bar{{height:100%;background:#127f7a}}.memory-bar{{background:#527ba2}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;text-align:left;border-bottom:1px solid #dce4eb;white-space:nowrap}}code,pre{{overflow-wrap:anywhere;word-break:break-word}}pre{{font-size:11px;max-height:450px;overflow:auto;white-space:pre-wrap}}button{{background:#127f7a;color:white;border:0;border-radius:5px;padding:10px 14px;font:inherit;margin:10px 0 16px}}a{{color:#076967}}@media(max-width:640px){{main{{padding:22px 14px}}section{{padding:18px}}h1{{font-size:29px}}.label{{flex-direction:column;gap:0}}}}@media print{{button,details{{display:none}}section{{break-inside:avoid}}.bar{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}}}
</style></head><body><main><p>LATTICA · APPLE M5 PRO · 64 GiB UNIFIED MEMORY</p><h1>Memory headroom with three GPU workers</h1><p class="status">{outcome}</p><p>{measured_summary}</p>
<section><h2>Acceptance criteria</h2><p>Three workers use six CPU threads each. The target is at least <b>15% lower worst-worker physical footprint</b>, with at most <b>10% lower throughput</b>: at least <b>{baseline['transaction_equivalents_per_hour']*.9:.2f} transaction-equivalents/hour</b> and at most <b>{baseline['worst_worker_peak_footprint_bytes']*.85/GIB:.2f} GiB</b> for the largest worker peak. System memory-compression growth must also improve, with normal pressure and no additional swap.</p><div class="table-wrap"><table><thead><tr><th>Attempt</th><th>Throughput</th><th>Footprint</th><th>Compression</th><th>Decision</th></tr></thead><tbody>{acceptance_rows}</tbody></table></div></section>
<section><h2>Aggregation throughput</h2><p class="note">Longer bars are better. Historical baseline reused; it was not rerun. The candidate contains the new source changes. Bars start at zero on a common scale.</p>{chart('transaction_equivalents_per_hour',1,'/hour')}<p>Each valid window completes 24 transaction-equivalents, 21 fresh recursive proofs and three independent CPU root audits. Existing wallet-proof fixtures are inputs; wallet-proof generation and accepted-chain throughput are outside this measurement.</p></section>
<section><h2>Worst-worker peak physical footprint</h2><p class="note">Shorter bars are better. Both baseline and candidate use 500 ms physical-footprint sampling. These are individual worker maxima, not unique whole-system RAM usage.</p>{chart('worst_worker_peak_footprint_bytes',GIB,'GiB',True)}<div class="table-wrap"><table><thead><tr><th>Configuration</th><th>Worker</th><th>Fresh proofs</th><th>Peak physical footprint</th></tr></thead><tbody>{worker_rows}</tbody></table></div></section>
<section><h2>System memory and elapsed time</h2><div class="table-wrap"><table><thead><tr><th>Configuration</th><th>Seconds</th><th>Compressor growth GiB</th><th>Compressor peak GiB</th><th>New swap MiB</th><th>Pressure</th></tr></thead><tbody>{resource_rows}</tbody></table></div><p class="note">Compressor values describe physical RAM occupied by compressed pages. Growth is relative to each run's initial snapshot. VM snapshots are sampled every ten seconds and on pressure warnings. Existing swap may remain even when growth is zero. Shared pages appear in multiple process RSS readings; GPU bytes, RSS and physical footprint must not be added.</p></section>
<section><h2>Implementation</h2><p>Query reconstruction uses an explicit 2 GiB allowance for its transform pair and additional column tiles when needed. Completed hash/LDE scratch is retired before later allocations. Opening interpolation weights cover only the degree prefix; coset, weights and inverse denominators are released after their final consumers.</p><p>The optional late-stage permit pool covers quotient commitment through randomization, opening, FRI and query reconstruction. Admission occurs before releasing the existing early-stage permit, and release follows proof-state destruction and GPU draining. The first candidate uses the existing scheduling; a second is allowed only when the first needs further memory headroom.</p><p>All workers retain a 7 GiB managed allowance, 2 GiB LDE transform scratch, shared public preprocessing, CPU quotient, compact data, direct readback and GPU query gathering. Proof parameters, randomness and verification remain covered by focused equivalence tests. Source, fixture and binary hashes are retained in each raw result.</p></section>
<section><h2>Interpretation and evidence</h2><p>This is a minimal screening campaign with {len(attempts)} candidate window(s), not sustained production qualification or a statistical confidence estimate. No automatic four-worker retry was performed. There is no total execution timeout or fixed proving-worker RSS limit; macOS pressure monitoring remains active.</p><p>{cleanup_note}</p><p>Raw result paths, per-worker logs, source/build identities, qualification results, timing, permit waits and memory observations are embedded below. The complete raw artifacts remain in the benchmark result directory. Post-run cleanup evidence is in <a href="post-run-process-check.json">the process check</a>.</p><button id="download">Download evidence JSON</button><details><summary>Embedded evidence</summary><pre id="details"></pre></details></section>
<script id="evidence" type="application/json">{encoded}</script><script>const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-memory-headroom.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}};</script></main></body></html>''')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--attempt',type=Path,action='append',required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    if not 1 <= len(args.attempt) <= 2:
        p.error('at most two candidate windows')
    baseline=analyze(args.baseline.resolve())
    if not baseline['valid']:
        raise ValueError('baseline was not a completed verified screen')
    attempts=[]
    for path in args.attempt:
        row=analyze(path.resolve())
        if row['fixture_sha256'] != baseline['fixture_sha256'] or row['options'] != baseline['options']:
            raise ValueError('incompatible baseline fixture or pipeline')
        row['acceptance']=evaluate(baseline,row)
        attempts.append(row)
    data=dict(schema='apple-memory-headroom-v1',report_generator_sha256=digest(__file__),baseline=baseline,attempts=attempts,
              baseline_repeated=False,full_benchmark_windows=len(attempts),four_worker_retry=False)
    args.out.mkdir(parents=True,exist_ok=True)
    cleanup_path = args.out/'post-run-process-check.json'
    if cleanup_path.exists():
        data['cleanup'] = json.loads(cleanup_path.read_text())
    (args.out/'analysis.json').write_text(json.dumps(data,indent=2)+'\n')
    render(data,args.out/'report.html')
    print(json.dumps([dict(seconds=row['seconds'],rate=row['transaction_equivalents_per_hour'],
                           peak_footprint_gib=row['worst_worker_peak_footprint_bytes']/GIB if row['valid'] else None,
                           **row['acceptance']) for row in attempts],indent=2))


if __name__=='__main__':
    main()
