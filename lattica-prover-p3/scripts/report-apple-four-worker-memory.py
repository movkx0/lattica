#!/usr/bin/env python3
"""Analyze at most two four-worker memory screens; never launch benchmark work."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import shlex

GIB = 1 << 30

def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def memory_sample(line):
    # stdout profiling can interleave with stderr's formatted progress writes.
    # An incomplete progress record is diagnostic, not a zero-byte observation.
    peak = re.search(r'\bpeak_footprint_bytes=(\d+)\b', line)
    interval = re.search(r'\bsample_ms=(\d+)\b', line)
    if peak is None or interval is None or interval[1] != '500': return None
    return dict(peak=int(peak[1]), final=line.startswith('metal_worker_memory '))

def decision(row, baseline_rate):
    """Resource failure takes precedence over speed when selecting one follow-up."""
    memory_ok = (row['resources']['pressure_levels'] == [1] and row['resources']['swap_growth_bytes'] == 0
                 and row['resources']['compressor_growth_bytes'] <= 6*GIB)
    throughput_ok = row['audited'] and row['rate'] is not None and row['rate'] >= baseline_rate * .9
    accepted = row['valid'] and memory_ok and throughput_ok
    resource_failure = row['failure'] == 'memory pressure invalidates screen' or (row['audited'] and not memory_ok)
    followup = None if accepted else ('late_one' if resource_failure else ('query_two_gib' if row['valid'] and memory_ok and not throughput_ok else None))
    return dict(accepted=accepted, memory_ok=memory_ok, throughput_ok=throughput_ok, followup=followup)

def resource_summary(path):
    first = None; peak_rss = 0; peak_swap = 0; levels = set(); snapshots = []
    with path.open() as f:
        for line in f:
            row = json.loads(line)
            if first is None: first = row
            peak_rss = max(peak_rss, row['aggregate_rss']); peak_swap = max(peak_swap, row['swap_used_bytes']); levels.add(row['pressure'])
            if 'vm_stat' in row:
                vm = row['vm_stat']; page = int(re.search(r'page size of (\d+) bytes', vm)[1])
                compressor = int(re.search(r'Pages occupied by compressor:\s+(\d+)', vm)[1]) * page
                snapshots.append(dict(seconds=row['monotonic']-first['monotonic'], compressor_bytes=compressor))
    if not snapshots: raise ValueError('compressor evidence missing')
    return dict(pressure_levels=sorted(levels), swap_growth_bytes=max(0, peak_swap-first['swap_used_bytes']),
                aggregate_peak_rss_bytes=peak_rss, compressor_start_bytes=snapshots[0]['compressor_bytes'],
                compressor_peak_bytes=max(s['compressor_bytes'] for s in snapshots),
                compressor_growth_bytes=max(s['compressor_bytes'] for s in snapshots)-snapshots[0]['compressor_bytes'],
                resources_sha256=digest(path))

def audited_jobs(window, workers, expected_workers):
    """Require every distinct job and its seven proofs, including a fifth worker."""
    jobs = window.get('jobs', [])
    indices = set(range(expected_workers))
    return (len(jobs) == len(workers) == expected_workers
            and {j['index'] for j in jobs} == indices
            and {w['index'] for w in workers} == indices
            and all(j['verified'] for j in jobs)
            and all(w['proofs'] == 7 for w in workers))


def analyze(path, baseline_rate, *, expected_workers=4):
    raw = json.loads(path.read_text()); run = path.parent
    if raw['status'] == 'RUNNING': raise ValueError('attempt is still running')
    assert expected_workers in (4, 5)
    assert raw['workers'] == expected_workers and raw['threads_per_worker'] == 18 // expected_workers
    assert raw['compact_salts'] and raw['query_phase_slots'] == 1 and raw['managed_bytes_per_worker'] == 7*GIB
    window = raw.get('window') or raw.get('failed_window')
    if not window: raise ValueError('no benchmark window evidence')
    workers = []; phases = []
    for launch in window['worker_launches']:
        logfile = run/'candidate-reference'/f'job-{launch["index"]}'/'worker.log'
        worker = dict(index=launch['index'], proofs=0, incomplete_memory_progress_records=0, persisted_peak_footprint_bytes=0, exit_sample=False,
                      salt_commits=0, salt_dense_bytes_over_commits=0, salt_checkpoint_bytes_over_commits=0,
                      largest_salt_group_dense_bytes=0, largest_salt_group_checkpoint_bytes=0,
                      regenerated_rows=0, query_plans=0, query_scratch_peak_bytes=0, errors=[])
        with logfile.open() as log:
            for line in log:
                if line.startswith('grouped_node_complete '): worker['proofs'] += 1
                if line.startswith(('metal_worker_memory ', 'metal_worker_memory_progress ')):
                    sample = memory_sample(line)
                    if sample is None:
                        if line.startswith('metal_worker_memory '): raise ValueError('incomplete final memory record')
                        worker['incomplete_memory_progress_records'] += 1
                    else:
                        worker['persisted_peak_footprint_bytes'] = max(worker['persisted_peak_footprint_bytes'], sample['peak'])
                        worker['exit_sample'] |= sample['final']
                    continue
                if line.startswith(('apple_salt_storage ', 'apple_salt_queries ', 'apple_query_scratch ', 'apple_memory_admit ', 'apple_memory_release ')):
                    fields = dict(x.split('=', 1) for x in shlex.split(line)[1:] if '=' in x)
                    if line.startswith('apple_salt_storage '):
                        worker['salt_commits'] += 1
                        if int(fields['dense_bytes']) > worker['largest_salt_group_dense_bytes']:
                            worker['largest_salt_group_dense_bytes'] = int(fields['dense_bytes'])
                            worker['largest_salt_group_checkpoint_bytes'] = int(fields['checkpoint_bytes'])
                        worker['salt_dense_bytes_over_commits'] += int(fields['dense_bytes'])
                        worker['salt_checkpoint_bytes_over_commits'] += int(fields['checkpoint_bytes'])
                    elif line.startswith('apple_salt_queries '): worker['regenerated_rows'] += int(fields['regenerated_rows'])
                    elif line.startswith('apple_query_scratch '):
                        worker['query_plans'] += 1
                        worker['query_scratch_peak_bytes'] = max(worker['query_scratch_peak_bytes'], int(fields['transform_bytes']))
                        assert int(fields['allowance_bytes']) == raw['query_scratch_bytes']
                        assert int(fields['transform_bytes']) <= raw['query_scratch_bytes']
                    else: phases.append((int(fields['clock_ns']), line.startswith('apple_memory_admit '), fields))
                if re.search(r'(panicked at|^error:|allocation cap exceeded|proof.*failed)', line): worker['errors'].append(line.strip()[:400])
        worker['log_sha256'] = digest(logfile); workers.append(worker)
    limits = dict(heavy=2, late=raw['late_phase_slots'], query=1)
    active = {}; peak = dict.fromkeys(limits, 0); waits = dict.fromkeys(limits, 0); inflight = set(); max_inflight = 0
    for _, admitted, fields in sorted(phases):
        pool = fields.get('pool', 'heavy'); slot = int(fields['slot']); pid = fields['pid']; key = (pool, slot)
        assert pool in limits and 0 <= slot < limits[pool]
        if admitted:
            assert key not in active; active[key] = pid
            peak[pool] = max(peak[pool], sum(k[0] == pool for k in active))
            waits[pool] += int(fields['waited_ms'])
            if pool == 'heavy' and fields['phase'] == 'trace and quotient':
                assert pid not in inflight; inflight.add(pid); max_inflight = max(max_inflight, len(inflight))
        else:
            assert active.pop(key) == pid
            if pool == 'late': inflight.discard(pid)
    audited = audited_jobs(window, workers, expected_workers)
    valid = raw['status'] == 'COMPLETE_VERIFIED_SCREEN' and raw.get('valid_comparison', False) and audited
    if valid:
        assert not active and not inflight and all(not w['errors'] and w['exit_sample'] and w['salt_commits'] and w['query_plans'] for w in workers)
    row = dict(result_path=str(path.resolve()), result_sha256=digest(path), raw=raw, seconds=window['seconds'],
               valid=valid, audited=audited, completed_recursive_proofs=sum(w['proofs'] for w in workers),
               completed_root_audits=sum(j['verified'] for j in window.get('jobs', [])),
               failure=raw.get('failure'), rate=window.get('transaction_equivalents_per_hour') if audited else None,
               resources=resource_summary(run/'candidate-reference/resources.jsonl'), workers=workers,
               phase_maximum=peak, phase_wait_ms=waits, max_inflight_proofs=max_inflight,
               active_permits_at_stop=[dict(pool=k[0], slot=k[1], pid=v) for k,v in active.items()])
    row.update(decision(row, baseline_rate))
    cleanup_path = run/'post-run-process-check.json'
    if not cleanup_path.exists(): raise ValueError('post-run cleanup evidence missing')
    row['cleanup'] = json.loads(cleanup_path.read_text())
    assert not row['cleanup']['remaining_processes'] and not row['cleanup']['shared_scratch_files']
    assert row['cleanup']['binary_hashes_verified'] and row['cleanup']['source_archive_verified']
    return row

def render(data, path):
    baseline = data['baseline']; attempts = data['attempts']; scale = max([baseline['rate'], *(a['rate'] for a in attempts if a['valid'])])
    bars = [("Verified 3 workers × 6 threads", baseline['rate'])] + [(f'4 workers × 4 threads · attempt {i+1}', a['rate']) for i,a in enumerate(attempts) if a['valid']]
    chart = ''.join(f'<div class="row"><b>{label}</b><span>{rate:.2f} transaction-equivalents/hour</span><div class="track"><div class="throughput-bar" style="width:{rate/scale*100:.3f}%"></div></div></div>' for label,rate in bars)
    target = data['minimum_rate']
    chart += f'<div class="row"><b>Acceptance minimum</b><span>{target:.2f}/hour</span><div class="track"><div class="target-bar" style="width:{target/scale*100:.3f}%"></div></div></div>'
    selected = next((a for a in reversed(attempts) if a['accepted']), None)
    summary = (f"Accepted profile: four workers × four threads, {selected['raw']['late_phase_slots']} late-stage permit and one query permit. Measured {selected['rate']:.2f}/hour ({(selected['rate']/baseline['rate']-1)*100:+.2f}% versus three workers), with {selected['resources']['compressor_growth_bytes']/GIB:.2f} GiB compressor growth and no additional swap." if selected else 'No attempted four-worker profile met every acceptance criterion.')
    cards = ''
    for i,a in enumerate(attempts):
        r = a['resources']; raw = a['raw']; status = 'QUALIFIED SCREEN' if a['accepted'] else ('COMPLETED · BELOW ACCEPTANCE' if a['valid'] else 'STOPPED OR RESOURCE-INVALID')
        rate = f'{a["rate"]:.2f}/hour' if a['valid'] else 'No valid throughput result'
        largest_salts = max(a['workers'], key=lambda w:w['largest_salt_group_dense_bytes'])
        workers = ''.join(f'<tr><td>{w["index"]+1}</td><td>{w["proofs"]}/7</td><td>{w["persisted_peak_footprint_bytes"]/GIB:.2f} GiB{" (partial)" if not w["exit_sample"] else ""}</td><td>{w["salt_commits"]}</td></tr>' for w in a['workers'])
        cards += f'''<section id="attempt-{i+1}"><h2>Attempt {i+1}: {status}</h2><p>{a['seconds']:.2f} seconds · {rate} · {a['completed_recursive_proofs']}/28 fresh recursive proofs · {a['completed_root_audits']}/4 independent CPU audits.</p><p>{html.escape(a['failure'] or 'All requested jobs completed.')}</p><p>Late permits: {raw['late_phase_slots']}; query permits: 1; query scratch: {raw['query_scratch_bytes']/GIB:g} GiB. Maximum concurrent proofs after heavy-stage admission: {a['max_inflight_proofs']} (excludes workers waiting to enter that stage). Stage maxima: heavy {a['phase_maximum']['heavy']}, late {a['phase_maximum']['late']}, query {a['phase_maximum']['query']}.</p><div class="table-wrap"><table><tr><th>Measurement</th><th>Observed</th></tr><tr><td>System compressor start → peak</td><td>{r['compressor_start_bytes']/GIB:.2f} → {r['compressor_peak_bytes']/GIB:.2f} GiB</td></tr><tr><td>Compressor growth (maximum 6 GiB)</td><td>{r['compressor_growth_bytes']/GIB:.2f} GiB</td></tr><tr><td>Additional swap</td><td>{r['swap_growth_bytes']/(1<<20):.2f} MiB</td></tr><tr><td>Pressure levels (1 = normal; 2 = warning)</td><td>{', '.join(map(str,r['pressure_levels']))}</td></tr><tr><td>Sampled aggregate RSS</td><td>{r['aggregate_peak_rss_bytes']/GIB:.2f} GiB</td></tr></table></div><div class="table-wrap"><table><tr><th>Worker</th><th>Proofs</th><th>Peak physical footprint</th><th>Compact salt commits</th></tr>{workers}</table></div><p>The largest salt group retained {largest_salts['largest_salt_group_dense_bytes']/(1<<20):.0f} MiB as full matrices before this change; its checkpoint representation retains {largest_salts['largest_salt_group_checkpoint_bytes']/(1<<20):.2f} MiB after GPU commitment completion. This is an allocation-lifetime reduction, not a measured system-peak reduction.</p><p>Cleanup verified: all tracked benchmark processes exited; shared scratch files were removed. Proof-source, binary and archive hashes matched after the run.</p></section>'''
    encoded = json.dumps(data,separators=(',', ':')).replace('<','\\u003c')
    path.write_text(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lattica · Four-worker memory reduction</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6f9;color:#173147;font:16px/1.6 system-ui,sans-serif}}main{{max-width:1050px;margin:auto;padding:32px 24px}}h1{{font-size:35px;line-height:1.2}}h2{{font-size:23px;margin-top:0}}section{{background:white;border:1px solid #dce4eb;border-radius:12px;padding:24px;margin:24px 0}}.row{{margin:22px 0}}.row span{{display:block}}.track{{height:27px;background:#e6edf2;border-radius:4px;overflow:hidden;margin:8px 0}}.throughput-bar,.target-bar{{height:100%;background:#127f7a}}.target-bar{{background:#758499}}.table-wrap{{overflow-x:auto;margin:16px 0}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #dce4eb;text-align:left;padding:9px;white-space:nowrap}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-height:440px;overflow:auto;font-size:11px}}button{{background:#127f7a;color:white;border:0;padding:10px 14px;border-radius:5px;font:inherit}}.note{{color:#52687a}}@media(max-width:640px){{main{{padding:20px 14px}}section{{padding:18px}}h1{{font-size:28px}}}}@media print{{button,details{{display:none}}section{{break-inside:avoid}}.throughput-bar,.target-bar{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}}}
</style></head><body><main><p>LATTICA · APPLE M5 PRO · 64 GiB UNIFIED MEMORY</p><h1>Four-worker memory and scheduling comparison</h1><p><strong>{data['status']}</strong></p><p>{summary}</p><section><h2>Verified throughput</h2><p>Four processes use four CPU threads each. Proofs remain independently in flight; permits constrain individual stages. The earlier three-worker result used six CPU threads each and earlier proof sources. It was reused without repeating the benchmark.</p>{chart}<p class="note">Bars start at zero on a shared scale. Interrupted and resource-invalid attempts have no throughput bar. These are single-window aggregation measurements using existing wallet-proof fixtures, not sustained production capacity or accepted-chain transaction rates.</p></section>{cards}<section><h2>Acceptance and interpretation</h2><p>The accepted 10% throughput tolerance sets a minimum of {target:.2f} transaction-equivalents/hour: all 32 equivalents must finish within {data['maximum_seconds']:.2f} seconds, including independent CPU audits. This is an acceptance threshold, not a timeout. Memory pressure must remain normal, additional swap must be zero, and system compressor growth must not exceed 6 GiB.</p><p>Compact salt storage retains private RNG checkpoints every 1,024 rows. Exact salt values are regenerated only for requested queries; no checkpoint or seed is included in proof serialization or this report. The temporary full salt matrices still exist during commitment construction, then are released after GPU completion. Salt byte totals in the evidence sum commits and must not be interpreted as peak RAM savings.</p><p>Two heavy-stage permits, 2 GiB LDE scratch, 7 GiB managed allowance per worker, shared public preprocessing and early scratch retirement remain active. No total timeout or fixed proving-worker RSS ceiling is applied. macOS pressure monitoring remains enabled.</p><p class="note">Aggregate RSS may count shared mappings more than once. Compressor usage is system-wide. Process physical footprint, RSS and GPU allocation figures overlap and must not be added. Native sampling runs every 500 ms; five-second progress records preserve partial peaks if workers are stopped. Incomplete progress lines interleaved with profiler output are counted in the evidence and skipped; complete process-exit records determine successful-run peaks. At most two full windows are allowed. All source, binary, fixture and controller hashes remain in the original results.</p></section><section><h2>Evidence</h2><p><a href="analysis.json">Analysis JSON</a>. Raw results, worker logs, archived sources and cleanup checks remain in each attempt directory. Full result data are also embedded here for sharing.</p><button id="download">Download evidence JSON</button><details><summary>Embedded evidence</summary><pre id="details"></pre></details></section><script id="evidence" type="application/json">{encoded}</script><script>const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-four-worker-memory.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}};</script></main></body></html>''')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline',type=Path,required=True);p.add_argument('--attempt',type=Path,action='append',required=True);p.add_argument('--out',type=Path,required=True)
    args = p.parse_args()
    if not 1 <= len(args.attempt) <= 2: p.error('one or two attempts required')
    raw = json.loads(args.baseline.read_text()); assert raw['status'] == 'COMPLETE_VERIFIED_SCREEN' and raw['workers'] == 3
    baseline = dict(rate=raw['window']['transaction_equivalents_per_hour'],raw=raw,result_sha256=digest(args.baseline))
    attempts = [analyze(path,baseline['rate']) for path in args.attempt]
    assert attempts[0]['raw']['late_phase_slots'] == 2 and attempts[0]['raw']['query_scratch_bytes'] == GIB
    if len(attempts) == 2:
        followup = attempts[0]['followup']; assert followup is not None
        expected = (1,GIB) if followup == 'late_one' else (2,2*GIB)
        assert (attempts[1]['raw']['late_phase_slots'],attempts[1]['raw']['query_scratch_bytes']) == expected
        assert attempts[0]['raw']['binary_sha256'] == attempts[1]['raw']['binary_sha256']
    data = dict(schema='apple-four-worker-memory-v1',status='QUALIFIED_FOUR_WORKER_SCREEN' if any(a['accepted'] for a in attempts) else 'NO_QUALIFYING_FOUR_WORKER_SCREEN',
                baseline=baseline,minimum_rate=baseline['rate']*.9,maximum_seconds=32*3600/(baseline['rate']*.9),attempts=attempts,
                next_configuration=attempts[0]['followup'] if len(attempts)==1 else None, full_window_limit=2,generator_sha256=digest(__file__))
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'analysis.json').write_text(json.dumps(data,indent=2)+'\n');render(data,args.out/'report.html')
    print(json.dumps(dict(status=data['status'], next_configuration=data['next_configuration'],attempts=[{k:a[k] for k in ('seconds','valid','rate','accepted','completed_recursive_proofs','completed_root_audits','resources','phase_maximum','max_inflight_proofs')} for a in attempts]),indent=2))

if __name__ == '__main__': main()
