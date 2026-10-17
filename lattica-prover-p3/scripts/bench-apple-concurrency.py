#!/usr/bin/env python3
"""One compact Metal concurrency experiment; reuse audited comparison windows."""
import argparse
import datetime
import html
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('concurrency_screen', ROOT / 'scripts/bench-apple-throughput.py')
screen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(screen)
GIB = 1 << 30
OPTIONS = dict(pipeline='reference', poseidon_diagonal='specialized', ntt_tables='on',
               ntt_tile_log2='12', quotient='cpu', prefix_store='separate',
               direct_readback='1', denominator_cache='0', query_gather='1', compact_data='1')


def checkpoints(text):
    rows = {}
    for line in text.splitlines():
        if not line.startswith(('bounded_gpu_', 'metal_checkpoint ', 'metal_initialized ')):
            continue
        parts = shlex.split(line)
        fields = {}
        for part in parts[1:]:
            if '=' in part:
                k, v = part.split('=', 1)
                fields[k] = int(v) if v.isdigit() else v
        rows[parts[0]] = fields
    return rows



def phase_evidence(phases, late_slots=None, query_slots=None):
    """Validate independent pools; old evidence without pool names is heavy."""
    limits = {'heavy': 2}
    if late_slots is not None:
        limits['late'] = late_slots
    if query_slots is not None:
        limits['query'] = query_slots
    active = {}; peak = {pool: 0 for pool in limits}; waits = dict.fromkeys(limits, 0)
    proofs = set(); max_proofs = 0
    admissions = dict.fromkeys(limits, 0)
    for _, admitted, fields in sorted(phases):
        pool = fields.get('pool', 'heavy')
        if pool not in limits:
            raise RuntimeError('unexpected memory permit pool: ' + pool)
        slot = int(fields['slot']); pid = fields['pid']; key = (pool, slot)
        if not 0 <= slot < limits[pool]:
            raise RuntimeError('memory permit slot outside configured pool')
        if admitted:
            if key in active:
                raise RuntimeError('overlapping phases used the same permit')
            active[key] = pid
            admissions[pool] += 1
            if late_slots is not None and pool == 'heavy' and fields.get('phase') == 'trace and quotient':
                if pid in proofs: raise RuntimeError('proof phase admitted twice')
                proofs.add(pid); max_proofs = max(max_proofs, len(proofs))
            waits[pool] += int(fields['waited_ms'])
            peak[pool] = max(peak[pool], sum(k[0] == pool for k in active))
        elif active.pop(key, None) != pid:
            raise RuntimeError('memory phase released without matching admission')
        elif pool == 'late':
            proofs.discard(pid)
    if active or not all(admissions.values()):
        raise RuntimeError('memory permit evidence incomplete')
    return dict(max_concurrent_heavy_phases=peak['heavy'], max_concurrent_late_phases=peak.get('late', 0), max_concurrent_query_phases=peak.get('query', 0),
                max_inflight_proofs=max_proofs if late_slots is not None else None,
                phase_events=len(phases), phase_admissions=admissions, phase_wait_ms=waits)


def render(report, path):
    baseline = report['baseline']
    candidate = report.get('window')
    workers = report['workers']
    threads = report['threads_per_worker']
    managed_gib = report['managed_bytes_per_worker'] / GIB
    target_seconds = report['target_seconds']
    memory_note = ('This candidate uses two concurrent heavy-stage permits, '
                   'a 2 GiB transform scratch allowance per worker, early scratch retirement, and shared read-only public preprocessing. '
                   'The single-worker baseline uses earlier sources. '
                   + ('The concurrency comparison uses the same qualified proof binaries. '
                      if report.get('comparison_same_proof_build') else 'The concurrency comparison also uses historical sources. ') +
                   'Per-process RSS includes shared pages and its sum can double-count them.'
                   if report.get('memory_optimized') else 'The baseline is an earlier verified run of the same binaries.')
    memory_section = ''
    if report.get('memory_optimized'):
        evidence = report.get('memory_optimization_evidence', {})
        sharing_rows = ''.join(f"<tr><td>{r['key']}</td><td>{r['bytes']/GIB:.2f}</td><td>{r['workers']}</td><td>{r['validated_reuses']}</td></tr>"
                               for r in evidence.get('shared_prefixes', []))
        memory_section = (f'<section><h2>Memory changes</h2><p>{workers} worker processes use {threads} CPU threads each ({workers * threads} total). '
                          'A process-shared permit allows at most two preprocessing or trace/quotient stages at once. '
                          'Permits are released after large trace prefixes and temporary GPU buffers are retired; '
                          'the remaining proof stages can overlap with another worker.</p><p>The transform pair is limited to 2 GiB per worker, '
                          f'inside the {managed_gib:g} GiB managed allowance. NTT table reservations are included in planning. '
                          'Public preprocessing prefixes use one read-only mapped file per circuit mode. '
                          'Every reuse is checked against freshly computed GPU output; witness data and randomness stay private.</p>'
                          f"<p>Observed maximum concurrent heavy stages: <strong>{evidence.get('max_concurrent_heavy_phases', 'pending')}</strong>.</p>"
                          '<div class="table-wrap"><table><thead><tr><th>Public prefix key</th><th>Size GiB</th><th>Workers sharing</th><th>Validated reuses</th></tr></thead>'
                          f'<tbody>{sharing_rows}</tbody></table></div><p class="note">Shared pages can appear in several worker RSS readings. '
                          'Logical copies avoided are not a measured peak physical-memory reduction. '
                          'Shared scratch files are removed after every owned worker exits; metadata remains in the evidence.</p></section>')
    if report.get('query_scratch_bytes') is not None:
        memory_section += (f'<section><h2>Additional memory headroom</h2><p>The query transform pair is limited to {report["query_scratch_bytes"]/GIB:g} GiB. '
                           f'Late-stage permits: {report.get("late_phase_slots") or "disabled"}; query permits: {report.get("query_phase_slots") or "disabled"}. Compact salt checkpoints: {report.get("compact_salts", False)}. Opening interpolation weights use only degree-prefix rows; '
                           'their storage and inverse denominators are released before FRI processing. Obsolete cached GPU scratch is retired before later allocations.</p></section>')
    rows = [('Earlier single-worker run · 7 GiB', baseline['transaction_equivalents_per_hour'], baseline['seconds'], '1 × 18 threads', 'PASS')]
    comparison = report.get('comparison_window')
    if comparison:
        n = comparison['workers']
        prior_gib = report.get('comparison_managed_bytes_per_worker', 7 * GIB) / GIB
        rows.append((f'Earlier {n}-worker run · {prior_gib:g} GiB each', comparison['transaction_equivalents_per_hour'], comparison['seconds'], f'{n} × {18//n} threads', f'PASS × {n}'))
    if candidate:
        rows.append((f'{workers} compact workers · {managed_gib:g} GiB each', candidate['transaction_equivalents_per_hour'], candidate['seconds'], f'{workers} × {threads} threads', f'PASS × {workers}'))
    scale = max(200, *(row[1] for row in rows))
    bars = ''.join(f'<div class="row"><b>{html.escape(label)}</b><span>{rate:.2f} transaction equivalents/hour</span>'
                   f'<div class="track"><div class="bar" style="width:{rate/scale*100:.2f}%"></div></div>'
                   f'<small>{seconds:.2f} seconds · {threads} · CPU audit {audit}</small></div>'
                   for label, rate, seconds, threads, audit in rows)
    bars += f'<div class="row target"><b>Target</b><span>200.00 transaction equivalents/hour</span><div class="track"><div class="bar" style="width:{200/scale*100:.2f}%"></div></div></div>'
    failure = report.get('failed_window')
    if failure:
        outcome = f'The concurrent attempt stopped after {failure["seconds"]:.2f} seconds: {html.escape(failure["failure"])}. No completed-window throughput is assigned.'
    elif candidate:
        outcome = (f'{workers} independent CPU audits passed. Observed throughput was {candidate["transaction_equivalents_per_hour"]:.2f}/hour; '
                   f'the 200/hour screening target was {"met" if report["target_met"] else "not met"}.')
    else:
        outcome = html.escape(report.get('failure', 'The experiment is running.'))
    attempt = candidate or failure or {}
    jobs = ''.join(f'<tr><td>{j["index"]}</td><td>{j["proof_seconds"]:.2f}</td><td>{j["audited_completion_seconds"]:.2f}</td>'
                   f'<td>{j["worker_peak_rss_bytes"]/GIB:.2f}</td><td>PASS</td></tr>' for j in attempt.get('jobs', []))
    resources = (f'<p>Sampled aggregate peak RSS: <strong>{attempt.get("aggregate_peak_rss_bytes",0)/GIB:.2f} GiB</strong>. '
                 f'Swap growth: {attempt.get("swap_growth_bytes",0)/(1<<20):.2f} MiB. '
                 f'Memory-pressure incident: {attempt.get("memory_pressure_incident",False)}.</p>') if attempt else ''
    encoded = json.dumps(report, separators=(',', ':')).replace('<', '\\u003c')
    path.write_text(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · {workers}-worker Apple throughput experiment</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6f9;color:#173147;font:16px/1.6 system-ui,-apple-system,sans-serif}}main{{max-width:1050px;margin:auto;padding:38px 24px}}section{{background:white;border:1px solid #dce4eb;border-radius:12px;margin:24px 0;padding:24px}}h1{{font-size:36px;line-height:1.2}}h2{{font-size:23px;margin-top:0}}.row{{margin:24px 0}}.row span{{display:block;font-variant-numeric:tabular-nums}}.track{{height:28px;border-radius:4px;background:#e6edf2;margin:8px 0;overflow:hidden}}.bar{{height:100%;background:#127f7a}}.target .bar{{background:#758499}}small,.note{{color:#52687a}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;text-align:left;border-bottom:1px solid #dce4eb;white-space:nowrap}}code,pre{{overflow-wrap:anywhere;word-break:break-word}}pre{{font-size:11px;max-height:480px;overflow:auto;white-space:pre-wrap}}button{{background:#127f7a;color:white;border:0;border-radius:5px;padding:10px 14px;font:inherit}}@media print{{button,details{{display:none}}section{{break-inside:avoid}}.bar{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}}}@media(max-width:640px){{main{{padding:20px 14px}}section{{padding:18px}}h1{{font-size:28px}}}}
</style></head><body><main><p>LATTICA · APPLE M5 PRO · 64 GiB · 7 OCTOBER 2026</p>
<h1>{workers} compact workers: transaction throughput on Apple Silicon</h1><p><strong>{html.escape(report['status'])}</strong></p><section><h2>Observed result</h2><p>{outcome}</p></section>
<section><h2>Aggregation throughput</h2><p class="note">Longer bars are better. All bars start at zero on the same scale. {html.escape(memory_note)} No baseline jobs were repeated in this experiment.</p>{bars}</section>
<section><h2>Work completed and memory</h2>{resources}<div class="table-wrap"><table><thead><tr><th>Job</th><th>Proof seconds</th><th>Audited completion<br>seconds from window start</th><th>Peak worker RSS<br>GiB</th><th>Independent audit</th></tr></thead><tbody>{jobs}</tbody></table></div><p class="note">GPU managed memory and RSS overlap; they must not be added. RSS is sampled and does not describe the entire system footprint. Interrupted-run peaks are partial observations.</p></section>
{memory_section}<section><h2>Experiment design</h2><p>Exactly {workers} fresh eight-input jobs, {threads} CPU threads and a {managed_gib:g} GiB managed allowance per worker. Earlier one- and two-worker results used 7 GiB each; a different allowance changes both concurrency and memory configuration. Each additional worker starts after the preceding worker completes its initial preprocessing. All use compact prover data, direct readback, GPU query gathering, specialized Poseidon, cached NTT tables and CPU quotient evaluation.</p><p>The timing window includes all launches, their stagger, proof generation, pruning and separate CPU audits. The target is {workers*8} × 3,600 / 200 = <strong>{target_seconds:g} seconds</strong>. Each completed job must produce seven fresh recursive proofs. Wallet proofs are existing fixtures; wallet-proof creation and builds are excluded.</p><p>No total benchmark timeout or fixed proving-worker RSS cap is applied. System memory pressure remains monitored. CPU/GPU timelines and two five-second CPU stack samples per worker are enabled for this concurrent window and the earlier concurrency window; the single-worker baseline was not profiled. Their overhead is included in the measured result. {html.escape(memory_note)}</p><p>One concurrent timing window is one sample. It cannot establish sustained production throughput or statistical confidence. No proving parameters, verification checks or circuit definitions were changed.</p></section>
<section><h2>Evidence</h2><p>Source, binary, fixture and controller hashes, launch offsets, audits and resource observations are embedded below. Full logs and source archives remain in the result directory.</p><button id="download">Download evidence JSON</button><details><summary>Embedded evidence</summary><pre id="details"></pre></details></section>
<script id="evidence" type="application/json">{encoded}</script><script>const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-compact-concurrency-20261007.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}};</script></main></body></html>''')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=(2, 3, 4, 5), default=2)
    parser.add_argument('--managed-gib', type=int, choices=(4, 5, 7), default=7)
    parser.add_argument('--memory-optimized', action='store_true', help='two heavy-stage permits, 2 GiB transform scratch, shared public preprocessing; compare historical qualified sources')
    parser.add_argument('--query-scratch-mib', type=int, help='combined query transform buffers; requires --memory-optimized')
    parser.add_argument('--late-phase-slots', type=int, choices=(1, 2, 3), help='optional quotient/opening/FRI permit pool')
    parser.add_argument('--compact-salts', action='store_true', help='retain private RNG checkpoints instead of full compact salt matrices')
    parser.add_argument('--query-phase-slots', type=int, choices=(1, 2, 3), help='shared query reconstruction permit pool')
    parser.add_argument('--comparison', type=Path, help='optional prior verified concurrency result')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.workers >= 4 and not args.memory_optimized:
        parser.error('four or five workers require --memory-optimized')
    if args.workers == 5 and (not args.compact_salts or args.late_phase_slots != 1
                              or args.query_phase_slots != 1 or args.query_scratch_mib != 1024):
        parser.error('five-worker screen requires --compact-salts, --late-phase-slots 1, '
                     '--query-phase-slots 1 and --query-scratch-mib 1024')
    if (args.query_scratch_mib is not None or args.late_phase_slots is not None or args.query_phase_slots is not None or args.compact_salts) and not args.memory_optimized:
        parser.error('headroom controls require --memory-optimized')
    if args.query_scratch_mib is not None and not 0 < args.query_scratch_mib <= args.managed_gib * 1024:
        parser.error('query scratch MiB must be positive and fit the managed allowance')
    return args


def main():
    args = parse_args()
    prior = json.loads(args.reference.read_text())
    build = json.loads(args.build.read_text())
    qualification = json.loads(args.qualification.read_text())
    workers = args.workers
    threads = 18 // workers
    target_seconds = workers * 8 * 3600 / 200
    managed_bytes = args.managed_gib * GIB
    baseline, = [w for w in prior['windows'] if w['effective_managed_bytes'] == 7 * GIB]
    if not baseline['valid_comparison'] or not all(j['verified'] for j in baseline['jobs']):
        raise RuntimeError('reference is not independently verified and resource-clean')
    if prior['options'] != OPTIONS or prior['workers'] != 1 or prior['threads'] != 18:
        raise RuntimeError('reference configuration differs')
    if qualification['status'] != 'PASS' or qualification['proof_source_sha256'] != build['source_hashes']:
        raise RuntimeError('qualification does not match proof sources')
    required = {'proof-direct-gather', 'proof-banded-gather', 'large-buffer-fill', 'wide-lde-tiles'}
    if not required.issubset({t['label'] for t in qualification['tests'] if t['status'] == 'PASS'}):
        raise RuntimeError('required qualification missing')
    if args.memory_optimized:
        required |= {'phase-permits', 'shared-prefix', 'queue-retirement', 'shared-preprocessing-proof'}
        if not required.issubset({t['label'] for t in qualification['tests'] if t['status'] == 'PASS'}):
            raise RuntimeError('memory optimization qualification missing')
    if args.query_scratch_mib is not None or args.late_phase_slots is not None:
        required |= {'headroom-proof', 'scratch-retirement', 'opening-weights'}
        if not required.issubset({t['label'] for t in qualification['tests'] if t['status'] == 'PASS'}):
            raise RuntimeError('headroom qualification missing')
    if args.compact_salts and not {'salt-replay', 'salt-proof'}.issubset({t['label'] for t in qualification['tests'] if t['status'] == 'PASS'}):
        raise RuntimeError('compact salt qualification missing')
    if args.query_phase_slots is not None and not {'query-phase-proof', 'query-unwind'}.issubset({t['label'] for t in qualification['tests'] if t['status'] == 'PASS'}):
        raise RuntimeError('query phase qualification missing')
    for name, sha in build['source_hashes'].items():
        if screen.digest(ROOT / name) != sha:
            raise RuntimeError('proof source differs from qualified build: ' + name)
    if not args.memory_optimized and prior['build']['source_hashes'] != build['source_hashes']:
        raise RuntimeError('reference proof sources differ')
    comparison = json.loads(args.comparison.read_text()) if args.comparison else None
    if comparison:
        if comparison['status'] != 'COMPLETE_VERIFIED_SCREEN' or not comparison['valid_comparison']:
            raise RuntimeError('concurrency comparison is not verified and resource-clean')
        for key, expected in [('options', OPTIONS), ('fixture_sha256', prior['fixture_sha256']),
                              ('binary_sha256', prior['binary_sha256'])]:
            if comparison[key] != expected and not (args.memory_optimized and key == 'binary_sha256'):
                raise RuntimeError('concurrency comparison differs: ' + key)
        if not args.memory_optimized and comparison['build']['source_hashes'] != build['source_hashes']:
            raise RuntimeError('concurrency comparison proof sources differ')
        if len(comparison['window']['jobs']) != comparison['workers'] or not all(j['verified'] for j in comparison['window']['jobs']):
            raise RuntimeError('concurrency comparison audit missing')
    fixture = ROOT / 'fixtures/apple-benchmark-eight'
    for name, sha in prior['fixture_sha256'].items():
        if (fixture / name).is_symlink() or screen.digest(fixture / name) != sha:
            raise RuntimeError('fixture differs from reference: ' + name)
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    (out / 'bin').mkdir(); (out / 'fixture').mkdir()
    binaries = {}
    for role, name in {'cpu': 'block-v2-grouped-probe', 'audit': 'block-v2-grouped-artifact-audit', 'metal': 'block-v2-metal-grouped-probe'}.items():
        entry = build['binaries'][name]
        if screen.digest(entry['path']) != entry['sha256'] or (not args.memory_optimized and prior['binary_sha256'][name] != entry['sha256']):
            raise RuntimeError('binary differs from reference or build: ' + name)
        binaries[role] = out / 'bin' / name
        shutil.copy2(entry['path'], binaries[role])
    for name in screen.baseline.FIXTURE_NAMES:
        shutil.copy2(fixture / name, out / 'fixture' / name)
    with tarfile.open(out / 'source.tar.gz', 'w:gz') as archive:
        for path in [*(ROOT / name for name in build['source_hashes']), *sorted((ROOT / 'scripts').glob('*.py'))]:
            archive.add(path, arcname=str(path.relative_to(ROOT)))
    for name in list(os.environ):
        if name.startswith(('LATTICA_', 'RAYON_')):
            os.environ.pop(name)
    os.environ['LATTICA_V2_GPU_MANAGED_BYTES'] = str(managed_bytes)
    if args.memory_optimized:
        for name in ('phases', 'shared-preprocessing'):
            (out / name).mkdir(mode=0o700)
        os.environ.update(LATTICA_APPLE_PHASE_DIR=str(out / 'phases'), LATTICA_APPLE_PHASE_SLOTS='2',
                          LATTICA_APPLE_MEMORY_RECLAIM='1', LATTICA_APPLE_LDE_SCRATCH_BYTES=str(2 * GIB),
                          LATTICA_APPLE_SHARED_PREPROCESSING_DIR=str(out / 'shared-preprocessing'))
    if args.query_scratch_mib is not None:
        os.environ['LATTICA_APPLE_QUERY_SCRATCH_BYTES'] = str(args.query_scratch_mib * (1 << 20))
    if args.late_phase_slots is not None:
        os.environ['LATTICA_APPLE_LATE_PHASE_SLOTS'] = str(args.late_phase_slots)
    if args.compact_salts:
        os.environ['LATTICA_APPLE_COMPACT_SALTS'] = '1'
    if args.query_phase_slots is not None:
        os.environ['LATTICA_APPLE_QUERY_PHASE_SLOTS'] = str(args.query_phase_slots)
    run_args = argparse.Namespace(workers=workers, kernel_variant='reference', workgroup=256,
                                  worker_launch_phase='after-preprocessing', diagnostic_profile=True,
                                  **{'candidate_' + k: v for k, v in OPTIONS.items()})
    env = screen.policy(workers, True, out / 'scratch', 'reference', 256, True, OPTIONS)
    assert env['RAYON_NUM_THREADS'] == str(threads) and env['LATTICA_V2_GPU_MANAGED_BYTES'] == str(managed_bytes)
    screen.validate_candidate_workers(workers, OPTIONS)
    report = dict(schema='apple-compact-concurrency-v1', status='RUNNING',
                  started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  build=build, qualification=qualification, baseline=baseline, options=OPTIONS,
                  reference_result=str(args.reference.resolve()), reference_result_sha256=screen.digest(args.reference),
                  fixture_sha256=prior['fixture_sha256'], binary_sha256={p.name: screen.digest(p) for p in binaries.values()},
                  query_scratch_bytes=args.query_scratch_mib * (1 << 20) if args.query_scratch_mib is not None else None,
                  late_phase_slots=args.late_phase_slots, query_phase_slots=args.query_phase_slots, compact_salts=args.compact_salts,
                  memory_optimized=args.memory_optimized, historical_reference_sources=prior['build']['source_hashes'],
                  historical_reference_binary_sha256=prior['binary_sha256'],
                  controller_sha256=screen.digest(__file__),
                  helper_sha256={str(p.relative_to(ROOT)): screen.digest(p) for p in (ROOT / 'scripts').glob('*.py')},
                  source_archive_sha256=screen.digest(out / 'source.tar.gz'), external=prior['external'],
                  workers=workers, threads_per_worker=threads, threads_total=workers * threads, cpu_core_budget=18, managed_bytes_per_worker=managed_bytes,
                  worker_launch_phase='after-preprocessing', diagnostic_profile=True,
                  transactions_per_job=8, fresh_recursive_proofs_per_job=7, jobs_requested=workers,
                  target_transaction_equivalents_per_hour=200, target_seconds=target_seconds,
                  benchmark_timeout_seconds=None, worker_rss_limit_bytes=None,
                  production_ready=False, performance_promotion=False,
                  hardware=subprocess.check_output(['/usr/sbin/sysctl', 'machdep.cpu.brand_string', 'hw.memsize', 'hw.ncpu'], text=True),
                  before=screen.observations(), environment={k:v for k,v in env.items() if k.startswith(('LATTICA_', 'RAYON_'))})
    if comparison:
        report.update(comparison_window=comparison['window'], comparison_result=str(args.comparison.resolve()),
                      comparison_managed_bytes_per_worker=comparison['managed_bytes_per_worker'],
                      comparison_result_sha256=screen.digest(args.comparison),
                      comparison_same_proof_build=(comparison['build']['source_hashes'] == build['source_hashes']
                                                  and comparison['binary_sha256'] == report['binary_sha256']),
                      comparison_match_seconds=workers * 8 * 3600 / comparison['window']['transaction_equivalents_per_hour'])
    def save():
        screen.save(out / 'result.json', report); render(report, out / 'report.html')
    def interrupted(signum, frame):
        raise KeyboardInterrupt('controller signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    save()
    try:
        if report['before']['pressure'] != 1:
            raise RuntimeError('memory pressure present before trial')
        print(f'PREFLIGHT: source, binary and fixture hashes match; {workers} workers, {threads} threads each, {args.managed_gib} GiB each', flush=True)
        print(f'TARGET: all {workers} independent CPU audits complete within {target_seconds:g} seconds; no benchmark timeout', flush=True)
        if comparison:
            print(f'COMPARISON: match the earlier {comparison["workers"]}-worker {comparison["window"]["transaction_equivalents_per_hour"]:.2f}/hour at {report["comparison_match_seconds"]:.2f}s', flush=True)
        with screen.coordinator_lease():
            window = screen.run_window(run_args, out, binaries, prior['external'], True)
        for job in window['jobs']:
            path = out / window['label'] / f'job-{job["index"]}' / 'worker.log'
            text = path.read_text()
            observed = {int(x) for x in re.findall(r'bounded_gpu_initialized[^\n]*managed_limit_bytes=(\d+)', text)}
            if observed != {managed_bytes}:
                raise RuntimeError('managed allowance did not take effect')
            if set(re.findall(r'bounded_lde_readback_layout layout=(\w+)', text)) != {'Direct'}:
                raise RuntimeError('direct readback did not take effect')
            if not re.search(r'bounded_gpu_query_checkpoint .*gather=true calls=[1-9]', text):
                raise RuntimeError('GPU query gathering missing')
            if args.memory_optimized:
                if 'apple_shared_preprocessing ' not in text:
                    raise RuntimeError('shared public preprocessing missing')
                if 'apple_memory_admit ' not in text or 'scratch retired' not in text:
                    raise RuntimeError('memory phase admission/retirement missing')
                job['memory_events'] = [line for line in text.splitlines() if line.startswith(('apple_memory_', 'apple_shared_preprocessing ', 'apple_scratch_retired ', 'apple_query_scratch ', 'apple_opening_workspace ', 'apple_salt_storage ', 'apple_salt_queries '))]
            memory = re.findall(r'metal_worker_memory peak_rss_bytes=(\d+) peak_footprint_bytes=(\d+) sample_ms=(\d+)', text)
            if len(memory) != 1 or memory[0][2] != '500':
                raise RuntimeError('worker physical-footprint sampling evidence missing')
            job['worker_sampled_peak_footprint_bytes'] = int(memory[0][1])
            if args.query_scratch_mib is not None:
                scratch = [dict(part.split('=', 1) for part in line.split()[1:]) for line in text.splitlines() if line.startswith('apple_query_scratch ')]
                if not scratch or any(int(row['allowance_bytes']) != report['query_scratch_bytes'] or not 0 < int(row['transform_bytes']) <= report['query_scratch_bytes'] for row in scratch):
                    raise RuntimeError('query scratch allowance did not take effect')
                job['query_scratch_peak_bytes'] = max(int(row['transform_bytes']) for row in scratch)
                job['query_scratch_plans'] = len(scratch)
            if args.compact_salts:
                salt_rows = [dict(part.split('=', 1) for part in line.split()[1:]) for line in text.splitlines() if line.startswith('apple_salt_storage ')]
                query_rows = [dict(part.split('=', 1) for part in line.split()[1:]) for line in text.splitlines() if line.startswith('apple_salt_queries ')]
                if not salt_rows or not query_rows or any(int(r['checkpoint_bytes']) >= int(r['dense_bytes']) for r in salt_rows):
                    raise RuntimeError('compact salt storage/replay evidence missing')
                job['salt_storage_commits'] = len(salt_rows)
                job['salt_dense_bytes_over_commits'] = sum(int(r['dense_bytes']) for r in salt_rows)
                job['salt_checkpoint_bytes_over_commits'] = sum(int(r['checkpoint_bytes']) for r in salt_rows)
                job['salt_regenerated_rows'] = sum(int(r['regenerated_rows']) for r in query_rows)
            job['memory_progress_samples'] = len(re.findall(r'^metal_worker_memory_progress ', text, re.MULTILINE))
            job['checkpoints'] = checkpoints(text)
            job['worker_log'] = str(path.relative_to(out))
        if args.memory_optimized:
            groups = {}
            phases = []
            for job in window['jobs']:
                for line in job['memory_events']:
                    fields = dict(part.split('=', 1) for part in shlex.split(line)[1:] if '=' in part)
                    if line.startswith('apple_shared_preprocessing '):
                        groups.setdefault(fields['key'], []).append(fields)
                    elif line.startswith(('apple_memory_admit ', 'apple_memory_release ')):
                        phases.append((int(fields['clock_ns']), line.startswith('apple_memory_admit '), fields))
            sharing = []
            for key, rows in groups.items():
                if len({r['pid'] for r in rows}) != workers or len({r['inode'] for r in rows}) != 1:
                    raise RuntimeError('preprocessing was not shared by all workers')
                if sum(r['cache_hit'] == 'false' for r in rows) != 1:
                    raise RuntimeError('public preprocessing did not have exactly one writer')
                sharing.append(dict(key=key, workers=len({r['pid'] for r in rows}),
                                    bytes=int(rows[0]['bytes']), inode=int(rows[0]['inode']),
                                    validated_reuses=sum(r['cache_hit'] == 'true' for r in rows)))
            if not groups:
                raise RuntimeError('shared preprocessing evidence missing')
            phase_stats = phase_evidence(phases, args.late_phase_slots, args.query_phase_slots)
            report['memory_optimization_evidence'] = dict(shared_prefixes=sharing, **phase_stats,
                logical_duplicate_prefix_bytes_avoided=sum(r['bytes'] for r in sharing) * (workers - 1),
                note='Logical copies avoided across cached modes; not a measured reduction in peak physical memory.')
        for name, sha in build['source_hashes'].items():
            if screen.digest(ROOT / name) != sha:
                raise RuntimeError('proof source changed during experiment: ' + name)
        for role, path in binaries.items():
            if screen.digest(path) != report['binary_sha256'][path.name]:
                raise RuntimeError('binary changed during experiment: ' + role)
        window['transaction_equivalents_per_hour'] = 8 * window['verified_jobs_per_hour']
        report.update(window=window, valid_comparison=window['valid_comparison'],
                      throughput_ratio=window['transaction_equivalents_per_hour']/baseline['transaction_equivalents_per_hour'],
                      target_met=window['valid_comparison'] and window['seconds'] <= target_seconds,
                      status='COMPLETE_VERIFIED_SCREEN' if window['valid_comparison'] else 'INVALID_RESOURCE_COMPARISON')
        if comparison:
            report['comparison_throughput_ratio'] = window['transaction_equivalents_per_hour']/comparison['window']['transaction_equivalents_per_hour']
        print(f'VERIFIED: {window["seconds"]:.2f}s; {window["transaction_equivalents_per_hour"]:.2f} transaction equivalents/hour; '
              f'target_met={report["target_met"]}; peak aggregate RSS={window["aggregate_peak_rss_bytes"]/GIB:.2f} GiB', flush=True)
    except BaseException as error:
        report.update(status='FAILED', failure=str(error), target_met=False)
        failure = out / 'candidate-reference/result.json'
        if failure.exists():
            report['failed_window'] = json.loads(failure.read_text())
        raise
    finally:
        cache = out / 'shared-preprocessing'
        if cache.exists():
            # The window has reaped every owned worker before returning. Preserve
            # metadata, not multi-GiB public scratch artifacts, in the report.
            report['shared_preprocessing_files'] = [{'name': p.name, 'bytes': p.stat().st_size, 'inode': p.stat().st_ino}
                                                   for p in sorted(cache.iterdir()) if p.is_file()]
            for p in cache.iterdir():
                p.unlink()
            report['shared_preprocessing_scratch_removed'] = True
        report['after'] = screen.observations()
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    main()
