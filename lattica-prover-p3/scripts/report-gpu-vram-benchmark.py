#!/usr/bin/env python3
"""Reconcile the VRAM comparison with independent CPU audits and saved telemetry."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def summarize(out):
    config = read(out / 'config.json')
    require(read(out / 'completion.json')['status'] == 'completed', 'missing completed experiment')
    require(read(out / 'controller-result.json') == {'exit_code': 0, 'completion_receipt_exists': True},
            'controller did not complete')
    for name, digest in read(out / 'source-pins.json').items():
        require(sha(name) == digest, 'source receipt changed: ' + name)
    if (out / 'control-manifest.json').exists():
        for name, digest in read(out / 'control-manifest.json').items():
            require(sha(out / 'control' / name) == digest, 'experiment control changed: ' + name)
    source = Path(config['source_run'])
    for name, digest in read(source / 'source-manifest.json').items():
        require(sha(source / name) == digest, 'pinned source changed: ' + name)
    for name, digest in read(out / 'binary-manifest.json').items():
        require(sha(name) == digest, 'binary changed: ' + name)
    for name, digest in read(out / 'fixture-manifest.json').items():
        require(sha(out / 'fixture' / name) == digest, 'fixture changed: ' + name)
    stages = {s['name']: s for s in read(out / 'stages.json')}
    for name, s in stages.items():
        require(s['exit_code'] == 0 and not s['interrupted'], 'failed stage: ' + name)
        require(sha(out / name / 'output.log') == s['output_sha256'], 'stage output changed: ' + name)
        a = s['accounting']
        counts = dict(line.split() for line in a['memory.events'].splitlines())
        require(all(int(counts[k]) == 0 for k in ['max', 'oom', 'oom_kill']), 'memory events: ' + name)
        require(int(a['memory.swap.peak']) == 0 and int(a['memory.peak']) <= int(a['memory.max']),
                'RAM/swap bound failed: ' + name)
        require(s['process_timing']['exit_code'] == 0, 'process failed: ' + name)
    plan = read(out / 'proof-plan.json')
    body = read(out / 'fixture/body.json')
    proof_manifest = {}
    trials = []
    for trial in config['trials']:
        name = trial['name']
        directory = out / ('prove-' + name)
        proof_dir = out / ('proofs-' + name)
        result = read(proof_dir / 'result.json')
        require(result['count'] == config['count'] and result['fresh_proofs'] == plan['fresh_proofs']
                and result['backend'] == 'gpu' and result['host_pipeline'], 'wrong proof scope: ' + name)
        log = (directory / 'output.log').read_text()
        lines = log.splitlines()
        events = [json.loads(line) for line in lines if line.startswith('{')]
        nodes = [v for v in events if v.get('event') == 'fresh_typed_node']
        reports = [json.loads(line.split(' ', 1)[1]) for line in lines if line.startswith('proving_stage_report ')]
        reports = [v for v in reports if len(v['capabilities']['stages']) == 16]
        require(len(nodes) == len(reports) == plan['fresh_proofs'], 'incomplete GPU proof reports: ' + name)
        for report in reports:
            require(report['policy'] == 'gpu_required' and report['succeeded'] and report['stage_coverage_complete']
                    and not report['completion_rejected'] and report['observation_errors'] == 0,
                    'GPU proof report failed: ' + name)
            require(all(s['backend'] == 'open_cl' for s in report['capabilities']['stages']),
                    'GPU arithmetic coverage changed: ' + name)
        require('bounded_gpu_shutdown managed_live_bytes=0 lease_released=true' in log,
                'GPU teardown missing: ' + name)
        audit = read(out / ('audit-' + name) / 'summary.json')
        require(audit['status'] == 'succeeded' and audit['count'] == config['count']
                and audit['cpu_audited_nodes'] == plan['fresh_proofs'], 'CPU node audit incomplete: ' + name)
        root_events = [json.loads(line) for line in (out / ('audit-root-' + name) / 'output.log').read_text().splitlines()
                       if line.startswith('{')]
        require(any(v.get('event') == 'independent_cpu_root_audit' and v.get('passed') for v in root_events),
                'CPU root audit failed: ' + name)
        pids = {json.loads(line.split(' ', 1)[1])['pid'] for line in lines if line.startswith('bounded_gpu_context ')}
        require(len(pids) == 1, 'ambiguous GPU worker: ' + name)
        pid = next(iter(pids))
        telemetry = [json.loads(line) for line in (directory / 'telemetry.jsonl').read_text().splitlines()]
        samples = [v['gpu'] for v in telemetry if 'gpu' in v]
        worker_memory = [p['used_mib'] for sample in samples for p in sample['compute_processes'] if p['pid'] == pid]
        require(bool(worker_memory), 'no GPU memory samples: ' + name)
        gpu_stages = defaultdict(float)
        for report in reports:
            for observation in report['observations']:
                gpu_stages[observation['stage']] += observation['device_ns'] / 1e9
        lde_plans = [json.loads(line.split(' ', 1)[1]) for line in lines if line.startswith('bounded_gpu_lde_plan ')]
        tiles = Counter((tuple((v['rows'], v['columns'], v['added_bits']) for v in p['inputs']), p['columns_per_tile'])
                        for p in lde_plans)
        budget = read(directory / 'budget.json')
        selected = config['variants'][trial['variant']]
        require(budget['gpu']['managed_bytes'] == selected['managed_bytes']
                and budget['gpu']['max_allocation_bytes'] == selected['max_allocation_bytes']
                and budget['lde_workspace_bytes'] == selected['workspace_bytes'], 'variant budget changed: ' + name)
        preflight = read(directory / 'gpu-preflight.json')
        prior_pids = {p['pid'] for p in preflight['compute_processes']}
        extra_pids = sorted({p['pid'] for sample in samples for p in sample['compute_processes']
                             if p['pid'] not in prior_pids and p['pid'] != pid})
        for p in lde_plans:
            require(p['managed_cap_bytes'] == budget['gpu']['managed_bytes']
                    and p['max_allocation_bytes'] == budget['gpu']['max_allocation_bytes']
                    and p['predicted_managed_peak_bytes'] <= p['managed_cap_bytes'], 'LDE limit mismatch: ' + name)
        cache = re.findall(r'bounded_lde_workspace retained_bytes=(\d+) reused=(true|false)', log)
        for task in plan['tasks']:
            path = proof_dir / task['file']
            proof_manifest[str(path.relative_to(out))] = sha(path)
        root = proof_dir / f"node.{plan['depth']}.0"
        stage = stages['prove-' + name]
        seconds = stage['process_timing']['elapsed_seconds']
        trials.append(dict(**trial, process_seconds=seconds, internal_proving_seconds=result['seconds'],
            total_transactions_per_second=config['count'] / seconds,
            cpu_audit_seconds=sum(stages[prefix + name]['process_timing']['elapsed_seconds']
                                 for prefix in ['audit-root-', 'audit-all-']),
            gpu_initialization_seconds=next(v['gpu_initialization_seconds'] for v in events
                                           if v.get('event') == 'capacity_benchmark_complete'),
            gpu_device_seconds_by_stage=dict(gpu_stages),
            worker_cgroup_peak_bytes=int(stage['accounting']['memory.peak']),
            sampled_worker_vram_peak_mib=max(worker_memory), sampled_device_vram_peak_mib=max(s['used_mib'] for s in samples),
            mean_gpu_utilization_percent=statistics.mean(s['gpu_percent'] for s in samples),
            mean_memory_controller_utilization_percent=statistics.mean(s['memory_percent'] for s in samples),
            sampled_fleet_peak_bytes=max(s.get('fleet_memory_current', 0) for s in telemetry),
            additional_gpu_processes_during_trial=extra_pids,
            gpu_proof_reports=len(reports), cpu_audited_nodes=audit['cpu_audited_nodes'],
            root_sha256=sha(root), root_bytes=root.stat().st_size,
            cache_retention_events=len(cache), cache_reuse_events=sum(reused == 'true' for _, reused in cache),
            cache_largest_retained_bytes=max([int(n) for n, _ in cache] or [0]),
            node_times=[{k:v[k] for k in ['mode','level','count','seconds']} for v in nodes],
            transform_tiles=[dict(inputs=k[0], columns_per_tile=k[1], calls=v) for k,v in tiles.items()]))
    require(len({t['root_sha256'] for t in trials}) == len(trials), 'proof roots must be fresh')
    measured = [t for t in trials if t['measured']]
    aggregates = {}
    baseline_by_repeat = {t['name'].split('-')[0]:t['process_seconds'] for t in measured if t['variant'] == 'baseline'}
    for variant in config['variants']:
        selected = [t for t in measured if t['variant'] == variant]
        require(len(selected) == config['repetitions'], 'incomplete variant: ' + variant)
        differences = [100 * (1 - t['process_seconds'] / baseline_by_repeat[t['name'].split('-')[0]]) for t in selected]
        aggregates[variant] = dict(trials=len(selected), median_process_seconds=statistics.median(t['process_seconds'] for t in selected),
            process_seconds=[t['process_seconds'] for t in selected], within_round_time_reduction_percent=differences,
            median_within_round_time_reduction_percent=statistics.median(differences),
            peak_worker_ram_bytes=max(t['worker_cgroup_peak_bytes'] for t in selected),
            sampled_peak_worker_vram_mib=max(t['sampled_worker_vram_peak_mib'] for t in selected),
            cache_reuse_events=sum(t['cache_reuse_events'] for t in selected))
    summary = dict(schema='lattica-gpu-vram-benchmark-v1', status='passed', scope=config['scope'],
                   count=config['count'], block_capacity=128, recursive_proofs_per_trial=plan['fresh_proofs'],
                   user_transactions=sum(tx['kind'] != 'issuance' for tx in body['transactions']),
                   variants=config['variants'], trials=trials, aggregates=aggregates,
                   hardware=read(out / 'hardware.json')['device'], evidence_directory=str(out),
                   validation='All selected wallets and recursive nodes independently CPU verified; root-only verification and durable journal replay passed for every trial.',
                   limits=dict(worker_ram_bytes=3 << 30, coordinator_ram_bytes=1 << 30, aggregate_ram_bytes=4 << 30,
                               cpu_threads=4, swap_bytes=0, gpu_context_allowance_bytes=4 << 30, gpu_headroom_bytes=1 << 30),
                   limitations=['Small fixed-fixture standalone comparison, not a full 128-transaction timing or sustained throughput qualification.',
                                'Two opposite trial orders reduce order effects; the sample is too small for a general performance guarantee.',
                                'RAM uses cgroup peaks; GPU memory and utilization are sampled.',
                                'Production settings are unchanged.'],
                   source_manifest_sha256=sha(source / 'source-manifest.json'), binary_manifest_sha256=sha(out / 'binary-manifest.json'))
    summary['reporter_source_sha256'] = sha(__file__)
    if (out / 'control-manifest.json').exists():
        summary['control_manifest_sha256'] = sha(out / 'control-manifest.json')
    (out / 'proof-manifest.json').write_text(json.dumps(proof_manifest, indent=2) + '\n')
    summary['proof_manifest_sha256'] = sha(out / 'proof-manifest.json')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(aggregates, indent=2))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    summarize(args.output.resolve())
