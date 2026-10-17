#!/usr/bin/env python3
"""Validate the complete 128-transaction sibling-subtree aggregation comparison."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics

GIB = 1 << 30
MIB = 1 << 20


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(MIB), b''):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prefixed(lines, prefix):
    return [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]


def account(stage, ram):
    value = stage['accounting']
    events = dict(line.split() for line in value['memory.events'].splitlines())
    require(all(int(events[key]) == 0 for key in ['max', 'oom', 'oom_kill']), 'worker memory event')
    require(int(value['memory.peak']) <= int(value['memory.max']) == ram, 'worker RAM limit changed')
    require(int(value['memory.swap.max']) == int(value['memory.swap.peak']) == 0, 'worker used swap')
    require(value['cpu.max'] == '400000 100000' and value['cpuset.cpus.effective'] == '0-3',
            'worker CPU assignment changed')


def summarize(out):
    require(read(out / 'completion.json') == dict(status='completed', transactions_per_block=128,
            fresh_blocks=2, fresh_recursive_proofs=254, worker_processes=6, repetitions_per_mode=1),
            'incomplete full-block comparison')
    require(read(out / 'controller-result.json') == dict(exit_code=0, completion_receipt_exists=True),
            'controller failed')
    tests = read(out / 'tests/results.json')
    require([entry['stage'] for entry in tests] == ['compile', 'run']
            and all(entry['exit_code'] == 0 for entry in tests), 'partition source tests failed')
    require('test result: ok. 3 passed; 0 failed;' in (out / 'tests/run.log').read_text(),
            'partition test result missing')
    for file, digest in read(out / 'tests/source-manifest.json').items():
        require(sha(out / file) == digest, 'tested partition source changed')
    for name, directory in [('source-manifest.json', out), ('control-manifest.json', out / 'control'),
                            ('fixture-manifest.json', out / 'fixture'), ('support-pins.json', Path('/')),
                            ('binary-manifest.json', Path('/'))]:
        for file, digest in read(out / name).items():
            require(sha(directory / file) == digest, 'changed pinned input: ' + file)
    require(read(out / 'prior-slice.json') == read(out / 'restored-slice.json'), 'fleet RAM cap not restored')
    before, after = [read(out / ('fleet-accounting-' + name + '.json')) for name in ['before', 'after']]
    counters = [dict(line.split() for line in v['memory.events'].splitlines()) for v in [before, after]]
    require(all(counters[0][k] == counters[1][k] for k in ['max', 'oom', 'oom_kill']), 'fleet memory event')
    require(after['memory.swap.current'] == after['memory.swap.max'] == '0'
            and after['cpu.max'] == '400000 100000' and int(after['memory.max']) == 7 * GIB,
            'fleet resource bounds changed')
    calibration = read(out / 'context-calibration.json')
    require(calibration['source_trial'] == '01-sequential' and calibration['fresh_proofs'] == 127
            and calibration['sampled_peak_context_bytes'] * 1.25 <= calibration['context_allowance_bytes'] == 224 * MIB,
            'full-block context calibration failed')
    plan = read(out / 'proof-plan.json')
    require((plan['count'], plan['fresh_proofs'], plan['block_capacity'], plan['depth']) == (128, 127, 128, 7),
            'unexpected full-block plan')
    body = read(out / 'fixture/body.json')
    require(len(body['transactions']) == 128 and sum(t['kind'] == 'issuance' for t in body['transactions']) == 32,
            'unexpected transaction mix')
    assignments = {'left': [], 'right': [], 'root': []}
    planned = {}
    for task in plan['tasks']:
        match = re.fullmatch(r'node\.([1-7])\.(\d+)', task['file'])
        require(match is not None, 'malformed proof coordinate')
        level, index = map(int, match.groups())
        require(task['file'] not in planned, 'duplicate task')
        require((index + 1) * (1 << level) <= 128, 'task outside block')
        part = 'root' if level == 7 else ('left' if (index + 1) * (1 << level) <= 64 else 'right')
        assignments[part].append(task['file'])
        planned[task['file']] = task
    require({k: len(v) for k, v in assignments.items()} == {'left': 63, 'right': 63, 'root': 1},
            'not a complete balanced aggregation tree')
    require(assignments['root'] == ['node.7.0'], 'wrong root')
    stages = {item['name']: item for item in read(out / 'stages.json')}
    require(len(stages) == 10, 'expected six GPU workers and four CPU audits')
    for name, stage in stages.items():
        require(stage['exit_code'] == stage['process_timing']['exit_code'] == 0, 'failed stage: ' + name)
        require(sha(out / name / 'output.log') == stage['output_sha256'], 'changed stage log: ' + name)
        account(stage, (3 if name.startswith('prove-') else 1) * GIB)
    handoffs = read(out / 'lease-handoffs.json')
    require(not handoffs['errors'] and len(handoffs['handoffs']) == 6, 'lease handoff count or errors')
    proof_manifest, trials, workers, context_values = {}, [], [], []
    for trial in read(out / 'trials.json'):
        name, mode = trial['name'], trial['mode']
        require((name, mode) in [('01-sequential', 'sequential'), ('01-parallel', 'parallel')], 'unknown trial')
        require(trial['count'] == 128 and trial['fresh_proofs'] == 127 and trial['processes'] == 3, 'partial block')
        require(trial['managed_per_worker_bytes'] == 7064 * MIB
                and trial['context_per_worker_bytes'] == 224 * MIB
                and trial['required_free_vram_bytes'] == 14704 * MIB, 'trial GPU budget changed')
        selected = {}
        telemetry = [json.loads(line) for line in (out / (name + '-telemetry.jsonl')).read_text().splitlines()]
        require(bool(telemetry), 'no telemetry')
        proofs = out / ('proofs-' + name)
        require({p.name for p in proofs.glob('node.*')} == set(planned), 'missing or extra proof files')
        for stage_name in trial['stages']:
            stage = stages[stage_name]
            part = stage['partition']
            require(part in assignments and part not in selected, 'duplicate or unknown partition')
            expected = assignments[part]
            directory = out / stage_name
            lines = (directory / 'output.log').read_text().splitlines()
            events = [json.loads(line) for line in lines if line.startswith('{')]
            declared = [v for v in events if v.get('event') == 'aggregation_partition_plan']
            require(len(declared) == 1 and declared[0]['partition'] == part
                    and declared[0]['count'] == 128 and declared[0]['tasks'] == expected,
                    'worker selected the wrong subtree')
            nodes = [v for v in events if v.get('event') == 'fresh_typed_node']
            require([f"node.{v['level']}.{v['index']}" for v in nodes] == expected,
                    'proof execution differs from declared partition')
            for node, file in zip(nodes, expected):
                require(node['mode'] == planned[file]['mode'] and node['count'] == planned[file]['count'],
                        'wrong node statement')
                require(node['bytes'] == (proofs / file).stat().st_size, 'proof size differs from event')
                proof_manifest[str((proofs / file).relative_to(out))] = sha(proofs / file)
            receipt = read(proofs / ('result-' + part + '.json'))
            require(receipt['status'] == 'partition_proved_cpu_audit_pending' and receipt['count'] == 128
                    and receipt['fresh_proofs'] == len(expected) and receipt['aggregation_partition'] == part
                    and receipt['backend'] == 'gpu' and receipt['host_pipeline'], 'partition receipt failed')
            reports = [v for v in prefixed(lines, 'proving_stage_report ') if len(v['capabilities']['stages']) == 16]
            require(len(reports) == len(expected), 'missing GPU coverage reports')
            gpu_seconds = defaultdict(float)
            for report in reports:
                require(report['policy'] == 'gpu_required' and report['succeeded'] and report['stage_coverage_complete']
                        and not report['completion_rejected'] and report['observation_errors'] == 0,
                        'GPU proving coverage failed')
                require(all(v['backend'] == 'open_cl' for v in report['capabilities']['stages']), 'CPU proving fallback')
                for observation in report['observations']:
                    gpu_seconds[observation['stage']] += observation['device_ns'] / 1e9
            specialized = [line for line in lines if line.startswith('bounded_gpu_quotient_specialization selected=true ')]
            executions = [line for line in lines if line.startswith('bounded_gpu_quotient_specialized_execution ')]
            require(len(specialized) == len(executions) == len(expected), 'specialized quotient not executed for every proof')
            require(all('research_context=true' in line and 'driver_reserve_bytes=234881024' in line
                        and int(re.search(r'resident_private_bound_bytes=(\d+)', line)[1]) <= 64 * MIB
                        for line in specialized), 'specialization context/private bounds changed')
            require('bounded_gpu_shutdown managed_live_bytes=0 lease_released=true' in lines, 'unclean GPU shutdown')
            contexts = prefixed(lines, 'bounded_gpu_context ')
            pids = {c['pid'] for c in contexts}
            require(pids == {stage['process_timing']['pid']}, 'worker PID differs from telemetry')
            pid = next(iter(pids))
            require(sum(v['pid'] == pid and v['unit'] == stage['unit'] for v in handoffs['handoffs']) == 1,
                    'missing device lease transfer')
            require(max(c['context_bytes'] for c in contexts) <= 224 * MIB
                    and all(c['process_bytes'] <= c['limit_bytes'] == (7064 + 224) * MIB for c in contexts),
                    'worker exceeded GPU allowance')
            if mode == 'sequential':
                context_values.extend(c['context_bytes'] for c in contexts)
            budget = read(directory / 'budget.json')
            require(budget['gpu']['managed_bytes'] == 7064 * MIB and budget['gpu']['context_bytes'] == 224 * MIB
                    and budget['gpu']['max_allocation_bytes'] == GIB and budget['host']['fleet_bytes'] == 7 * GIB
                    and budget['lde_workspace_bytes'] == 0, 'worker budget differs')
            lde = prefixed(lines, 'bounded_gpu_lde_plan ')
            require(bool(lde) and all(v['predicted_managed_peak_bytes'] <= v['managed_cap_bytes'] == 7064 * MIB for v in lde),
                    'managed GPU reservation bound failed')
            resident = [p['used_mib'] for s in telemetry for p in s['gpu']['compute_processes'] if p['pid'] == pid]
            require(bool(resident), 'no resident worker samples')
            timing = stage['process_timing']
            worker = dict(name=stage_name, trial=name, partition=part, pid=pid, fresh_proofs=len(expected),
                process_seconds=timing['elapsed_seconds'], process_timing=timing,
                worker_ram_peak_bytes=int(stage['accounting']['memory.peak']),
                sampled_worker_vram_peak_mib=max(resident), sampled_context_peak_bytes=max(c['context_bytes'] for c in contexts),
                specialized_quotient_proofs=len(specialized), gpu_device_seconds_by_stage=dict(gpu_seconds))
            selected[part] = worker
            workers.append(worker)
        require(set(selected) == {'left', 'right', 'root'}, 'incomplete partitions')
        times = [v['process_timing'] for v in selected.values()]
        subtrees = [selected[k]['process_timing'] for k in ['left', 'right']]
        root = selected['root']['process_timing']
        require(root['start_monotonic_ns'] >= max(t['end_monotonic_ns'] for t in subtrees),
                'root started before both sibling proofs finished')
        elapsed = (root['end_monotonic_ns'] - min(t['start_monotonic_ns'] for t in subtrees)) / 1e9
        subtree_span = (max(t['end_monotonic_ns'] for t in subtrees) - min(t['start_monotonic_ns'] for t in subtrees)) / 1e9
        overlap = max(0, sum(t['elapsed_seconds'] for t in subtrees) - subtree_span)
        require(abs(elapsed - trial['primary_proving_seconds']) < 1e-6
                and abs(subtree_span - trial['subtree_makespan_seconds']) < 1e-6
                and abs(overlap - trial['subtree_overlap_seconds']) < 1e-6, 'trial timing mismatch')
        require((overlap > 0) == (mode == 'parallel'), 'unexpected worker process overlap')
        pids = {v['pid'] for v in selected.values()}
        sibling_pids = {selected[k]['pid'] for k in ['left', 'right']}
        simultaneous = [s for s in telemetry if sibling_pids <= {p['pid'] for p in s['gpu']['compute_processes'] if p['used_mib'] > 0}]
        require((len(simultaneous) > 1) == (mode == 'parallel'), 'unexpected GPU residency overlap')
        preflight = read(out / (name + '-preflight.json'))
        prior_pids = {p['pid'] for p in preflight['compute_processes']}
        extra_pids = {p['pid'] for s in telemetry for p in s['gpu']['compute_processes']} - pids - prior_pids
        require(not extra_pids and min(s['gpu']['free_mib'] for s in telemetry) >= 128, 'GPU coexistence reserve violated')
        audit = read(out / ('audit-' + name) / 'summary.json')
        require(audit['status'] == 'succeeded' and audit['count'] == 128 and audit['cpu_audited_nodes'] == 127
                and any('journal recovery reverified every wallet and node' in check for check in audit['checks']),
                'complete CPU/journal audit failed')
        root_lines = (out / ('audit-root-' + name) / 'output.log').read_text().splitlines()
        root_events = [json.loads(line) for line in root_lines if line.startswith('{')]
        require(any(v.get('event') == 'independent_cpu_root_audit' and v.get('passed')
                    and v['count'] == v['block_capacity'] == 128 for v in root_events), 'root-only CPU verification failed')
        trials.append(dict(**trial, transactions_per_second=128 / elapsed, user_transactions_per_second=96 / elapsed,
            sampled_combined_worker_vram_peak_mib=max(sum(p['used_mib'] for p in s['gpu']['compute_processes'] if p['pid'] in pids) for s in telemetry),
            sampled_device_vram_peak_mib=max(s['gpu']['used_mib'] for s in telemetry),
            sampled_free_vram_min_mib=min(s['gpu']['free_mib'] for s in telemetry),
            sampled_combined_worker_ram_peak_bytes=max(sum(int(v.get('memory.current', 0)) for v in s['workers'].values()) for s in telemetry),
            sampled_fleet_ram_peak_bytes=max(s['fleet_memory_current'] for s in telemetry),
            max_worker_ram_bytes=max(v['worker_ram_peak_bytes'] for v in selected.values()),
            mean_gpu_utilization_percent=statistics.mean(s['gpu']['gpu_percent'] for s in telemetry),
            mean_memory_controller_utilization_percent=statistics.mean(s['gpu']['memory_percent'] for s in telemetry),
            gpu_residency_overlap_samples=len(simultaneous), additional_compute_pids=sorted(extra_pids),
            cpu_audit_seconds=sum(stages[prefix + name]['process_timing']['elapsed_seconds'] for prefix in ['audit-root-', 'audit-all-']),
            root_bytes=(proofs / 'node.7.0').stat().st_size, root_sha256=sha(proofs / 'node.7.0'), cpu_audit=audit))
    require(len(trials) == 2 and {t['mode'] for t in trials} == {'sequential', 'parallel'}, 'incomplete comparison')
    require(len(proof_manifest) == len(set(proof_manifest.values())) == 254, 'missing or reused proof output')
    require(max(context_values) == calibration['sampled_peak_context_bytes']
            and len(context_values) == calibration['checkpoints'], 'calibration receipt differs from checkpoints')
    by_mode = {v['mode']: v for v in trials}
    ratio = by_mode['sequential']['primary_proving_seconds'] / by_mode['parallel']['primary_proving_seconds']
    summary = dict(schema='lattica-gpu-parallel-aggregation-v1', status='passed', evidence_directory=str(out),
        scope='One complete 128-transaction block per mode, with 96 user and 32 issuance transactions. Two sibling 64-transaction subtrees feed one final root.',
        repetitions_per_mode=1, fresh_blocks=2, fresh_recursive_proofs=254, worker_processes=6,
        throughput_ratio=ratio, throughput_change_percent=100 * (ratio - 1),
        block_time_change_percent=100 * (1 / ratio - 1), trials=trials, workers=workers,
        hardware=read(out / 'hardware.json'), context_calibration=calibration,
        limits=dict(managed_vram_per_worker_bytes=7064 * MIB, context_vram_per_worker_bytes=224 * MIB,
                    shared_gpu_headroom_bytes=128 * MIB, max_gpu_buffer_bytes=GIB, worker_ram_bytes=3 * GIB,
                    aggregate_ram_bytes=7 * GIB, aggregate_cpu_quota_percent=400, allowed_cpus=[0, 1, 2, 3],
                    rayon_threads_per_worker=4, swap_bytes=0, scratch_cache_bytes=0),
        validation='All 254 fresh recursive proofs, all selected wallets, both root-only proofs, and both durable journal replays passed independent CPU verification. All proving stages used OpenCL and all quotient proofs used specialized kernels.',
        limitations=['One complete block per mode, sequential first; exploratory comparison, not sustained-throughput qualification.',
            'Both modes use the same three-process plan: left subtree, right subtree, then root. This is not a fresh comparison against a monolithic single-process prover.',
            'Each process authenticates the complete wallet fixture. Wallet generation, key generation, GPU admission waits, and independent CPU audits are excluded from proving time.',
            'Static balanced subtree partitioning on one GPU; no dynamic work stealing, cross-device scheduling, or simultaneous-kernel profiling.',
            'The 224 MiB context admission is isolated research, calibrated by the complete sequential block, and not a new production default.',
            'VRAM and combined RAM peaks are sampled. Individual worker RAM peaks come from cgroups. The GPU also serves the desktop.',
            'The first copied incremental build reused stale external-driver dep-info. Its unchanged binary was never run; a clean isolated package rebuild produced the measured binary.'],
        manifests={name:sha(out / name) for name in ['source-manifest.json', 'control-manifest.json', 'fixture-manifest.json',
                   'support-pins.json', 'binary-manifest.json', 'scope.json', 'patch-reconstruction.json', 'tests/source-manifest.json', 'tests/results.json', 'tests/run.log']},
        reporter_source_sha256=sha(__file__))
    (out / 'proof-manifest.json').write_text(json.dumps(proof_manifest, indent=2) + '\n')
    summary['manifests']['proof-manifest.json'] = sha(out / 'proof-manifest.json')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(dict(throughput_change_percent=summary['throughput_change_percent'],
        block_time_change_percent=summary['block_time_change_percent'],
        trials=[{k:t[k] for k in ['mode', 'primary_proving_seconds', 'transactions_per_second',
            'sampled_combined_worker_vram_peak_mib', 'sampled_combined_worker_ram_peak_bytes', 'cpu_audit_seconds']} for t in trials]), indent=2))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    summarize(parser.parse_args().output.resolve())
