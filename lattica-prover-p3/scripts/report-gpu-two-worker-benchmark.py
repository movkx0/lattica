#!/usr/bin/env python3
"""Validate and summarize the isolated same-GPU two-worker comparison."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics


def read(path):
    return json.loads(path.read_text())


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prefixed(lines, prefix):
    return [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]


def summarize(out):
    scope = read(out / 'scope.json') if (out / 'scope.json').exists() else {}
    completion = read(out / 'completion.json')
    measured_pairs = completion.get('measured_pairs', 0)
    require(completion == dict(status='completed', workers=2, transactions_per_worker=8,
            measured_pairs=measured_pairs) and type(measured_pairs) is int
            and 2 <= measured_pairs <= 10 and measured_pairs % 2 == 0, 'incomplete experiment')
    repetitions = measured_pairs // 2
    expected_runs = 2 + 2 * measured_pairs
    require(read(out / 'controller-result.json') == dict(exit_code=0, completion_receipt_exists=True),
            'controller failed')
    for manifest, directory in [('source-manifest.json', out),
                                ('control-manifest.json', out / 'control'),
                                ('fixture-manifest.json', out / 'fixture')]:
        for name, digest in read(out / manifest).items():
            require(sha(directory / name) == digest, 'changed pinned input: ' + name)
    for manifest in ['support-pins.json', 'binary-manifest.json']:
        for name, digest in read(out / manifest).items():
            require(sha(name) == digest, 'changed support or binary: ' + name)
    require(read(out / 'prior-slice.json') == read(out / 'restored-slice.json'),
            'fleet RAM limit was not restored')
    fleet_before, fleet_after = [read(out / ('fleet-accounting-' + when + '.json')) for when in ['before', 'after']]
    before_counts, after_counts = [dict(line.split() for line in v['memory.events'].splitlines())
                                   for v in [fleet_before, fleet_after]]
    require(all(before_counts[k] == after_counts[k] for k in ['max', 'oom', 'oom_kill']),
            'aggregate memory-limit or OOM event during experiment')
    require(fleet_after['memory.swap.current'] == fleet_after['memory.swap.max'] == '0'
            and fleet_after['cpu.max'] == '400000 100000' and int(fleet_after['memory.max']) == 7 << 30,
            'aggregate resource bounds changed')
    calibration = read(out / 'context-calibration.json')
    require(calibration['checkpoints'] > 0 and
            calibration['sampled_peak_context_bytes'] * 1.25 <= calibration['context_allowance_bytes'],
            'insufficient calibrated context margin')
    stages = {v['name']: v for v in read(out / 'stages.json')}
    require(len(stages) == 3 * expected_runs, 'expected one GPU stage and two CPU audits per run')
    for name, stage in stages.items():
        require(stage['exit_code'] == stage['process_timing']['exit_code'] == 0, 'stage failed: ' + name)
        require(sha(out / name / 'output.log') == stage['output_sha256'], 'changed stage output: ' + name)
        account = stage['accounting']
        events = dict(line.split() for line in account['memory.events'].splitlines())
        require(all(int(events[key]) == 0 for key in ['max', 'oom', 'oom_kill']), 'worker memory event: ' + name)
        require(int(account['memory.swap.peak']) == int(account['memory.swap.max']) == 0,
                'worker swap bound failed: ' + name)
        expected_cap = (3 if name.startswith('prove-') else 1) << 30
        require(int(account['memory.peak']) <= int(account['memory.max']) == expected_cap,
                'worker RAM bound failed: ' + name)
        require(account['cpu.max'] == '400000 100000' and account['cpuset.cpus.effective'] == '0-3',
                'worker CPU assignment changed: ' + name)
    plan = read(out / 'proof-plan.json')
    require((plan['count'], plan['fresh_proofs'], plan['block_capacity'], plan['depth']) == (8, 8, 128, 7),
            'unexpected proof scope')
    body = read(out / 'fixture/body.json')
    require(len(body['transactions']) == 8, 'unexpected transaction count')
    user_count = sum(t['kind'] != 'issuance' for t in body['transactions'])
    handoffs = read(out / 'lease-handoffs.json')
    require(not handoffs['errors'] and len(handoffs['handoffs']) == expected_runs, 'lease transfers incomplete')
    proof_manifest, trials, pairs = {}, [], []
    for pair in read(out / 'pairs.json'):
        selected = []
        telemetry = [json.loads(line) for line in (out / (pair['name'] + '-telemetry.jsonl')).read_text().splitlines()]
        require(bool(telemetry), 'missing GPU samples: ' + pair['name'])
        for name in pair['stages']:
            stage = stages[name]
            job = name.removeprefix('prove-')
            proof_dir = out / ('proofs-' + job)
            result = read(proof_dir / 'result.json')
            require(result['count'] == result['fresh_proofs'] == 8 and result['backend'] == 'gpu'
                    and result['host_pipeline'], 'wrong proof result: ' + name)
            log = (out / name / 'output.log').read_text()
            lines = log.splitlines()
            events = [json.loads(line) for line in lines if line.startswith('{')]
            nodes = [event for event in events if event.get('event') == 'fresh_typed_node']
            reports = [v for v in prefixed(lines, 'proving_stage_report ')
                       if len(v['capabilities']['stages']) == 16]
            require(len(nodes) == len(reports) == 8, 'incomplete recursive proof reports: ' + name)
            specialized = [line for line in lines
                           if line.startswith('bounded_gpu_quotient_specialization selected=true ')]
            specialized_executions = [line for line in lines
                                     if line.startswith('bounded_gpu_quotient_specialized_execution ')]
            require(len(specialized) == len(specialized_executions),
                    'specialized quotient execution checkpoint missing: ' + name)
            expected_specialized = scope.get('expected_specialized_quotients_per_worker')
            if expected_specialized is not None:
                require(len(specialized) == expected_specialized, 'specialization coverage changed: ' + name)
            private_bounds = [int(re.search(r'resident_private_bound_bytes=(\d+)', line)[1])
                              for line in specialized]
            if expected_specialized is not None and pair['context_per_worker_bytes'] < 4 << 30:
                require(all('research_context=true' in line for line in specialized)
                        and max(private_bounds, default=0) <= 64 << 20,
                        'research specialization private memory bound failed: ' + name)
            gpu_seconds = defaultdict(float)
            for report in reports:
                require(report['policy'] == 'gpu_required' and report['succeeded'] and report['stage_coverage_complete']
                        and not report['completion_rejected'] and report['observation_errors'] == 0,
                        'GPU proof coverage failed: ' + name)
                require(all(v['backend'] == 'open_cl' for v in report['capabilities']['stages']),
                        'non-OpenCL proving stage: ' + name)
                for observation in report['observations']:
                    gpu_seconds[observation['stage']] += observation['device_ns'] / 1e9
            require('bounded_gpu_shutdown managed_live_bytes=0 lease_released=true' in log,
                    'unclean GPU teardown: ' + name)
            contexts = prefixed(lines, 'bounded_gpu_context ')
            pids = {v['pid'] for v in contexts}
            require(len(pids) == 1, 'ambiguous GPU worker: ' + name)
            pid = next(iter(pids))
            require(pid == stage['process_timing']['pid'], 'timed process was not the GPU worker: ' + name)
            require(sum(v['pid'] == pid and v['unit'] == stage['unit'] for v in handoffs['handoffs']) == 1,
                    'missing controller lease transfer: ' + name)
            budget = read(out / name / 'budget.json')
            require(budget['gpu']['managed_bytes'] == pair['managed_per_worker_bytes']
                    and budget['gpu']['context_bytes'] == pair['context_per_worker_bytes']
                    and budget['gpu']['max_allocation_bytes'] == 1 << 30
                    and budget['host']['fleet_bytes'] == 7 << 30 and budget['lde_workspace_bytes'] == 0,
                    'unexpected proving budget: ' + name)
            require(max(c['context_bytes'] for c in contexts) <= pair['context_per_worker_bytes'],
                    'context exceeded allowance: ' + name)
            lde = prefixed(lines, 'bounded_gpu_lde_plan ')
            require(bool(lde) and all(v['predicted_managed_peak_bytes'] <= v['managed_cap_bytes'] ==
                    pair['managed_per_worker_bytes'] for v in lde), 'managed GPU bound failed: ' + name)
            audit = read(out / ('audit-' + job) / 'summary.json')
            require(audit['status'] == 'succeeded' and audit['count'] == audit['cpu_audited_nodes'] == 8
                    and any('journal recovery reverified' in check for check in audit['checks']),
                    'CPU node/journal audit incomplete: ' + name)
            root_events = [json.loads(line) for line in (out / ('audit-root-' + job) / 'output.log').read_text().splitlines()
                           if line.startswith('{')]
            require(any(v.get('event') == 'independent_cpu_root_audit' and v.get('passed')
                        and v['count'] == 8 and v['block_capacity'] == 128 for v in root_events),
                    'CPU root verification failed: ' + name)
            memory = [p['used_mib'] for sample in telemetry for p in sample['gpu']['compute_processes'] if p['pid'] == pid]
            require(bool(memory) and max(memory) > 0, 'no resident GPU samples: ' + name)
            for task in plan['tasks']:
                path = proof_dir / task['file']
                proof_manifest[str(path.relative_to(out))] = sha(path)
            root = proof_dir / 'node.7.0'
            timing = stage['process_timing']
            trial = dict(name=name, pair=pair['name'], mode=pair['mode'], measured=pair['measured'], pid=pid,
                         process_seconds=timing['elapsed_seconds'], internal_proving_seconds=result['seconds'],
                         cpu_seconds=timing['user_seconds'] + timing['system_seconds'],
                         worker_ram_peak_bytes=int(stage['accounting']['memory.peak']),
                         sampled_worker_vram_peak_mib=max(memory), sampled_context_peak_bytes=max(c['context_bytes'] for c in contexts),
                         gpu_device_seconds_by_stage=dict(gpu_seconds), gpu_proof_reports=len(reports),
                         specialized_quotient_proofs=len(specialized),
                         generic_quotient_proofs=len(reports) - len(specialized),
                         max_specialized_private_backing_bound_bytes=max(private_bounds, default=0),
                         cpu_audited_nodes=audit['cpu_audited_nodes'], root_bytes=root.stat().st_size, root_sha256=sha(root),
                         cpu_audit_seconds=sum(stages[prefix + job]['process_timing']['elapsed_seconds']
                                              for prefix in ['audit-root-', 'audit-all-']))
            trials.append(trial)
            selected.append(trial)
        require(len(selected) == pair['workers'], 'incomplete pair: ' + pair['name'])
        times = [stages[t['name']]['process_timing'] for t in selected]
        total = sum(t['elapsed_seconds'] for t in times)
        makespan = (max(t['end_monotonic_ns'] for t in times) - min(t['start_monotonic_ns'] for t in times)) / 1e9
        overlap = max(0, total - makespan)
        require(abs(pair['pair_makespan_seconds'] - makespan) < 1e-6
                and abs(pair['sum_worker_seconds'] - total) < 1e-6, 'pair timing mismatch')
        seconds = total if pair['mode'] == 'sequential' else makespan
        require(abs(pair['primary_proving_seconds'] - seconds) < 1e-6, 'primary timing mismatch')
        pids = {t['pid'] for t in selected}
        simultaneous = [s for s in telemetry if pids <= {p['pid'] for p in s['gpu']['compute_processes'] if p['used_mib'] > 0}]
        if pair['mode'] == 'concurrent':
            require(overlap > 0 and len(simultaneous) > 1, 'workers never overlapped on GPU')
        elif pair['workers'] == 2:
            require(overlap == 0 and not simultaneous, 'sequential workers overlapped')
        preflight = read(out / (pair['name'] + '-preflight.json'))
        prior_pids = {p['pid'] for p in preflight['compute_processes']}
        extra_pids = {p['pid'] for s in telemetry for p in s['gpu']['compute_processes']} - pids - prior_pids
        require(not extra_pids, 'another compute process appeared')
        free = min(s['gpu']['free_mib'] for s in telemetry)
        require(free >= 128, 'GPU free reserve violated')
        pairs.append(dict(**pair, transactions_per_second=8 * pair['workers'] / seconds,
                          user_transactions_per_second=user_count * pair['workers'] / seconds,
                          sampled_combined_worker_vram_peak_mib=max(sum(p['used_mib'] for p in s['gpu']['compute_processes']
                                                                 if p['pid'] in pids) for s in telemetry),
                          sampled_device_vram_peak_mib=max(s['gpu']['used_mib'] for s in telemetry),
                          sampled_free_vram_min_mib=free,
                          sampled_fleet_ram_peak_bytes=max(s['fleet_memory_current'] for s in telemetry),
                          sampled_combined_worker_ram_peak_bytes=max(sum(int(v.get('memory.current', 0))
                                                                      for v in s['workers'].values()) for s in telemetry),
                          mean_gpu_utilization_percent=statistics.mean(s['gpu']['gpu_percent'] for s in telemetry),
                          mean_memory_controller_utilization_percent=statistics.mean(s['gpu']['memory_percent'] for s in telemetry),
                          gpu_residency_overlap_samples=len(simultaneous),
                          gpu_residency_overlap_sample_span_seconds=(simultaneous[-1]['monotonic_ns'] - simultaneous[0]['monotonic_ns']) / 1e9
                          if simultaneous else 0, summed_worker_cpu_seconds=sum(t['cpu_seconds'] for t in selected),
                          additional_compute_pids=sorted(extra_pids)))
    require(len(trials) == len({t['root_sha256'] for t in trials}) == expected_runs, 'missing or reused proof roots')
    require(len(pairs) == measured_pairs + 2, 'incomplete run order')
    measured_budgets = {(p['managed_per_worker_bytes'], p['context_per_worker_bytes']) for p in pairs if p['measured']}
    require(len(measured_budgets) == 1, 'measured pairs used different budgets')
    managed_bytes, context_bytes = next(iter(measured_budgets))
    aggregates = {}
    for mode in ['sequential', 'concurrent']:
        selected = [p for p in pairs if p['measured'] and p['mode'] == mode]
        selected_trials = [t for t in trials if t['measured'] and t['mode'] == mode]
        require(len(selected) == repetitions and len(selected_trials) == 2 * repetitions, 'incomplete measured repetitions')
        seconds = statistics.median(p['primary_proving_seconds'] for p in selected)
        aggregates[mode] = dict(pairs=len(selected), pair_seconds=[p['primary_proving_seconds'] for p in selected],
            median_pair_seconds=seconds, worst_pair_seconds=max(p['primary_proving_seconds'] for p in selected),
            transactions_per_second=16 / seconds, user_transactions_per_second=2 * user_count / seconds,
            median_worker_latency_seconds=statistics.median(t['process_seconds'] for t in selected_trials),
            sampled_combined_worker_vram_peak_mib=max(p['sampled_combined_worker_vram_peak_mib'] for p in selected),
            sampled_device_vram_peak_mib=max(p['sampled_device_vram_peak_mib'] for p in selected),
            sampled_combined_worker_ram_peak_bytes=max(p['sampled_combined_worker_ram_peak_bytes'] for p in selected),
            sampled_fleet_ram_peak_bytes=max(p['sampled_fleet_ram_peak_bytes'] for p in selected),
            max_worker_ram_bytes=max(t['worker_ram_peak_bytes'] for t in selected_trials))
    speedup = aggregates['sequential']['median_pair_seconds'] / aggregates['concurrent']['median_pair_seconds']
    reference = next(t for t in trials if t['name'] == 'prove-standard-w0')
    reference_tps = 8 / reference['process_seconds']
    reference_comparison = dict(process_seconds=reference['process_seconds'], transactions_per_second=reference_tps,
        specialized_quotient_proofs=reference['specialized_quotient_proofs'],
        concurrent_throughput_ratio=aggregates['concurrent']['transactions_per_second'] / reference_tps,
        scope='One unmeasured standard-budget reference; not a replicated standard-budget pair comparison.')
    matched = []
    for repeat in [f'{index:02d}' for index in range(1, repetitions + 1)]:
        sequential = next(p for p in pairs if p['name'] == repeat + '-sequential')
        concurrent = next(p for p in pairs if p['name'] == repeat + '-concurrent')
        matched.append(dict(round=int(repeat), throughput_ratio=sequential['primary_proving_seconds'] / concurrent['primary_proving_seconds']))
    summary = dict(schema='lattica-gpu-two-worker-benchmark-v1', status='passed', evidence_directory=str(out),
        scope='Two independent complete 8-transaction depth-seven block proofs on one GPU; 128-capacity profile.',
        transactions_per_worker=8, user_transactions_per_worker=user_count, issuance_transactions_per_worker=8-user_count,
        measured_pairs=measured_pairs, total_worker_runs=expected_runs, cpu_audited_recursive_proofs=8 * expected_runs,
        aggregates=aggregates, throughput_ratio=speedup, throughput_change_percent=100 * (speedup - 1),
        standard_single_worker_reference=reference_comparison,
        pair_time_reduction_percent=100 * (1 - 1 / speedup), matched_rounds=matched, trials=trials, pairs=pairs,
        hardware=read(out / 'hardware.json'), context_calibration=calibration,
        validation=f'{expected_runs} root-only verifications, all selected wallet proofs, {8 * expected_runs} recursive proofs, and all durable journal replays passed on CPU.',
        limits=dict(worker_ram_bytes=3 << 30, fleet_ram_bytes=7 << 30, aggregate_cpu_quota_percent=400,
                    allowed_cpus=[0, 1, 2, 3], rayon_threads_per_worker=4, swap_bytes=0,
                    managed_vram_per_worker_bytes=managed_bytes, context_vram_per_worker_bytes=context_bytes,
                    gpu_headroom_bytes=128 << 20, max_buffer_bytes=1 << 30),
        limitations=[f'{repetitions} measured pair(s) per mode; exploratory comparison, not sustained-throughput qualification.',
                     'Each worker proves a separate 8-transaction block using the same fixed fixture with fresh randomized proofs.',
                     'This does not measure parallel execution of the DAG for one 128-transaction block.',
                     'Process time includes initialization and shutdown; wallet proof generation and independent CPU audits are excluded.',
                     'Both GPU processes had overlapping residency and execution intervals; simultaneous kernel execution was not profiled.',
                     'VRAM and combined RAM peaks are sampled; per-service RAM peaks come from cgroups.',
                     'The GPU also serves the desktop; pre-existing compute PIDs are preserved in preflight evidence.',
                     'Research source and concurrency allowances are isolated; production defaults are unchanged.',
                     'Setup also retained two earlier reference proofs, one separate constrained calibration, and rejected reservation/startup attempts; those are excluded from this comparison.',
                     'The first compiler attempt exceeded a 3 GiB build cap; compilation passed with 8 GiB. This was not a prover OOM.'],
        manifests={name:sha(out / name) for name in ['source-manifest.json','control-manifest.json','support-pins.json','binary-manifest.json','fixture-manifest.json']},
        reporter_source_sha256=sha(__file__))
    measured_trials = [trial for trial in trials if trial['measured']]
    summary['quotient_execution'] = dict(
        measured_specialized_proofs=sum(t['specialized_quotient_proofs'] for t in measured_trials),
        measured_generic_proofs=sum(t['generic_quotient_proofs'] for t in measured_trials),
        standard_reference_specialized_proofs=reference['specialized_quotient_proofs'],
        context_gate='Ordinary specialization requires a 4 GiB context allowance. Only the separate specialized research variant permits a calibrated 224 MiB allowance under a validated shared device lease.')
    if any(t['generic_quotient_proofs'] for t in measured_trials):
        summary['limitations'].append(
            'The reduced context allowance disables specialized quotient kernels in measured pairs; all stages remain on GPU, but this is not a concurrency test of the specialized solver. The managed VRAM reduction alone does not explain the single-worker slowdown.')
    else:
        summary['limitations'].append(
            'Specialized kernels use a research-only context admission rule calibrated for this fixture and device; the result does not establish a general production context allowance.')
    if (out / 'scope.json').exists():
        summary['manifests']['scope.json'] = sha(out / 'scope.json')
    (out / 'proof-manifest.json').write_text(json.dumps(proof_manifest, indent=2) + '\n')
    summary['manifests']['proof-manifest.json'] = sha(out / 'proof-manifest.json')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(dict(aggregates=aggregates, throughput_ratio=speedup, matched_rounds=matched,
                         standard_single_worker_reference=reference_comparison), indent=2))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    summarize(parser.parse_args().output.resolve())
