#!/usr/bin/env python3
"""Run a frozen, sequential single-GPU capacity qualification.

Each completed size needs fresh recursive proofs, an independent CPU root audit,
bounded worker accounting and measurements from the declared GPU. This does not
measure wallet proving, native delivery or a sustained transaction campaign.
"""
import argparse
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback


def read(path):
    return json.loads(path.read_bytes())


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write('\n')


def stamp():
    return dict(monotonic_ns=time.monotonic_ns(), wall_time_ns=time.time_ns(),
                utc=datetime.datetime.now(datetime.timezone.utc).isoformat())


def context_peaks(log, uuid, pid, budget):
    samples = [json.loads(line.split(' ', 1)[1]) for line in log.read_text().splitlines()
               if line.startswith('bounded_gpu_context ')]
    if not samples:
        raise ValueError('GPU context samples are missing')
    for sample in samples:
        if (sample['uuid'] != uuid or sample['pid'] != pid
                or sample['limit_bytes'] != budget['total_bytes']
                or not 0 <= sample['managed_live_bytes'] <= budget['managed_bytes']
                or not 0 <= sample['context_bytes'] <= budget['context_bytes']
                or not 0 < sample['process_bytes'] <= budget['total_bytes']):
            raise ValueError('GPU sample differs from the admitted device, process or limits')
    return dict(samples=len(samples),
        sampled_peak_process_bytes=max(s['process_bytes'] for s in samples),
        sampled_peak_managed_bytes=max(s['managed_live_bytes'] for s in samples),
        sampled_peak_context_bytes=max(s['context_bytes'] for s in samples),
        sampling_scope='In-process stage checkpoints; sampled peaks are not continuous NVML maxima.')


def run(area):
    root = Path.cwd()
    frozen = area/'frozen-r1'
    campaign = read(frozen/'campaign.json')
    sys.path.insert(0, str(frozen/'controllers'))
    S = importlib.import_module('block-v2-typed-shared-gpu-run')
    P = importlib.import_module('block-v2-count-phase-analysis')
    from benchmark_report.measurements import fields
    os.environ['RAYON_NUM_THREADS'] = '1'
    gpu, cpu, fixture = (frozen/name for name in ('gpu-block-v2-paired-probe', 'cpu-block-v2-paired-probe', 'fixture'))
    uuid = campaign['gpu_uuid']

    def pin(path):
        return dict(path=str(path.relative_to(root)), bytes=path.stat().st_size, sha256=digest(path))

    def host_snapshot():
        return dict(captured=stamp(), host=S.G.detect_worker_host('/tmp'),
                    devices=S.R.detect_gpus(str(gpu)),
                    compute_processes=subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,gpu_uuid,used_memory', '--format=csv,noheader'], text=True))

    record = dict(schema_version=1, status='running', started_at=stamp(), completed_counts=[],
                  gpu_uuid=uuid, declared_counts=campaign['counts'], production_ready=False)
    active_count = None
    try:
        for source in read(frozen/'manifest.json')['files']:
            path = root/source['path']
            if path.stat().st_size != source['bytes'] or digest(path) != source['sha256']:
                raise ValueError('frozen input changed: '+str(path))
        assert campaign['counts'] == [16,32,64] and campaign['single_gpu'] is True
        assert campaign['opening_denominator_cache'] is True and campaign['host_readback_layout'] == 'direct'
        for count in campaign['counts']:
            active_count = count
            directory = area/f'count-{count:02d}'
            directory.mkdir()
            before = host_snapshot()
            save(directory/'host-before.json', before)
            selected, = [device for device in before['devices'] if device['uuid'] == uuid]
            assert selected['nvidia']['total_bytes'] <= campaign['vram_ceiling_bytes']
            command = [sys.executable, str(frozen/'controllers/block-v2-typed-shared-gpu-run.py'),
                '--gpu-binary', str(gpu), '--cpu-binary', str(cpu), '--fixture', str(fixture),
                '--count', str(count), '--gpu-uuid', uuid, '--scratch', '/tmp',
                '--evidence', str(directory/'root')]
            save(directory/'invocation.command.json', command)
            started = stamp()
            with (directory/'invocation.log').open('xb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                           env=S.T.clean_environment())
                save(directory/'invocation.process.json', dict(pid=process.pid, start_ticks=S.Bootstrap.birth(process.pid)))
                returncode = process.wait()
            finished = stamp()
            invocation = dict(returncode=returncode, started_at=started, finished_at=finished,
                              seconds=(finished['monotonic_ns']-started['monotonic_ns'])/1e9)
            save(directory/'invocation.exit.json', invocation)
            save(directory/'host-after.json', host_snapshot())
            if returncode:
                raise RuntimeError(f'count {count} controller exited {returncode}')
            trial = directory/'root'
            summary, config, plan = (read(trial/name) for name in ('summary.json','config.json','proof-plan.json'))
            result = summary['result']
            S.T.validate_plan(plan, 'paired')
            S.T.check_pins(config['pins'])
            assert summary['status'] == result['status'] == 'succeeded'
            assert result['cpu_audited'] is True and result['count'] == plan['count'] == count
            assert result['fresh_proofs'] == plan['fresh_proofs'] and result['reused_proofs'] == 0
            assert not any(summary['parent_memory_event_deltas'].values())
            assert len(config['workers']) == len(summary['workers']) == 1
            worker, actual = config['workers'][0], summary['workers'][0]
            S.T.check_pins(worker['pins'])
            budget = worker['budget']
            assert budget['gpu']['uuid'] == actual['gpu_uuid'] == uuid and actual['worker_failed'] is False
            assert budget['gpu']['bootstrap'] is True
            assert budget['gpu']['total_bytes'] <= budget['gpu']['usable_bytes'] <= campaign['vram_ceiling_bytes']
            assert budget['opening_denominator_cache'] is True and budget['readback_layout'] == 'direct'
            S.T.validate_accounting(actual['accounting'], budget)
            worker_dir = Path(worker['directory'])
            log = worker_dir/'prove.log'
            peaks = context_peaks(log, uuid, actual['termination']['worker_pid'], budget['gpu'])
            assert S.T.measured_context(log, uuid) == actual['context_measurement']
            spans = P.spans(log.read_text())
            assert all(identity in spans for identity in P.PHASES.values())
            assert spans[P.PHASES['native_batch_prove']]['calls'] == result['fresh_proofs']
            counters = {}
            for line in log.read_text().splitlines():
                prefix = line.split(' ', 1)[0]
                if prefix in ('bounded_gpu_opening_checkpoint','bounded_gpu_opening_denominator_cache_checkpoint'):
                    assert prefix not in counters
                    counters[prefix] = fields(line)
            opening = counters['bounded_gpu_opening_checkpoint']
            cache = counters['bounded_gpu_opening_denominator_cache_checkpoint']
            assert opening['calls'] == cache['calls'] == result['fresh_proofs']
            assert cache['enabled'] is True and cache['saved_upload_bytes'] > 0 and opening['kernel_ns'] > 0
            for name in ('node.6.0','body.json'):
                assert digest(trial/'owner/root-only'/name) == result['artifacts'][name]
            assert 0 < result['root_bytes'] <= 2*1024**2
            transactions = read(trial/'owner/root-only/body.json')['transactions'][:count]
            assert len(transactions) == count
            kinds = {kind:sum(tx['kind']==kind for tx in transactions) for kind in ('joinsplit','htlc_redeem','htlc_refund','issuance')}
            assert sum(kinds.values()) == count
            assert not json.loads(S.G.systemctl('list-units','lattica-v2-multi-*.service',
                '--state=active,activating,deactivating','--output=json','--no-pager'))
            qualified = dict(schema_version=1, record_type='single_gpu_16gb_capacity_trial', status='passed',
                count=count, transaction_types=kinds, user_transactions=count-kinds['issuance'],
                issuance_transactions=kinds['issuance'], cpu_audited_roots=1, fresh_recursive_proofs=result['fresh_proofs'],
                reused_recursive_proofs=0, fresh_wallet_proofs=0, native_blocks_applied=0,
                gpu_uuid=uuid, vram_ceiling_bytes=campaign['vram_ceiling_bytes'], device=selected,
                budget=budget, context_measurements=peaks, opening_counters=counters,
                root_bytes=result['root_bytes'], root_artifacts=result['artifacts'],
                controller_invocation=invocation, owner_seconds=result['elapsed_seconds'],
                proving_seconds=result['proving_seconds'], worker_accounting=actual['accounting'],
                owner_accounting=summary['owner_accounting'], phase_profiles=list(spans.values()),
                phase_scope='Inclusive cumulative spans overlap and are not an additive elapsed-time breakdown.',
                production_ready=False, delivered_transactions_measured=False, scope=campaign['scope'],
                source_commit=campaign['source_commit'], runtime_manifest=pin(frozen/'manifest.json'),
                sources=[pin(path) for path in sorted(directory.rglob('*')) if path.is_file() and '__pycache__' not in path.parts])
            save(directory/'qualified.json', qualified)
            public = root/'docs/evidence'/f'block-v2-vram16-capacity-count-{count}-2026-10-06-r1.json'
            save(public, qualified)
            record['completed_counts'].append(count)
            print(json.dumps(dict(status='passed', count=count, fresh_recursive_proofs=result['fresh_proofs'],
                proving_seconds=result['proving_seconds'], sampled_gpu_peak_bytes=peaks['sampled_peak_process_bytes'],
                public_result=str(public))), flush=True)
        record['status'] = 'passed'
    except BaseException as error:
        record.update(status='failed', failed_count=active_count,
                      failure=f'{type(error).__name__}: {error}', traceback=traceback.format_exc())
        try:
            save(area/'failure-host-snapshot-r1.json', host_snapshot())
        except BaseException as snapshot_error:
            record['failure_snapshot_error'] = str(snapshot_error)
    finally:
        record['finished_at'] = stamp()
        save(area/'run-qualification-r1.json', record)
        print(json.dumps(record), flush=True)
    return 0 if record['status']=='passed' else 1


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--area', type=Path, required=True)
    args=parser.parse_args()
    sys.exit(run(args.area.resolve(strict=True)))
