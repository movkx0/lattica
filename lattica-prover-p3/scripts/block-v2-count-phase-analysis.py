#!/usr/bin/env python3
"""Retain phase observations from already validated typed count-matrix roots.

No prover is launched. Counters must cover the exact completed proof plan and
the expected one-program cache transitions. Inclusive spans are not additive.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex


PHASES = {
    'preprocessing_setup': ('lattica_block_v2_perf', 'preprocessing setup'),
    'execution_trace': ('lattica_block_v2_perf', 'execution trace'),
    'native_batch_prove': ('lattica_block_v2_perf', 'native batch prove'),
    'quotient': ('lattica_prover_p3::block_v2::gpu_quotient_prover', 'compute quotient'),
    'quotient_polynomial': ('p3_batch_stark::prover', 'compute quotient polynomial'),
    'gpu_opening': ('lattica_block_v2_perf', 'GPU opening proof'),
    'fri': ('lattica_prover_p3::block_v2::batched_fri', 'FRI prover'),
    'fri_query': ('lattica_prover_p3::block_v2::batched_fri', 'query phase'),
}


def pin(path):
    path = Path(path).resolve(strict=True)
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def read_pinned(item, root):
    path = Path(item['path'])
    if not path.is_absolute():
        path = root / path
    data = path.read_bytes()
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('phase input pin changed: ' + str(path))
    return data


def spans(log):
    result = {}
    for line in log.splitlines():
        if not line.startswith('performance_span '):
            continue
        tokens = shlex.split(line)[1:]
        fields = {}
        for token in tokens:
            key, value = token.split('=', 1)
            if key in fields:
                raise ValueError('duplicate performance span field')
            fields[key] = value
        if set(fields) != {'target', 'name', 'calls', 'total_ns', 'max_ns'}:
            raise ValueError('incomplete or unexpected performance span fields')
        for key in ('calls', 'total_ns', 'max_ns'):
            value = fields[key]
            if not value.isascii() or not value.isdecimal():
                raise ValueError('noncanonical performance span counter')
            fields[key] = int(value)
        if fields['calls'] < 1 or not 0 <= fields['max_ns'] <= fields['total_ns']:
            raise ValueError('invalid performance span counters')
        identity = fields['target'], fields['name']
        if identity in result:
            raise ValueError('repeated cumulative performance span: ' + repr(identity))
        result[identity] = fields
    return result


def phase_metrics(row, log):
    parsed = spans(log)
    stages = row['stage_costs']['stages']
    proofs = row['fresh_proofs']
    if type(proofs) is not int or proofs < 1 or len(stages) != proofs:
        raise ValueError('phase proof count differs from validated stages')
    changes = sum(index == 0 or stage['mode'] != stages[index - 1]['mode']
                  for index, stage in enumerate(stages))
    phases = {}
    for name, identity in PHASES.items():
        if identity not in parsed:
            raise ValueError('missing required phase: ' + name)
        phase = dict(parsed[identity])
        expected_calls = changes if name == 'preprocessing_setup' else proofs
        if phase['calls'] != expected_calls:
            raise ValueError('phase does not cover the completed plan: ' + name)
        phase['inclusive_seconds'] = phase['total_ns'] / 1e9
        # These selected spans each bracket sequential calls on the prover
        # thread. Nested parallel spans elsewhere may exceed whole-job time.
        if phase['inclusive_seconds'] > row['proving_seconds'] + 0.001:
            raise ValueError('phase exceeds its proving interval: ' + name)
        phases[name] = phase
    return {'recursive_proofs': proofs, 'expected_preprocessing_cache_transitions': changes,
            'phases': phases, 'all_spans': list(parsed.values()),
            'interpretation': 'Inclusive spans overlap and must not be summed. '
                              'Nested parallel spans can exceed wall time. '
                              'Cache transitions count observed mode changes; '
                              'these observations do not isolate a setup speedup.'}


def analyze(data, root):
    if (data.get('schema_version') != 1 or
            data.get('record_type') != 'typed_count_matrix_analysis' or
            data.get('status') not in ('running', 'succeeded')):
        raise ValueError('a validated count analysis is required')
    if len(data['rows']) != data['coverage']['completed']:
        raise ValueError('phase coverage differs from count analysis')
    snapshot = json.loads(read_pinned(data['matrix_snapshot_source'], root))
    if snapshot['coverage'] != data['coverage'] or snapshot['status'] != data['status']:
        raise ValueError('count analysis differs from retained matrix snapshot')
    for item in data['analysis_sources']:
        read_pinned(item, root)
    rows, identities = [], set()
    for row in data['rows']:
        identity = row['gpu_uuid'], row['count']
        if identity in identities:
            raise ValueError('duplicate count/device phase row')
        identities.add(identity)
        logs = []
        for item in row['sources']:
            content = read_pinned(item, root)
            if Path(item['path']).name == 'prove.log':
                logs.append((item, content.decode('utf-8')))
        if len(logs) != 1:
            raise ValueError('exactly one pinned prover log is required')
        metrics = phase_metrics(row, logs[0][1])
        rows.append({key: row[key] for key in
                     ('gpu_uuid', 'count', 'origin', 'worker_seconds', 'proving_seconds',
                      'fresh_proofs', 'root_sha256')} | metrics | {'log': logs[0][0]})
    return {'schema_version': 1, 'record_type': 'typed_count_phase_analysis',
            'status': 'succeeded', 'matrix_status': data['status'], 'coverage': data['coverage'],
            'captured_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'proof_accounting': data['proof_accounting'], 'rows': rows,
            'delivered_transactions_measured': False, 'production_ready': False,
            'scope': 'Profiling observations for previously CPU-audited count-matrix roots. '
                     'One run per count/device; no speedup or delivered throughput claim. '
                     'Selected phase counters cover the exact validated proof stages. '
                     'All inclusive spans are retained; they are not an additive time breakdown.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--repository-root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'count-analysis.json'
    source.write_bytes(args.analysis.read_bytes())
    try:
        result = analyze(json.loads(source.read_bytes()), args.repository_root.resolve(strict=True))
    except Exception as error:
        result = {'schema_version': 1, 'record_type': 'typed_count_phase_analysis',
                  'status': 'failed', 'failure': f'{type(error).__name__}: {error}',
                  'delivered_transactions_measured': False, 'production_ready': False}
    result['analysis_source'] = pin(source)
    result['tooling_source'] = pin(Path(__file__))
    (out / 'phase-analysis.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': result['status'], 'rows': len(result.get('rows', [])),
                      'failure': result.get('failure'), 'output': str(out / 'phase-analysis.json')}))
    return int(result['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
