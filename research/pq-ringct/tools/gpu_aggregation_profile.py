"""Acceptance for aggregation from verified native components, never full workflow.

The generic guard owns device selection, cgroups, source/binary provenance,
exclusive hardware use and terminal cleanup. This module adds the exact CLI
contract and distinguishes planning, input preparation, screens and full runs.
"""
import json
import fcntl
import math
import re
import time
from pathlib import Path
from cpu_proof_budget import Budget


class AggregationBudget(Budget):
    schema = 'gpu-aggregation-test-budget-v1'
    job_seconds = 600

    def read(self):
        value = json.loads(self.path.read_text()) if self.path.exists() else dict(
            schema=self.schema, limit_seconds=3600, attempts=[])
        extensions = value.get('extensions', [])
        require(value.get('schema') == self.schema and isinstance(extensions, list), 'invalid aggregation budget')
        ids = set()
        for row in extensions:
            require(isinstance(row, dict) and re.fullmatch(r'[a-z0-9-]{1,64}', row.get('id', ''))
                    and row['id'] not in ids and type(row.get('seconds')) is int
                    and 1 <= row['seconds'] <= 3600, 'invalid aggregation budget extension')
            ids.add(row['id'])
        require(value.get('limit_seconds') == 3600 + sum(row['seconds'] for row in extensions),
                'aggregation budget must match recorded extensions')
        return value

    def remaining(self):
        value = self.read()
        require(not any(a['status'] == 'running' for a in value['attempts']),
                'unfinished attempt requires receipt reconciliation')
        return value['limit_seconds'] - sum(a['wall_seconds'] for a in value['attempts'])

    def extend(self, extension_id, seconds):
        require(isinstance(extension_id, str) and re.fullmatch(r'[a-z0-9-]{1,64}', extension_id)
                and type(seconds) is int and 1 <= seconds <= 3600, 'invalid explicit budget extension')
        with self.path.with_suffix('.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = self.read()
            require(not any(a['status'] == 'running' for a in value['attempts']), 'cannot extend a running campaign')
            extensions = value.setdefault('extensions', [])
            for row in extensions:
                if row['id'] == extension_id:
                    require(row['seconds'] == seconds, 'extension id already has a different allowance')
                    return value
            extensions.append(dict(id=extension_id, seconds=seconds, recorded_unix_ns=time.time_ns()))
            value['limit_seconds'] += seconds
            self.save(value)
            return value


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def selection(args, argv):
    if not getattr(args, 'gpu_aggregation', False):
        return None
    require(args.profile == 'full' and args.build_label and 1 <= args.seconds <= 600,
            'aggregation requires recorded full GPU profile and at most 600 seconds')
    require(args.device_uuid and args.retained_tree_storage == 'host',
            'aggregation requires physical GPU pin and host retained trees')
    require(Path(argv[0]).name == 'pq-ringct-gpu-aggregate' and len(argv) >= 2,
            'aggregation requires its explicit research executable')
    command = argv[1]
    require(command in ('plan', 'prepare-inputs', 'screen', 'run', 'qualify-memory'), 'invalid aggregation command')
    values = {}
    allowed = {'--case', '--workload', '--input-bundle', '--input', '--output', '--profile',
               '--group-width', '--pipeline', '--timeout-seconds', '--max-components',
               '--identity', '--selection', '--request', '--repetitions', '--screen-family', '--first-leaf', '--leaves', '--gpu-managed-mib', '--query-gather', '--memory-qualification'}
    require(len(argv[2:]) % 2 == 0, 'aggregation options require values')
    for key, value in zip(argv[2::2], argv[3::2]):
        require(key in allowed and key not in values, 'unknown/duplicate aggregation option')
        values[key] = value
    require(values.get('--case') in ('n3', 'n4') and values.get('--input-bundle'), 'case/bundle required')
    require(args.host_profile == ('standard' if values['--case'] == 'n3' else 'expanded-36'),
            'aggregation case/host envelope mismatch')
    require(int(values.get('--timeout-seconds', '600')) <= args.seconds,
            'driver timeout exceeds process guard')
    profile = values.get('--profile', 'legacy')
    require(profile in ('legacy', 'grouped-v2', 'grouped-v3', 'grouped-v4'), 'invalid aggregation profile')
    require(command not in ('run', 'qualify-memory') or '--output' in values, 'full aggregate requires fresh output')
    if command in ('run', 'qualify-memory'):
        output = Path(values['--output'])
        require(output.is_absolute() and not output.exists() and not output.is_symlink(),
                'aggregate output must be a new absolute path')
        require(command != 'run' or profile == 'legacy' or '--selection' in values,
                'candidate aggregate requires measured layout selection')
    require(command != 'qualify-memory' or profile == 'grouped-v4', 'qualification requires grouped-v4')
    if profile == 'grouped-v4':
        require(values.get('--query-gather', 'batch') in ('scalar', 'batch'), 'invalid query gather')
        requested = values.get('--gpu-managed-mib', 'auto')
        require(requested == 'auto' or (requested.isdecimal() and 8192 <= int(requested) <= 12288
                and int(requested) % 256 == 0), 'invalid managed MiB')
    else:
        require(not any(k in values for k in ('--gpu-managed-mib', '--query-gather', '--memory-qualification')),
                'memory/query selection requires grouped-v4')
    return dict(command=command, values=values, profile=profile,
                transactions=int(values['--case'][1:]), complete_fresh_workflow=False)


def environment(selected):
    tuning = 'events,witness,programs' if selected['profile'] != 'legacy' else ''
    if selected['profile'] == 'grouped-v4' and selected['command'] != 'prepare-inputs' and selected['values'].get('--query-gather', 'batch') == 'batch':
        tuning += ',queries'
    return {'LATTICA_V2_GPU_TUNING': tuning}


def require_build(plan, executable):
    if plan.get('gpu_aggregation') is None:
        return
    build = json.loads(Path(executable['build_record']).read_text())
    argv = build['command']
    require(argv[1:2] == ['build'] and argv.count('--features') == 1
            and argv[argv.index('--features') + 1] == 'gpu-aggregation-experiment'
            and argv.count('--bin') == 1 and argv[argv.index('--bin') + 1] == 'pq-ringct-gpu-aggregate',
            'aggregation requires its recorded feature-isolated binary')


def validate(content, selected):
    prefix = 'GPU_AGGREGATION_PROFILE '
    rows = [json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    require(len(rows) == 1, 'missing/duplicate aggregation terminal')
    row = rows[0]
    require(row.get('schema') == 'ringct-gpu-aggregation-v1'
            and row.get('complete_fresh_workflow') is False
            and row.get('performance_qualified') is False, 'invalid aggregation scope')
    options, report = row['options'], row['report']
    require(options['command'] == selected['command'] and options['profile'] == selected['profile']
            and options['transactions'] == selected['transactions'], 'aggregation terminal identity mismatch')
    seconds = row['controller_wall_seconds']
    require(isinstance(seconds, (int, float)) and math.isfinite(seconds) and 0 <= seconds < 600,
            'aggregation terminal exceeded deadline')
    if selected['command'] == 'plan':
        require(report['proofs_generated'] == 0, 'planning produced a proof')
    elif selected['command'] == 'prepare-inputs':
        require(report['scope'] == 'native-component-preparation' and report['session_closed']
                and report['aggregation_timed'] is False, 'invalid native preparation terminal')
    elif selected['command'] in ('screen', 'qualify-memory'):
        require(report['verified'] and report['complete_aggregation'] is False
                and report['session']['session_closed'], 'screen is not complete aggregation')
    else:
        require(report['scope'] == 'aggregation-from-native-components' and report['complete']
                and report['native_proofs_created'] == 0 and report['recursive_proofs'] > 0
                and report['session']['session_closed'] and report['final_cpu_verified']
                and report['artifact_round_trip'] and report['public_mutation_rejected']
                and report['proof_mutation_rejected'] and report['order_mutation_rejected']
                and report['under_ten_minutes'], 'incomplete or unverified aggregation')
    return row


def qualification(records):
    """Require distinct verified artifacts and a consistent source/device/configuration."""
    groups, labels, artifacts = {}, set(), set()
    for record in records:
        row = record.get('gpu_aggregation_acceptance', {})
        options, report = row.get('options', {}), row.get('report', {})
        if record.get('status') != 'passed' or options.get('command') != 'run':
            continue
        try:
            validate('GPU_AGGREGATION_PROFILE ' + json.dumps(row), dict(
                command='run', profile=options['profile'], transactions=options['transactions']))
            require(all(record.get(k) is True for k in ('source_inputs_unchanged',
                'executable_unchanged', 'all_subprocesses_terminal_and_reaped')), 'missing terminal provenance')
            seconds = report['aggregation_seconds']
            require(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds < 600,
                'invalid aggregation duration')
            label, artifact = record['label'], report['artifact_sha3']
            require(label and artifact and label not in labels and artifact not in artifacts,
                'duplicate qualification run')
            identity = (report['source_sha3'], record['executable_provenance']['sha256'],
                record['environment']['LATTICA_GPU_DEVICE_UUID'], options['profile'],
                options['identity'], options['parallel'], options['group_width'], options['workload'],
                report['selection_sha3'])
            require(all(identity[:3]) and report['input_sha3'], 'missing qualification identity')
            case = options['transactions']
            require(case in (3, 4), 'invalid qualification case')
        except (KeyError, TypeError, ValueError, RuntimeError):
            continue
        labels.add(label); artifacts.add(artifact)
        groups.setdefault((identity, case, report['input_sha3']), []).append(seconds)
    qualified = {case: {identity for (identity, n, _), samples in groups.items()
        if n == case and len(samples) >= 3} for case in (3, 4)}
    return dict(cases={f'n{n}': bool(qualified[n]) for n in (3, 4)},
        performance_qualified=bool(qualified[3] & qualified[4]))
