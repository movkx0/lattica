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
    require(command in ('plan', 'prepare-inputs', 'screen', 'run', 'qualify-memory', 'kernel-screen', 'preflight-groups', 'architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph'), 'invalid aggregation command')
    values = {}
    allowed = {'--case', '--workload', '--input-bundle', '--input', '--output', '--profile',
               '--group-width', '--pipeline', '--timeout-seconds', '--max-components',
        '--identity', '--selection', '--request', '--repetitions', '--screen-family', '--first-leaf', '--leaves', '--gpu-managed-mib', '--query-gather', '--memory-qualification', '--compiler-policy', '--ntt-profile', '--poseidon-profile', '--native-source', '--recursion-backend', '--preparation-workers'}
    require(len(argv[2:]) % 2 == 0, 'aggregation options require values')
    for key, value in zip(argv[2::2], argv[3::2]):
        require(key in allowed and key not in values, 'unknown/duplicate aggregation option')
        values[key] = value
    require(values.get('--case') in ('n3', 'n4') and values.get('--input-bundle'), 'case/bundle required')
    require(args.host_profile == ('standard' if values['--case'] == 'n3' else 'expanded-36'),
            'aggregation case/host envelope mismatch')
    require(int(values.get('--timeout-seconds', '600')) <= args.seconds,
            'driver timeout exceeds process guard')
    profile = values.get('--profile', 'grouped-v5')
    require(profile in ('legacy', 'grouped-v2', 'grouped-v3', 'grouped-v4', 'grouped-v5'), 'invalid aggregation profile')
    require(command not in ('run', 'qualify-memory') or '--output' in values, 'full aggregate requires fresh output')
    if command in ('run', 'qualify-memory'):
        output = Path(values['--output'])
        require(output.is_absolute() and not output.exists() and not output.is_symlink(),
                'aggregate output must be a new absolute path')
    require(command != 'qualify-memory' or profile in ('grouped-v4', 'grouped-v5'), 'qualification requires grouped-v4')
    if profile in ('grouped-v4', 'grouped-v5'):
        require(values.get('--query-gather', 'batch') in ('scalar', 'batch'), 'invalid query gather')
        requested = values.get('--gpu-managed-mib', 'auto')
        require(requested == 'auto' or (requested.isdecimal() and 8192 <= int(requested) <= 12288
                and int(requested) % 256 == 0), 'invalid managed MiB')
    else:
        require(not any(k in values for k in ('--gpu-managed-mib', '--query-gather', '--memory-qualification')),
                'memory/query selection requires grouped-v4')
    if command == 'architecture-graph': values.setdefault('--screen-family', 'graph')
    typed_command = command in ('run', 'plan') or command.startswith('architecture-')
    backend = values.get('--recursion-backend', 'typed' if profile == 'grouped-v5' and typed_command else 'machine')
    require(backend in ('typed', 'machine'), 'invalid recursion backend')
    require(1 <= int(values.get('--preparation-workers', '16')) <= 16, 'preparation worker range')
    typed = backend == 'typed'
    require(not typed or (profile == 'grouped-v5' and typed_command), 'typed backend command/profile')
    machine_reference = command == 'architecture-request' and values.get('--screen-family') == 'aes' and values.get('--group-width') == '1'
    require(not command.startswith('architecture-') or typed or machine_reference or command == 'architecture-graph', 'architecture screen requires typed backend')
    require(values.get('--screen-family', 'shake') in ('shake', 'aes', 'graph'), 'invalid screen family')
    require(values.get('--screen-family') != 'aes' or command.startswith('architecture-'), 'AES archive screen requires architecture command')
    values['--recursion-backend'] = backend
    if typed and values['--case'] == 'n4':
        values.setdefault('--compiler-policy', 'typed-batch')
        values.setdefault('--group-width', '16')
    require(values.get('--compiler-policy', 'standard') in ('standard', 'wide-inputs', 'wide-memory', 'typed-batch'), 'invalid compiler policy')
    width = int(values.get('--group-width', '4'))
    require(width in (1, 2, 4, 8, 16) and (width <= 8 or typed), 'invalid native batch width')
    require(values.get('--compiler-policy') != 'typed-batch' or typed or machine_reference, 'typed-batch requires typed recursion')
    require(values.get('--ntt-profile', 'baseline') in ('baseline', 'powers', 'split8', 'smalltile', 'padded', 'local48'), 'invalid NTT profile')
    require(values.get('--poseidon-profile', 'baseline') in ('baseline', 'square', 'square-unroll'), 'invalid Poseidon profile')
    require(profile == 'grouped-v5' or (not any(k in values for k in ('--compiler-policy', '--ntt-profile', '--poseidon-profile'))
        and command not in ('kernel-screen', 'preflight-groups', 'architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph')), 'kernel/compiler experiments require grouped-v5')
    require(values.get('--compiler-policy', 'standard') == 'standard' or values['--case'] == 'n4', 'wide policy requires N4')
    native_source = values.get('--native-source', 'current')
    require(native_source == 'current' or (command == 'architecture-graph' and native_source == 'revalidate-archive'
        and values.get('--screen-family') == 'graph' and '--request' not in values) or (native_source == 'revalidate-archive'
        and command in ('preflight-groups', 'architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph') and values.get('--screen-family', 'shake') in ('shake', 'aes')
        and '--request' in values and (width <= 4 or typed)),
        'archive revalidation requires a bounded AES/SHAKE architecture preflight')
    require(command not in ('architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph') or (native_source == 'revalidate-archive'
        and 1 <= int(values.get('--repetitions', '3')) <= 3),
        'architecture proof requires a revalidated AES/SHAKE archive and at most three fresh proofs')
    require(command != 'architecture-graph' or (native_source == 'revalidate-archive' and values.get('--screen-family') == 'graph'
        and '--request' not in values and (typed or width <= 4) and 1 <= int(values.get('--leaves', '8')) <= 8), 'invalid graph architecture selection')
    return dict(command=command, values=values, profile=profile,
                transactions=int(values['--case'][1:]), complete_fresh_workflow=False)


def ntt_profile(selected):
    return selected['values'].get('--ntt-profile',
        'smalltile' if selected['profile'] == 'grouped-v5' else 'baseline')


def environment(selected):
    tuning = 'events,witness,programs' if selected['profile'] != 'legacy' else ''
    if selected['profile'] in ('grouped-v4', 'grouped-v5') and selected['command'] != 'prepare-inputs' and selected['values'].get('--query-gather', 'batch') == 'batch':
        tuning += ',queries'
    return {'LATTICA_V2_GPU_TUNING': tuning,
        'LATTICA_V2_GPU_NTT_PROFILE': ntt_profile(selected),
        'LATTICA_V2_GPU_POSEIDON_PROFILE': selected['values'].get('--poseidon-profile', 'baseline'),
        'LATTICA_V2_GPU_COMPILER_POLICY': selected['values'].get('--compiler-policy', 'standard')}



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
    if selected['command'] in ('plan', 'preflight-groups', 'kernel-screen'):
        require(report['proofs_generated'] == 0, 'planning produced a proof')
        if selected['command'] in ('preflight-groups','kernel-screen'):
            require(report['session']['session_closed'] is True and report['session']['completion_claimed'] is False,
                    'proof-free command requires cleanup without a completion claim')
            require(report.get('source_and_backend_checked') is True if selected['command'] == 'preflight-groups'
                    else report.get('transform_reference_equal') is True, 'incomplete proof-free screen')
    elif selected['command'] in ('architecture-proof', 'architecture-parent'):
        require(report['scope'] == 'recursion-architecture-proof-screen'
            and 1 <= report['proofs_generated'] <= (6 if selected['command'] == 'architecture-parent' else 3) and report['native_proofs_generated'] == 0
            and report['verified'] is True and report['complete_aggregation'] is False
            and report['session']['session_closed'] is True
            and report['session']['completion_claimed'] is False,
            'architecture proof requires bounded verified proofs and cleanup without workflow completion')
        profile = report['proof_profile']
        require(len(profile['samples']) * (2 if selected['command'] == 'architecture-parent' else 1) == report['proofs_generated']
            and profile['independent_cpu_verification'] is True and profile['gpu_backend_only'] is True,
            'missing architecture proof measurements')
        for sample in profile['samples']:
            measurement = sample['measurement']
            require(measurement['verified'] is True and measurement['proof_json_bytes'] > 0
                and measurement['backend_report']['stage_coverage_complete'] is True,
                'architecture proof failed verification or GPU coverage')
        if selected['command'] == 'architecture-parent':
            require(profile['parent_geometry'] is not None and profile['parent_template_identity'],
                    'missing trusted parent geometry')
            for sample in profile['samples']:
                parent = sample['parent']
                require(parent['constrained_child_verification'] is True
                        and parent['measurement']['verified'] is True
                        and parent['measurement']['proof_json_bytes'] > 0
                        and parent['measurement']['backend_report']['stage_coverage_complete'] is True,
                        'parent proof failed constrained verification or GPU coverage')
    elif selected['command'] == 'architecture-graph':
        typed = selected['values']['--recursion-backend'] == 'typed'
        groups = len(report['groups'])
        count = groups
        remaining = groups
        if typed:
            while remaining > 1:
                count += remaining // 4 + (remaining % 4 > 1)
                remaining = (remaining + 3) // 4
        else:
            count = 2 * groups - 1
        require(report['scope'] == 'recursion-graph-subtree-screen' and report['verified'] is True
            and report['complete_aggregation'] is False and report['complete_graph'] is False
            and report['backend'] == selected['values']['--recursion-backend']
            and report['native_proofs_generated'] == 0 and report['archive_files_rewritten'] == 0
            and report['current_cache_entries_created'] == 0 and 1 <= groups <= 8
            and report['session']['session_closed'] is True and report['session']['completion_claimed'] is False
            and 1 <= len(report['samples']) <= 3, 'invalid graph architecture screen')
        for sample in report['samples']:
            require(sample['verified'] is True and sample['public_mutation_rejected'] is True
                and sample['recursive_proofs'] == count and sample['independent_cpu_verification'] is True
                and sample['gpu_backend_only'] is True and math.isfinite(sample['seconds']) and sample['seconds'] > 0,
                'incomplete graph architecture sample')
            if typed:
                require(len(sample['measurements']) == count and (groups == 1 or sample['order_mutation_rejected'] is True),
                    'incomplete typed graph reduction')
                for item in sample['measurements']:
                    m = item['measurement']
                    require(m['verified'] is True and m['proof_json_bytes'] > 0 and m['backend_report']['stage_coverage_complete'] is True,
                        'graph proof failed GPU coverage or CPU verification')
            else:
                require(sample['production_cpu_lookahead'] is True, 'graph reference omitted production lookahead')
    elif selected['command'] == 'architecture-request':
        profile = report['proof_profile']
        machine = selected['values'].get('--recursion-backend') == 'machine'
        groups = profile['native_groups']
        count = 2 * groups - 1 if machine else groups + (groups > 1)
        require(profile.get('backend', 'typed') == ('machine' if machine else 'typed'), 'request backend mismatch')
        require(report['scope'] == 'recursion-architecture-request-screen'
                and report['complete_request'] is True and report['verified'] is True
                and report['complete_aggregation'] is False and report['native_proofs_generated'] == 0
                and report['session']['session_closed'] is True and report['session']['completion_claimed'] is False
                and profile['complete_request'] is True and profile['independent_cpu_verification'] is True
            and profile['gpu_backend_only'] is True and 1 <= profile['native_groups'] <= 8
                and 1 <= len(profile['samples']) <= 3
            and report['proofs_generated'] == len(profile['samples']) * count,
                'invalid complete-request architecture screen')
        for sample in profile['samples']:
            require(sample['complete_request'] is True and sample['public_mutation_rejected'] is True
                and (sample['order_mutation_rejected'] is True or report.get('native_components') == 1)
                    and len(sample['leaves']) == profile['native_groups'], 'incomplete constrained request')
            if machine:
                require(len(sample['parents']) == groups - 1
                    and all(item['verified'] is True and math.isfinite(item['seconds']) and item['seconds'] > 0
                        for item in sample['leaves'] + sample['parents']), 'unverified machine request tree')
                continue
            direct = profile['native_groups'] == 1
            require(not direct or (profile.get('direct_native_batch') is True and sample.get('direct_native_batch') is True and sample['root'] is None), 'direct request must omit the redundant parent')
            for item in sample['leaves'] + ([] if direct else [sample['root']]):
                measurement = item['measurement']
                require(measurement['verified'] is True and measurement['proof_json_bytes'] > 0
                        and measurement['backend_report']['stage_coverage_complete'] is True,
                        'request proof failed verification or GPU coverage')
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
    from gpu_aggregation_telemetry import reduce_intervals
    row['telemetry'] = reduce_intervals(content)
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
