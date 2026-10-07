"""Context calibration from complete, pinned single-GPU shared-owner trials."""
import copy
import json
from pathlib import Path


def normalized_limits(shared, budget):
    limits = shared.T.resource_signature(budget)
    limits['host'].pop('coordinator_job_bytes', None)
    return limits


def stable_limits(limits):
    value = copy.deepcopy(limits)
    for field in ('context_bytes', 'total_bytes', 'bootstrap'):
        value['gpu'].pop(field, None)
    return value


def source_profile(config, shared):
    """Select the run's own workload, including older equivalent duplicate pins."""
    explicit = config.get('workload_path')
    if explicit is not None:
        if explicit not in config['pins']:
            raise ValueError('shared workload path is not pinned')
        workloads = [Path(explicit)]
    else:
        workloads = [Path(path) for path in config['pins']
                     if Path(path).name == 'block-v2-multi-gpu-direct-readback-workload.json']
    profiles = [shared.T.resource_profile(path, 'paired', 'compact') for path in workloads]
    if not profiles or any(profile != profiles[0] for profile in profiles):
        raise ValueError('shared calibration workload pins are missing or ambiguous')
    if config.get('workload_profile', profiles[0]) != profiles[0]:
        raise ValueError('shared recorded workload differs from its pinned input')
    return profiles[0]


def context_samples(path, uuid, pid, budget):
    rows = [json.loads(line.split(' ', 1)[1]) for line in path.read_text().splitlines()
            if line.startswith('bounded_gpu_context ')]
    if not rows:
        raise ValueError('shared calibration has no context observations')
    for row in rows:
        if (row.get('uuid') != uuid or type(row.get('pid')) is not int or row.get('pid') != pid
                or type(row.get('limit_bytes')) is not int
                or row.get('limit_bytes') != budget['gpu']['total_bytes']
                or any(type(row.get(key)) is not int or row[key] < 0 for key in (
                    'context_bytes', 'process_bytes', 'managed_live_bytes'))
                or row['managed_live_bytes'] > budget['gpu']['managed_bytes']
                or row['context_bytes'] != max(0, row['process_bytes'] - row['managed_live_bytes'])
                or row['context_bytes'] > budget['gpu']['context_bytes']):
            raise ValueError('shared calibration context observation has inconsistent identity or bytes')
    return dict(uuid=uuid, peak_context_bytes=max(row['context_bytes'] for row in rows), samples=len(rows))


def source_pins(directories, shared):
    """Pin observations before the managed controller is admitted."""
    pins = {}
    for source in directories:
        directory = Path(source).resolve(strict=True)
        config = shared.read(directory/'config.json')
        shared.T.check_pins(config['pins'])
        pins.update(config['pins'])
        files = [directory/name for name in ('config.json', 'summary.json', 'proof-plan.json', 'fleet-plan.json',
                 'owner/result.json', 'owner/accounting.json', 'owner/audit.log',
                 'owner/proofs/execution/worker-0-start.json',
                 'workers/gpu-01/budget.json', 'workers/gpu-01/accounting.json', 'workers/gpu-01/prove.log')]
        files += list((directory/'owner/root-only').iterdir())
        pins.update(dict(shared.T.pin(path) for path in files))
    return pins


def load(directories, *, shared, gpu_sha, cpu_sha, profile, count, assignment, uuids,
         target_plan, preseal=False):
    """Return pinned measurements; live admission still enforces the derived margin."""
    if (not assignment or assignment.get('schema') != 'lattica-typed-fleet-assignment-v1'
            or set(assignment.get('limits_by_gpu', {})) != set(uuids)
            or len(uuids) != len(set(uuids))):
        raise ValueError('shared calibration requires the exact selected fixed assignment')
    expected_profile = shared.G.profile_digest({'workload': profile})
    shared.T.validate_plan(target_plan, 'paired')
    if target_plan.get('count') != count:
        raise ValueError('shared calibration target plan count differs')
    required_tasks = {(task['mode'], task['count']) for task in target_plan['tasks']
                      if not preseal or task['file'] != 'node.6.0'}
    if not required_tasks:
        raise ValueError('shared calibration target has no proof work')
    calibrations, pins, seen = {}, {}, set()
    for source in directories:
        directory = Path(source).resolve(strict=True)
        if directory in seen:
            raise ValueError('duplicate shared calibration trial')
        seen.add(directory)
        config = shared.read(directory/'config.json')
        shared.T.check_pins(config['pins'])
        summary = shared.read(directory/'summary.json')
        result = shared.read(directory/'owner/result.json')
        plan = shared.read(directory/'proof-plan.json')
        shared.T.validate_plan(plan, 'paired')
        source_count = config.get('count')
        available_tasks = {(task['mode'], task['count']) for task in plan['tasks']}
        if (type(source_count) is not int or source_count < count
                or (not preseal and source_count != count)
                or not required_tasks <= available_tasks
                or plan.get('count') != source_count
                or result.get('count') != source_count or summary.get('count') != source_count
                or summary.get('schema') != 'lattica-typed-shared-gpu-v1'
                or summary.get('status') != 'succeeded' or result.get('status') != 'succeeded'
                or result != summary.get('result') or result.get('cpu_audited') is not True
                or result.get('construction') != 'paired'
                or result.get('execution_backend') != 'typed-shared-process-dag'
                or result.get('fresh_proofs') != plan.get('fresh_proofs')
                or result.get('reused_proofs') != 0 or result.get('failed_workers') != 0
                or result.get('preseal_only') is not False or config.get('preseal_only') is not False
                or config.get('recover_from') is not None or config.get('reuse_preseal')
                or len(config.get('workers', [])) != 1 or len(summary.get('workers', [])) != 1
                or not isinstance(summary.get('parent_memory_event_deltas'), dict)
                or not summary['parent_memory_event_deltas']
                or any(summary['parent_memory_event_deltas'].values())):
            raise ValueError('shared calibration requires one complete fresh single-GPU root and CPU audit')
        if (config['pins'].get(config['gpu_binary']) != gpu_sha
                or result.get('binary_sha256') != gpu_sha
                or config['pins'].get(config['cpu_binary']) != cpu_sha):
            raise ValueError('shared calibration proving or audit binary changed')
        if source_profile(config, shared) != profile:
            raise ValueError('shared calibration uses a different proof profile')
        worker = config['workers'][0]
        budget = worker['budget']
        if (budget.get('lde_workspace_bytes', 0) != profile.get('geometry', {}).get('lde_workspace_bytes', 0)
                or budget.get('gpu_fri_fold', False) is not profile.get('geometry', {}).get('gpu_fri_fold', False)
                or budget.get('preprocessing_cache') != profile.get('preprocessing_cache')
                or budget.get('opening_denominator_cache', False) is not shared.R.opening_denominator_cache(profile)
                or budget.get('query_readback_layout', 'rows') != shared.R.query_readback_layout(profile)):
            raise ValueError('shared calibration worker options differ from its pinned profile')
        recorded = summary['workers'][0]
        uuid = budget['gpu']['uuid']
        if (uuid not in assignment['limits_by_gpu'] or recorded.get('gpu_uuid') != uuid
                or recorded.get('budget') != budget or recorded.get('worker_failed') is not False
                or recorded.get('fresh_proofs') != plan['fresh_proofs']
                or stable_limits(normalized_limits(shared, budget)) != stable_limits(assignment['limits_by_gpu'][uuid])
                or assignment['limits_by_gpu'][uuid]['gpu'].get('bootstrap') is not False):
            raise ValueError('shared calibration changes managed GPU, CPU, RAM, spill or device assignments')
        shared.validate_execution(result['execution_result'], source_count, config['workers'], config.get('native_host'),
                                  allow_worker_failover=config.get('allow_worker_failover', False))
        termination = result['execution_result']['workers'][0]
        identity_path = directory/'owner/proofs/execution/worker-0-start.json'
        identity = shared.read(identity_path)
        if (recorded.get('termination') != termination
                or identity.get('worker_pid') != termination['worker_pid']
                or identity.get('unit') != budget['unit']):
            raise ValueError('shared calibration worker identity differs from its completed trial')
        worker_dir = Path(worker['directory'])
        if worker_dir.resolve() != (directory/'workers/gpu-01').resolve():
            raise ValueError('shared calibration worker evidence is outside its trial')
        if (shared.read(worker_dir/'budget.json') != budget
                or normalized_limits(shared, identity['assignment']) != normalized_limits(shared, budget)):
            raise ValueError('shared calibration worker budget differs from its launch')
        accounting = shared.read(worker_dir/'accounting.json')
        if accounting != recorded.get('accounting'):
            raise ValueError('shared calibration accounting changed')
        shared.T.validate_accounting(accounting, budget)
        owner_accounting = shared.read(directory/'owner/accounting.json')
        if owner_accounting != summary.get('owner_accounting'):
            raise ValueError('shared calibration owner accounting changed')
        shared.T.validate_accounting(owner_accounting, {'host': {'worker_bytes': budget['host']['coordinator_bytes']}})
        measured = context_samples(worker_dir/'prove.log', uuid, termination['worker_pid'], budget)
        if measured != recorded.get('context_measurement'):
            raise ValueError('shared calibration summary differs from recorded context samples')
        artifacts = result.get('artifacts', {})
        if 'node.6.0' not in artifacts:
            raise ValueError('shared calibration lacks the audited root')
        artifact_paths = []
        for name, digest in artifacts.items():
            if not name or Path(name).name != name:
                raise ValueError('invalid shared calibration artifact path')
            path = directory/'owner/root-only'/name
            if shared.G.digest(path) != digest:
                raise ValueError('shared calibration audited artifact changed')
            artifact_paths.append(path)
        identity = dict(uuid=uuid, driver=budget['detected_gpu']['nvidia']['driver'],
            runtime=budget['detected_gpu']['opencl']['driver'], binary_sha256=gpu_sha,
            profile_sha256=expected_profile, count=count, preseal_only=preseal,
            covered_tasks=[dict(mode=mode, count=n) for mode,n in sorted(required_tasks)],
            execution_backend='typed-shared-process-dag')
        calibration = calibrations.setdefault(uuid, dict(identity, peak_context_bytes=0, samples=0, trials=[]))
        if any(calibration[key] != value for key, value in identity.items()):
            raise ValueError('shared calibration device identity changed between trials')
        calibration['peak_context_bytes'] = max(calibration['peak_context_bytes'], measured['peak_context_bytes'])
        calibration['samples'] += measured['samples']
        calibration['trials'].append(shared.M.C.pin(directory/'summary.json'))
        pins.update(config['pins'])
        files = [directory/name for name in ('config.json', 'summary.json', 'proof-plan.json', 'fleet-plan.json',
                 'owner/result.json', 'owner/accounting.json', 'owner/audit.log')]
        files += [worker_dir/name for name in ('budget.json', 'accounting.json', 'prove.log')]
        files += [identity_path, *artifact_paths]
        pins.update(dict(shared.T.pin(path) for path in files))
    if set(calibrations) != set(uuids):
        raise ValueError('complete single-GPU context evidence is required for every selected GPU')
    return calibrations, pins
