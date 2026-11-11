"""Resolve one immutable aggregation VRAM envelope inside the exclusive guard."""
import hashlib
import json
import subprocess
from pathlib import Path
from gpu_aggregation_profile import ntt_profile

MIB, GIB = 1 << 20, 1 << 30
STEP, HEADROOM = 256 * MIB, 512 * MIB


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def budget(requested, global_bytes, free_bytes, reserve):
    require(2 * GIB <= reserve <= 4 * GIB and reserve % STEP == 0, 'invalid context reserve')
    maximum = min(12 * GIB, global_bytes - reserve - HEADROOM, free_bytes - reserve - HEADROOM)
    maximum = maximum // STEP * STEP
    # The measured 10.5 GiB envelope is the default ceiling. Explicit research
    # requests may still use the admitted 12 GiB maximum.
    selected = min(maximum, 10752 * MIB) if requested == 'auto' else int(requested) * MIB
    require(8 * GIB <= selected <= maximum and selected % STEP == 0,
            'requested GPU memory does not fit the available envelope')
    return selected


def inventory(uuid):
    result = subprocess.run(['nvidia-smi', '--id=' + uuid,
        '--query-gpu=uuid,driver_version,memory.free', '--format=csv,noheader,nounits'],
        check=True, capture_output=True, text=True, timeout=10)
    rows = result.stdout.strip().splitlines()
    require(len(rows) == 1, 'ambiguous GPU memory inventory')
    actual, driver, free = [s.strip() for s in rows[0].split(',')]
    require(actual == uuid and free.isdecimal() and driver, 'GPU memory inventory mismatch')
    return dict(device_uuid=actual, driver=driver, free_bytes=int(free) * MIB)


def file_sha3(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha3_256').hexdigest()


def validate_certificate(value, binding, gather, policy=None):
    require(value.get('schema') == 'ringct-gpu-memory-qualification-v1', 'invalid memory qualification')
    for key in ('source_sha3', 'executable_sha3', 'device_uuid', 'driver'):
        require(value.get(key) == binding[key], 'stale memory qualification: ' + key)
    require(value.get('query_gather') == gather and value.get('verified') is True
            and value.get('max_rows') in (1 << 18, 1 << 19, 1 << 20), 'memory qualification geometry mismatch')
    require(policy is None or value.get('kernel_policy') == policy, 'memory qualification kernel/compiler policy mismatch')
    reserve = value.get('context_bytes')
    peak = value.get('opaque_peak_bytes')
    require(type(reserve) is int and type(peak) is int and peak >= 0
            and 2 * GIB <= reserve <= 4 * GIB and reserve % STEP == 0
            and peak + HEADROOM <= reserve, 'smaller context reserve was not qualified')
    geometries = value.get('geometries', [])
    require(geometries and len(geometries) <= 128 and all(type(g.get('rows')) is int and g['rows'] <= value['max_rows']
        and type(g.get('public_values')) is int and 0 <= g['public_values'] <= 64 for g in geometries), 'invalid qualification geometries')
    return reserve, value['max_rows']


def prepare(plan, executable):
    selected = plan.get('gpu_aggregation')
    if not selected or selected['profile'] not in ('grouped-v4', 'grouped-v5') or selected['command'] == 'prepare-inputs':
        return
    env, values = plan['environment'], selected['values']
    gpu = inventory(env['LATTICA_GPU_DEVICE_UUID'])
    probe = subprocess.run([plan['command'][0], 'device-inventory'], env=env,
        check=True, capture_output=True, text=True, timeout=10)
    rows = [json.loads(line.split(' ', 1)[1]) for line in probe.stdout.splitlines()
            if line.startswith('GPU_AGGREGATION_DEVICE ')]
    require(len(rows) == 1, 'missing bounded OpenCL inventory')
    physical = rows[0]
    require(physical['device']['uuid'] == gpu['device_uuid']
            and physical['device']['driver'] == gpu['driver'], 'OpenCL/NVML identity mismatch')
    binding = dict(source_sha3=physical['source_sha3'], executable_sha3=file_sha3(plan['command'][0]),
        device_uuid=gpu['device_uuid'], driver=gpu['driver'])
    gather = values.get('--query-gather', 'batch')
    compiler = values.get('--compiler-policy', 'standard')
    typed = compiler == 'typed-batch'
    wide = compiler in ('wide-memory', 'typed-batch')
    policy = dict(ntt=ntt_profile(selected), poseidon=values.get('--poseidon-profile', 'baseline'),
        compiler=compiler, program_bytes=(6 if typed else 3 if wide else 2)*GIB,
        input_values=(8 if typed else 2 if compiler != 'standard' else 1) << 20,
        live_jobs=1 if typed else 2 if wide else 4,
        symbolic_bytes=(3 if typed else 1)*GIB,
        backend_host_bytes=(24 if wide else 20)*GIB, tree_host_bytes=(16 if wide else 8)*GIB)
    # The generic guard supplies the standard tree quota; V5 captures its explicit expanded partition here.
    env['LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'] = str(policy['tree_host_bytes'])

    reserve, max_rows, certificate_hash, geometries = 4 * GIB, 1 << 20, None, None
    certificate = values.get('--memory-qualification')
    if certificate:
        path = Path(certificate)
        require(path.is_file() and path.stat().st_size <= 1 << 20, 'memory qualification file limit')
        value = json.loads(path.read_text())
        reserve, max_rows = validate_certificate(value, binding, gather, policy)
        certificate_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        geometries = value['geometries']
    managed = budget(values.get('--gpu-managed-mib', 'auto'), physical['device']['global_bytes'],
                     gpu['free_bytes'], reserve)
    memory = dict(**binding, kernel_policy=policy, managed_bytes=managed, context_bytes=reserve, max_rows=max_rows,
        query_gather=gather, qualification_sha256=certificate_hash, qualified_geometries=geometries, startup_free_bytes=gpu['free_bytes'],
        physical_global_bytes=physical['device']['global_bytes'],
        max_allocation_bytes=physical['device']['max_allocation_bytes'], headroom_bytes=HEADROOM)
    selected['memory'] = memory
    env.update(LATTICA_V2_GPU_AGGREGATION_V4='1', LATTICA_V2_GPU_MANAGED_BYTES=str(managed),
        LATTICA_V2_GPU_CONTEXT_BYTES=str(reserve), LATTICA_V2_GPU_AGGREGATION_ROWS=str(max_rows),
        LATTICA_V2_GPU_AGGREGATION_MEMORY=json.dumps(memory, separators=(',', ':')),
        LATTICA_V2_GPU_AGGREGATION_DIAGNOSTICS='1' if selected['command'] in ('qualify-memory', 'kernel-screen') else '0')


def validate(content, plan):
    selected = plan.get('gpu_aggregation')
    if not selected or 'memory' not in selected:
        return
    row = plan['gpu_aggregation_acceptance']
    require(row['report'].get('memory') == selected['memory'], 'effective aggregation memory changed')
    report = row['report']
    if selected['command'] in ('screen', 'qualify-memory', 'run', 'kernel-screen', 'architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph'):
        require(plan.get('gpu_memory_observation', {}).get('samples', 0) > 0,
                'missing process VRAM observations')
    if 'session' in report:
        session = report['session']['session_cleanup' if selected['command'] in ('kernel-screen','preflight-groups','architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph') else 'session_finish']
        require(session['device_allowance_bytes'] == selected['memory']['managed_bytes']
                and session['gpu_context_allowance_bytes'] == selected['memory']['context_bytes']
                and session['managed_peak_bytes'] <= selected['memory']['managed_bytes'],
                'GPU memory terminal exceeds selected envelope')
    if selected['command'] != 'qualify-memory':
        return
    checkpoints = [json.loads(line.split(' ', 1)[1]) for line in content.splitlines()
                   if line.startswith('bounded_gpu_context ')]
    labels = {c['label'] for c in checkpoints}
    require({'aggregation registration', 'aggregation trace', 'aggregation proof complete',
             'aggregation LDE peak', 'aggregation query batch',
             'specialized quotient compilation', 'specialized quotient execution'} <= labels,
            'incomplete memory qualification checkpoints')
    require(all(c['uuid'] == selected['memory']['device_uuid'] and c['context_bytes'] >= 0
                and c['process_bytes'] <= c['limit_bytes'] for c in checkpoints), 'invalid VRAM checkpoints')
    import re
    pairs = sorted({(int(m.group(1)), int(m.group(2))) for m in re.finditer(r'gpu_aggregation_consuming_admission rows=(\d+) public_values=(\d+)', content)})
    heights = [p[0] for p in pairs]
    require(heights and report['verified'] and report['session']['session_closed'], 'incomplete qualified proof')
    opaque = max(c['context_bytes'] for c in checkpoints)
    reserve = max(2 * GIB, ((opaque + HEADROOM + STEP - 1) // STEP) * STEP)
    plan['gpu_memory_qualification'] = dict(schema='ringct-gpu-memory-qualification-v1',
        **{k: selected['memory'][k] for k in ('source_sha3', 'executable_sha3', 'device_uuid', 'driver', 'query_gather', 'kernel_policy')},
        opaque_peak_bytes=opaque, context_bytes=reserve, max_rows=max(heights), verified=True,
        geometries=[dict(rows=rows, public_values=publics) for rows, publics in pairs],
        smaller_reserve_qualified=reserve < 4 * GIB, supported_reserve=reserve <= 4 * GIB,
        managed_bytes_tested=selected['memory']['managed_bytes'], checkpoints=checkpoints)


def publish(plan):
    if plan.get('status') != 'passed' or 'gpu_memory_qualification' not in plan:
        return
    require(plan.get('source_inputs_unchanged') is True and plan.get('executable_unchanged') is True
            and plan.get('all_subprocesses_terminal_and_reaped') is True, 'qualification provenance incomplete')
    output = Path(plan['gpu_aggregation']['values']['--output'])
    with output.open('x') as stream:
        json.dump(plan['gpu_memory_qualification'], stream, indent=2)
        stream.write('\n')


def observe(plan, pid):
    selected = plan.get('gpu_aggregation')
    if not selected or selected['command'] not in ('screen', 'qualify-memory', 'run', 'kernel-screen', 'architecture-proof', 'architecture-parent', 'architecture-request', 'architecture-graph') or not pid:
        return
    env = plan['environment']
    uuid = env['LATTICA_GPU_DEVICE_UUID']
    response = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,gpu_uuid,used_memory',
        '--format=csv,noheader,nounits'], capture_output=True, text=True, check=True, timeout=10)
    observed = plan.setdefault('gpu_memory_observation', dict(samples=0, process_peak_bytes=0, minimum_free_bytes=None))
    for line in response.stdout.strip().splitlines():
        fields = [s.strip() for s in line.split(',')]
        require(len(fields) == 3, 'malformed process VRAM observation')
        if fields[0] == str(pid):
            require(fields[1] == uuid and fields[2].isdecimal(), 'process VRAM identity mismatch')
            used = int(fields[2]) * MIB
            observed['samples'] += 1
            observed['process_peak_bytes'] = max(observed['process_peak_bytes'], used)
            require(used <= int(env['LATTICA_V2_GPU_MANAGED_BYTES']) + int(env['LATTICA_V2_GPU_CONTEXT_BYTES']),
                    'observed process VRAM exceeds selected total envelope')
    free = inventory(uuid)['free_bytes']
    observed['minimum_free_bytes'] = min(free, observed['minimum_free_bytes'] if observed['minimum_free_bytes'] is not None else free)
    require(free >= HEADROOM, 'available VRAM headroom exhausted')


def merge_qualifications(paths, output):
    values = [json.loads(Path(path).read_text()) for path in paths]
    require(values, 'empty qualification merge')
    first = values[0]
    keys = ('source_sha3', 'executable_sha3', 'device_uuid', 'driver', 'query_gather', 'kernel_policy')
    require(all(v['schema'] == 'ringct-gpu-memory-qualification-v1' and v['verified'] is True
                and all(v.get(k) == first.get(k) for k in keys) for v in values), 'incompatible qualification records')
    pairs = sorted({(g['rows'], g['public_values']) for v in values for g in v['geometries']})
    opaque = max(v['opaque_peak_bytes'] for v in values)
    reserve = max(2 * GIB, ((opaque + HEADROOM + STEP - 1) // STEP) * STEP)
    result = dict(first, opaque_peak_bytes=opaque, context_bytes=reserve,
        max_rows=max(p[0] for p in pairs), geometries=[dict(rows=r, public_values=p) for r,p in pairs],
        smaller_reserve_qualified=reserve < 4 * GIB, supported_reserve=reserve <= 4 * GIB,
        managed_bytes_tested=max(v['managed_bytes_tested'] for v in values),
        checkpoints=[c for v in values for c in v['checkpoints']])
    with Path(output).open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    return result
