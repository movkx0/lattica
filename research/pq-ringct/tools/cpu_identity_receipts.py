"""Audit CPU identity work separately from strict GPU proof receipts."""
import copy
import json

FIELDS = ('batches', 'programs', 'elapsed_ns', 'analysis_ns', 'hash_wall_ns',
          'worker_elapsed_ns', 'finalizations', 'finalization_ns', 'fields',
          'uploaded_bytes', 'downloaded_bytes', 'reserved_host_peak_bytes',
          'reserved_managed_peak_bytes')
PEAKS = FIELDS[-2:]


def stage(report, entry, backend, policy):
    import owned_workflow_case_receipts as r
    r.object_fields(report, r.REPORT_FIELDS, 'identity operation')
    r.require(report['schema'] == 'lattica-proving-stages-v1' and report['entry_point'] == entry
              and report['policy'] == policy and report['succeeded'] is True
              and report['stage_coverage_complete'] is True and report['completion_rejected'] is False
              and report['observation_errors'] == 0 and report['components'] == [], 'invalid identity operation policy')
    r.integer(report['elapsed_ns'], 'identity operation time', bits=128, positive=True)
    r.require(report['capabilities'] == dict(scope='operation', profile='block_v2_cubic', max_log_fri_arity=1,
              stages=[dict(stage='preprocessing', backend=backend)]), 'invalid identity capability inventory')
    r.require(type(report['observations']) is list and len(report['observations']) == 1, 'identity observation inventory')
    observed = r.object_fields(report['observations'][0], r.OBSERVATION_FIELDS, 'identity observation')
    for name in r.OBSERVATION_FIELDS - {'stage', 'backend'}:
        r.integer(observed[name], 'identity.' + name, bits=128 if name.endswith('_ns') else 64)
    r.require(observed['stage'] == 'preprocessing' and observed['backend'] == backend
              and observed['calls'] == observed['completed_calls'] > 0, 'incomplete identity operation')
    r.require((backend == 'cpu' and observed['device_calls'] == observed['device_ns'] == 0)
              or (backend == 'open_cl' and 0 < observed['device_calls'] <= observed['completed_calls']
                  and observed['device_ns'] > 0), 'identity backend work mismatch')


def reconcile(content, expected):
    import owned_workflow_case_receipts as r
    import owned_workflow_cpu_receipts as cpu
    require, parse = r.require, r.parse_record
    r.object_fields(expected, FIELDS, 'CPU identity snapshot')
    for name in FIELDS:
        r.integer(expected[name], 'identity snapshot.' + name, bits=128)
    totals = dict.fromkeys(FIELDS, 0)
    pending, used, batches = set(), set(), set()
    raw = None
    outer_state = None
    normalized = []
    maximum = 0
    # Bind prefixes to actual original compiler slots and outer dispatches.
    leaves, routes, bases = set(), {}, {}
    for line in content.splitlines():
        if not line.startswith('owned_dispatch_verification '):
            continue
        value = parse(line.split(' ', 1)[1], 'identity inventory')
        if value.get('stage') != 'inventory':
            continue
        identity = value['identity']; route = identity['route'].get('Crypto')
        if not route or route.get('family') != 'Shake':
            continue
        binding = identity['binding']; source = tuple(binding['source_fingerprint']); output = route['output']
        if 'Compiled' in output:
            node = output['Compiled']; bases[source] = min(bases.get(source, node), node)
            if binding['kind'] == 'GroupCompile': leaves.add((source, node))
        if 'Outer' in output: routes[(source, binding['ordinal'])] = output['Outer']
    required = {binding: node - bases[binding[0]] for binding, node in routes.items() if (binding[0], node) in leaves}
    for line in content.splitlines():
        if line.startswith('owned_identity_report '):
            raise ValueError('GPU identity work is retired for CPU RingCT workflows')
        if line.startswith('owned_identity_cpu_report '):
            require(raw is None, 'duplicate CPU prefix report')
            raw = parse(line.split(' ', 1)[1], 'CPU prefix')
            require(raw.get('schema') == 'identity-cpu-prefix-v1', 'CPU prefix schema')
            count = r.integer(raw['streams'], 'CPU cohort width', positive=True)
            require(1 <= count <= 16 and raw['effective_workers'] == count
                    and type(raw['peak_active_workers']) is int and 1 <= raw['peak_active_workers'] <= count,
                    'CPU worker coverage')
            require(raw['requested_workers'] is None or type(raw['requested_workers']) is int
                    and count <= raw['requested_workers'] <= 16, 'CPU requested workers')
            stage(raw['analysis'], 'block_v2_identity_source_analysis', 'open_cl', 'gpu_required')
            stage(raw['cpu'], 'block_v2_cpu_identity_prefixes', 'cpu', 'cpu_required')
            for name in ('analysis_ns', 'hash_wall_ns', 'worker_elapsed_ns', 'fields'):
                r.integer(raw[name], name, bits=128, positive=True)
            workers = raw['workers']; require(type(workers) is list and len(workers) == count, 'CPU worker result inventory')
            for worker in workers:
                r.object_fields(worker, ('job', 'fields', 'elapsed_ns'), 'CPU worker')
                for name in worker: r.integer(worker[name], 'CPU worker.' + name, bits=128)
            require(len({w['job'] for w in workers}) == count
                    and sum(w['fields'] for w in workers) == raw['fields']
                    and sum(w['elapsed_ns'] for w in workers) == raw['worker_elapsed_ns']
                    and raw['hash_wall_ns'] <= raw['cpu']['elapsed_ns'], 'CPU worker totals')
            maximum = max(maximum, count)
            continue
        if line.startswith('proving_stage_report '):
            report = parse(line.split(' ', 1)[1], 'identity sequencing')
            entry = report.get('entry_point')
            if entry == 'block_v2_preprocessing':
                require(outer_state is None, 'unfinished prior CPU registration')
                outer_state = 'identity'
            elif entry == 'block_v2_cpu_identity':
                require(outer_state == 'identity', 'CPU identity missing, repeated or reordered')
                stage(report, entry, 'cpu', 'cpu_required')
                totals['finalizations'] += 1; totals['finalization_ns'] += report['elapsed_ns']
                outer_state = 'proof'
                continue
            elif entry == 'block_v2_registered_program':
                require(outer_state == 'proof', 'GPU proof lacks completed CPU identity')
                outer_state = None
        if not line.startswith('owned_outer_epoch '):
            normalized.append(line); continue
        value = parse(line.split(' ', 1)[1], 'CPU identity epoch')
        epoch = value['epoch']; prefix = epoch.get('identity_prefix'); use = epoch.get('identity_prefix_use')
        if prefix is None and use is None:
            require(raw is None, 'CPU report detached from epoch')
            normalized.append(line)
            continue
        source = tuple(value['binding']['source_fingerprint']); binding = (source, value['binding']['ordinal'])
        if prefix is not None:
            require(raw is not None and prefix['job_capacity'] == 16, 'missing CPU prefix or capacity')
            batch = r.integer(prefix['batch'], 'CPU batch'); key = (source, batch)
            require(key not in batches and raw['batch'] == batch, 'CPU batch mismatch or replay'); batches.add(key)
            cpu.successful_epoch({'schema': 'prefix-v1', 'ordinal': value['ordinal'],
                'epoch': {k: prefix[k] for k in ('startup', 'retirement')}}, 'prefix-v1', ('startup', 'retirement'))
            count = raw['streams']; jobs = prefix['jobs']
            require(len(jobs) == 16 and jobs[count:] == [None] * (16 - count)
                    and jobs[:count] == [w['job'] for w in raw['workers']], 'CPU deterministic job order')
            footprint = prefix['footprint']
            require(footprint == raw['footprint'] and footprint['program_storage'] == 'borrowed'
                    and footprint['borrowed_program_host_bytes'] > 0
                    and footprint['retained_host_bytes'] == count * ((32 << 20) + 4096)
                    and footprint['managed_bytes'] == footprint['max_allocation_bytes'] == 0
                    and footprint['host_bytes'] >= footprint['retained_host_bytes'] + count * (2 << 20)
                    and footprint['host_bytes'] <= 32 << 30, 'CPU footprint or original backing mismatch')
            measured = dict.fromkeys(FIELDS, 0)
            measured.update(batches=1, programs=count, elapsed_ns=raw['cpu']['elapsed_ns'] + raw['analysis_ns'],
                analysis_ns=raw['analysis_ns'], hash_wall_ns=raw['hash_wall_ns'],
                worker_elapsed_ns=raw['worker_elapsed_ns'], fields=raw['fields'],
                reserved_host_peak_bytes=footprint['host_bytes'])
            require(prefix['totals'] == measured, 'CPU epoch totals differ from actual operations')
            for name in FIELDS: totals[name] = max(totals[name], measured[name]) if name in PEAKS else totals[name] + measured[name]
            for job in jobs[:count]:
                token = (source, batch, job)
                require(token not in pending and job in [v for (s, _), v in required.items() if s == source], 'CPU prefix job authority')
                pending.add(token)
            require(use is not None and use['job'] == jobs[0], 'first CPU prefix consumer mismatch')
            raw = None
        if use is not None:
            require(binding in required and binding not in used and use['job'] == required[binding], 'CPU prefix consumer authority')
            token = (source, use['batch'], use['job'])
            require(token in pending, 'CPU prefix missing, reused or not retired')
            pending.remove(token); used.add(binding)
        require(raw is None, 'CPU report detached from epoch')
        projected = copy.deepcopy(value)
        projected['epoch'].pop('identity_prefix', None); projected['epoch'].pop('identity_prefix_use', None)
        normalized.append('owned_outer_epoch ' + json.dumps(projected))
    require(raw is None and not pending and outer_state is None, 'incomplete CPU identity lifecycle')
    require(totals == expected and totals['finalizations'] > 0, 'CPU identity snapshot mismatch')
    return '\n'.join(normalized), {'totals': totals, 'max_streams': maximum, 'tokens_consumed': len(used)}
