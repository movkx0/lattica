"""Audit fresh GPU prefix work, retirement, and exact one-time leaf coverage."""
import copy
import json

FIELDS = ('batches', 'programs', 'elapsed_ns', 'analysis_ns', 'hash_wall_ns',
          'hash_device_ns', 'fields', 'uploaded_bytes', 'downloaded_bytes',
          'reserved_host_peak_bytes', 'reserved_managed_peak_bytes')
PEAKS = FIELDS[-2:]


def reconcile_legacy(content, expected):
    # Imported at call time to preserve the existing receipt module boundary.
    import owned_workflow_case_receipts as receipts
    import owned_workflow_cpu_receipts as cpu
    require, parse = receipts.require, receipts.parse_record
    if expected is None:
        for line in content.splitlines():
            require(not line.startswith('owned_identity_report '), 'unselected identity preprocessing')
            if line.startswith('owned_outer_epoch '):
                value = parse(line.split(' ', 1)[1], 'owned_outer_epoch')
                epoch = value.get('epoch')
                require(type(epoch) is dict and 'identity_prefix' not in epoch
                        and 'identity_prefix_use' not in epoch, 'unselected identity preprocessing')
        return content, {'totals': dict.fromkeys(FIELDS, 0), 'max_streams': 0, 'tokens_consumed': 0}
    leaves, routes, bases = set(), {}, {}
    lines = content.splitlines()
    for line in lines:
        if not line.startswith('owned_dispatch_verification '):
            continue
        value = parse(line.split(' ', 1)[1], 'identity inventory')
        if value.get('stage') != 'inventory':
            continue
        identity = value['identity']
        route = identity['route'].get('Crypto')
        if not route or route.get('family') != 'Shake':
            continue
        binding = identity['binding']
        source = tuple(binding['source_fingerprint'])
        output = route['output']
        if 'Compiled' in output:
            node = output['Compiled']
            bases[source] = min(bases.get(source, node), node)
            if binding['kind'] == 'GroupCompile':
                leaves.add((source, node))
        if 'Outer' in output:
            routes[(source, binding['ordinal'])] = output['Outer']
    required = {binding: node - bases[binding[0]]
                for binding, node in routes.items() if (binding[0], node) in leaves}
    normalized, pending, batches, used = [], set(), set(), set()
    totals = dict.fromkeys(FIELDS, 0)
    raw = None
    max_streams = 0
    for line in lines:
        if line.startswith('owned_identity_report '):
            require(expected is not None and raw is None, 'unexpected or duplicate identity report')
            raw = parse(line.split(' ', 1)[1], 'owned_identity_report')
            receipts.object_fields(raw, receipts.REPORT_FIELDS, 'identity report')
            receipts.integer(raw['observation_errors'], 'identity observation errors')
            capabilities = receipts.object_fields(raw['capabilities'],
                ('scope', 'profile', 'max_log_fri_arity', 'stages'), 'identity capabilities')
            receipts.integer(capabilities['max_log_fri_arity'], 'identity FRI arity', bits=8)
            require(raw['schema'] == 'lattica-proving-stages-v1'
                    and raw['entry_point'] == 'block_v2_identity_prefix_batch'
                    and raw['policy'] == 'gpu_required' and raw['succeeded'] is True
                    and raw['stage_coverage_complete'] is True
                    and raw['completion_rejected'] is False and raw['observation_errors'] == 0
                    and raw['components'] == [], 'incomplete or non-GPU prefix work')
            receipts.integer(raw['elapsed_ns'], 'identity elapsed', bits=128, positive=True)
            require(raw['capabilities'] == {
                'scope': 'operation', 'profile': 'block_v2_cubic', 'max_log_fri_arity': 1,
                'stages': [{'stage': 'preprocessing', 'backend': 'open_cl'}]},
                'identity capability profile changed')
            require(type(raw['observations']) is list and len(raw['observations']) == 1,
                    'identity stage inventory changed')
            stage = receipts.object_fields(raw['observations'][0], receipts.OBSERVATION_FIELDS, 'identity stage')
            for key in receipts.OBSERVATION_FIELDS - {'stage', 'backend'}:
                receipts.integer(stage[key], 'identity stage.' + key,
                                 bits=128 if key.endswith('_ns') else 64)
            require(stage['stage'] == 'preprocessing' and stage['backend'] == 'open_cl'
                    and stage['calls'] == stage['completed_calls'] == stage['device_calls'] > 0
                    and stage['device_ns'] > 0, 'identity work includes incomplete or CPU calls')
            continue
        if not line.startswith('owned_outer_epoch '):
            normalized.append(line)
            continue
        value = parse(line.split(' ', 1)[1], 'owned_outer_epoch')
        epoch = value['epoch']
        prefix = epoch.get('identity_prefix')
        use = epoch.get('identity_prefix_use')
        source = tuple(value['binding']['source_fingerprint'])
        binding = (source, value['binding']['ordinal'])
        if prefix is not None:
            require(expected is not None and raw is not None, 'prefix epoch lacks actual GPU report')
            # Historical epochs have exactly sixteen slots. New epochs declare
            # the expanded capacity; do not infer authority from a list length.
            capacity = 16
            fields = ('batch', 'jobs', 'startup', 'retirement', 'totals')
            if 'job_capacity' in prefix:
                fields += ('job_capacity',)
                capacity = receipts.integer(prefix['job_capacity'], 'identity job capacity')
                require(capacity in (24, 32), 'identity job capacity changed')
            if 'footprint' in prefix:
                require('job_capacity' in prefix, 'borrowed prefix capacity missing')
                fields += ('footprint',)
            receipts.object_fields(prefix, fields, 'prefix epoch')
            batch = receipts.integer(prefix['batch'], 'identity batch')
            key = (source, batch)
            require(key not in batches, 'repeated identity batch')
            batches.add(key)
            cpu.successful_epoch({'schema': 'prefix-v1', 'ordinal': value['ordinal'],
                'epoch': {key: prefix[key] for key in ('startup', 'retirement')}},
                'prefix-v1', ('startup', 'retirement'))
            measured = receipts.object_fields(prefix['totals'], FIELDS, 'prefix totals')
            for name in FIELDS:
                receipts.integer(measured[name], 'prefix.' + name, bits=128, positive=True)
            count = measured['programs']
            require(measured['batches'] == 1 and 1 <= count <= capacity,
                    'identity cohort geometry changed')
            jobs = prefix['jobs']
            require(type(jobs) is list and len(jobs) == capacity and jobs[count:] == [None] * (capacity - count),
                    'identity cohort tail changed')
            if 'footprint' in prefix:
                footprint = receipts.object_fields(prefix['footprint'], (
                    'program_storage', 'borrowed_program_host_bytes', 'host_bytes',
                    'retained_host_bytes', 'managed_bytes', 'max_allocation_bytes'), 'prefix footprint')
                for name in set(footprint) - {'program_storage'}:
                    receipts.integer(footprint[name], 'prefix footprint.' + name, positive=True)
                require(footprint['program_storage'] == 'borrowed'
                        and footprint['retained_host_bytes'] == count * ((32 << 20) + 4096)
                        and footprint['host_bytes'] > footprint['retained_host_bytes']
                        and footprint['host_bytes'] == measured['reserved_host_peak_bytes']
                        and footprint['managed_bytes'] == measured['reserved_managed_peak_bytes']
                        and footprint['max_allocation_bytes'] <= footprint['managed_bytes'],
                        'borrowed prefix footprint mismatch')
            for job in jobs[:count]:
                receipts.integer(job, 'identity job')
                require((source, batch, job) not in pending
                        and job in [v for (s, _), v in required.items() if s == source],
                        'identity job is repeated or not an actual SHAKE leaf')
                pending.add((source, batch, job))
            require(use is not None and use.get('job') == jobs[0], 'first prefix consumer changed')
            require(measured['elapsed_ns'] == raw['elapsed_ns']
                    and measured['analysis_ns'] + measured['hash_wall_ns'] <= measured['elapsed_ns']
                    and measured['hash_device_ns'] <= raw['observations'][0]['device_ns']
                    and measured['reserved_host_peak_bytes'] <= 32 << 30
                    and measured['reserved_managed_peak_bytes'] <= 8 << 30,
                    'prefix timing or memory mismatch')
            for name in FIELDS:
                totals[name] = max(totals[name], measured[name]) if name in PEAKS else totals[name] + measured[name]
            max_streams = max(max_streams, count)
            raw = None
        if use is not None:
            require(expected is not None and binding in required and binding not in used,
                    'prefix used by wrong or repeated recursive phase')
            receipts.object_fields(use, ('batch', 'job'), 'prefix use')
            require(use['job'] == required[binding], 'prefix attached to another compiled program')
            key = (source, receipts.integer(use['batch'], 'prefix batch'),
                   receipts.integer(use['job'], 'prefix job'))
            require(key in pending, 'prefix missing, reused or consumed before retirement')
            pending.remove(key)
            used.add(binding)
        require(raw is None, 'prefix report is detached from its completed epoch')
        projected = copy.deepcopy(value)
        projected['epoch'].pop('identity_prefix', None)
        projected['epoch'].pop('identity_prefix_use', None)
        normalized.append('owned_outer_epoch ' + json.dumps(projected))
    require(raw is None and not pending, 'identity batch did not retire or has unconsumed tokens')
    if expected is not None:
        receipts.object_fields(expected, FIELDS, 'identity snapshot')
        for name in FIELDS:
            receipts.integer(expected[name], 'identity snapshot.' + name, bits=128, positive=True)
        require(expected == totals and used == set(required) and totals['batches'] > 0,
                'identity snapshot or complete SHAKE leaf coverage mismatch')
    else:
        require(not used and not batches, 'unselected identity preprocessing')
    return '\n'.join(normalized), {'totals': totals, 'max_streams': max_streams, 'tokens_consumed': len(used)}


def reconcile(content, expected):
    # Historical GPU records remain audit-only. New workflow envelopes require
    # CPU finalization totals and cannot select the legacy runtime mode.
    if isinstance(expected, dict) and 'finalizations' in expected:
        from cpu_identity_receipts import reconcile as cpu_reconcile
        return cpu_reconcile(content, expected)
    return reconcile_legacy(content, expected)
