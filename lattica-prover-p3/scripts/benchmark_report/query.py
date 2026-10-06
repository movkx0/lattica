"""Matched query-readback evidence with checked profiles, binaries and inputs."""
import hashlib
import json
import math
from pathlib import Path
from .model import reference, relative
from .typed import GPU_SCHEMA


def resource_limits(budget):
    devices = budget.get('detected_gpu', {})
    return {'cpu': budget.get('cpu'), 'host': budget.get('host'),
            'gpu': {k:v for k,v in budget.get('gpu', {}).items() if k != 'available_bytes'},
            'drivers': {k:devices.get(k, {}).get('driver') for k in ('nvidia','opencl')}}


def windows(root, path, data, by_source):
    from .history import pinned_comparison_source as pinned, safe_metadata
    layouts = ('rows', 'gather')
    trials, pairs = data.get('trials', []), data.get('pairs', [])
    requested = data.get('requested_pairs')
    complete = (data.get('status') == 'succeeded' and type(requested) is int
                and 0 < requested <= 10 and len(pairs) == requested and len(trials) == 2 * requested
                and data.get('baseline_query_layout') == 'rows' and data.get('candidate_query_layout') == 'gather')
    profiles, hashes = data.get('profiles', {}), data.get('profile_sha256', {})
    if not isinstance(profiles, dict) or not isinstance(hashes, dict):
        profiles, hashes, complete = {}, {}, False
    normalized = []
    for layout in layouts:
        profile = profiles.get(layout, {})
        if not isinstance(profile, dict) or not isinstance(profile.get('geometry'), dict):
            profile, complete = {}, False
        geometry = dict(profile.get('geometry', {}))
        complete = bool(complete and geometry.pop('query_readback_layout', 'rows') == layout)
        normalized.append({**profile, 'geometry': geometry})
        identity = {k: profile.get(k) for k in ('version', 'name', 'height', 'geometry')}
        sha = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        complete = bool(complete and sha == hashes.get(layout))
    complete = bool(complete and normalized[0] == normalized[1] and hashes.get('rows') != hashes.get('gather'))
    input_pins = data.get('input_pins', {})
    complete = bool(complete and input_pins and all(pinned(root, {'path': p, 'sha256': sha})
                                                   for p, sha in input_pins.items()))
    if complete:
        expected = [(n, layout) for n in range(1, requested + 1)
                    for layout in (layouts if n % 2 else layouts[::-1])]
        complete = ([(t.get('pair'), t.get('query_readback_layout')) for t in trials] == expected
                    and [p.get('pair') for p in pairs] == list(range(1, requested + 1)))
    if complete:
        for pair in pairs:
            rows = [t for t in trials if t['pair'] == pair['pair']]
            times = {t['query_readback_layout']: t.get('worker_seconds') for t in rows}
            reduction = pair.get('worker_reduction_percent')
            valid = all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in times.values())
            complete = bool(complete and valid and pair.get('worker_seconds') == times
                            and pair.get('order') == [t['query_readback_layout'] for t in rows]
                            and type(reduction) in (int, float) and math.isfinite(reduction)
                            and math.isclose(reduction, (1 - times['gather'] / times['rows']) * 100,
                                             rel_tol=1e-12, abs_tol=1e-9))
    assignment = pinned(root, data.get('resource_assignment'))
    assigned = safe_metadata(assignment) if assignment else None
    results, fixture_pins = [], []
    for trial in trials:
        layout = trial.get('query_readback_layout')
        if layout not in layouts:
            continue
        result_path = pinned(root, trial.get('result_source'))
        summary_path = pinned(root, trial.get('summary_source'))
        config_path = pinned(root, trial.get('config_source'))
        result, summary, config = (safe_metadata(p) if p else None for p in (result_path, summary_path, config_path))
        consistent = bool(assigned and assigned.get('schema') == 'lattica-typed-resource-assignment-v1'
            and result and summary and config
            and result.get('schema') == summary.get('schema') == GPU_SCHEMA
            and result.get('status') == summary.get('status') == 'succeeded' and summary.get('result') == result
            and result.get('construction') == trial.get('construction') == data.get('construction')
            and result.get('count') == data.get('count')
            and result.get('cpu_audited') is True and trial.get('cpu_audited') is True
            and result.get('fresh_proofs') == trial.get('fresh_proofs')
            and result.get('elapsed_seconds') == trial.get('worker_seconds')
            and result.get('profile_sha256') == trial.get('profile_sha256') == hashes.get(layout)
            and result.get('binary_sha256') == trial.get('binary_sha256') == data.get('gpu_sha256')
            and trial.get('cpu_binary_sha256') == data.get('cpu_sha256')
            and result.get('budget', {}).get('query_readback_layout', 'rows') == layout
            and resource_limits(result.get('budget', {})) == assigned.get('limits')
            and config.get('workload') == profiles.get(layout)
            and result.get('resource_assignment_sha256') == data['resource_assignment'].get('sha256')
            and result.get('artifacts', {}).get('node.6.0') == trial.get('root_sha256'))
        if consistent:
            config_pins = config.get('pins', {})
            consistent = bool(config_pins and all(pinned(root, {'path': p, 'sha256': sha}) for p, sha in config_pins.items())
                              and config_pins.get(config.get('gpu_binary')) == data.get('gpu_sha256')
                              and config_pins.get(config.get('cpu_binary')) == data.get('cpu_sha256'))
            fixture = Path(config.get('fixture', ''))
            public = {p: sha for p, sha in config_pins.items() if Path(p).parent == fixture}
            keys = {'reference':5, 'finalizer':6, 'paired':12}.get(data.get('construction'), 0)
            count = data.get('count')
            expected = {'body.json','height.json', *(f'key.{n}' for n in range(1, keys + 1))}
            if type(count) is int and 1 <= count <= 64:
                expected.update(f'wallet.{n}' for n in range(count))
            else:
                consistent = False
            consistent = bool(consistent and keys and {Path(p).name for p in public} == expected
                              and all(input_pins.get(p) == sha for p, sha in public.items()))
            fixture_pins.append(public)
        ids = [by_source[relative(result_path, root)]] if result_path and relative(result_path, root) in by_source else []
        pair = next((p for p in pairs if p.get('pair') == trial.get('pair')), {})
        results.append((relative(path.parent, root) + ':' + layout, {
            'run_ids': ids, 'elapsed_seconds': trial.get('worker_seconds'), 'source': reference(path, root),
            'recorded': {'type': 'typed_query_comparison', 'arm': layout, 'pair': trial.get('pair'),
                         'construction': data.get('construction'), 'count_per_root': data.get('count'),
                         'individual_seconds': [trial.get('worker_seconds')],
                         'requested_pairs': requested, 'series_status': data.get('status'),
                         'worker_reduction_percent': pair.get('worker_reduction_percent'),
                         'timing_boundary': data.get('timing_boundary')},
            'source_consistent': consistent, 'complete_mapping': bool(consistent and len(ids) == 1)}))
    ids = [rid for _, window in results for rid in window['run_ids']]
    complete = bool(complete and len(results) == len(trials) and len(ids) == len(set(ids))
                    and all(w['complete_mapping'] for _, w in results)
                    and len(fixture_pins) == len(trials) and all(p and p == fixture_pins[0] for p in fixture_pins))
    for _, window in results:
        window['complete_mapping'] = complete
        window['recorded']['repeat_qualified'] = bool(complete and requested >= 5)
    return results
