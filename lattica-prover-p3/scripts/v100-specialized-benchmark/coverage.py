"""Require every GPU stage and report authenticated public metadata reuse."""


def require_gpu_stages(parents, stages):
    previous_entry = None
    authenticated = False
    reused = 0
    for report in parents:
        if (report.get('policy') != 'gpu_required' or not report.get('succeeded')
                or not report.get('stage_coverage_complete')
                or report.get('completion_rejected') or report.get('observation_errors')):
            raise ValueError('incomplete required-GPU report')
        entry = report['entry_point']
        if entry != previous_entry:
            authenticated = False
        observed = {o['stage'] for o in report['observations']
                    if o['backend'] == 'open_cl' and o['device_calls'] > 0}
        missing = stages - observed
        if missing:
            raise ValueError('GPU stage missing: ' + str(missing))
        components = {c['scope']: c for c in report['components']}
        valid_reuse = all(
            all(components.get(scope, {}).get(flag) is True
                for flag in ('started', 'cached', 'succeeded', 'stage_coverage_complete'))
            for scope in ('registry_compilation', 'preprocessing'))
        if valid_reuse:
            if not authenticated:
                raise ValueError('public metadata reuse lacks preceding GPU proof')
            reused += 1
        authenticated = True
        previous_entry = entry
    return {'fresh_gpu_proofs': len(parents),
            'proofs_with_public_compilation_cache_hits': reused,
            'required_stage_count': len(stages)}
