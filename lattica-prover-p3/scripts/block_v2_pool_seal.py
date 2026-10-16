"""Original post-seal clock, bound into the durable native arrival selection.

This is host scheduling metadata, not a proof or consensus-format extension.
The full workflow clock remains authoritative when it expires first.
"""
import copy

import block_v2_pool_timing as T

POST_SEAL_MS = 180000


def issue(workflow):
    boot, now = T.workflow_clock()
    workflow = T.validate_workflow(workflow, boot, now)
    return {'schema_version': 1, 'pool_workflow': workflow,
            'sealed_monotonic_ms': now,
            'deadline_monotonic_ms': min(now + POST_SEAL_MS, workflow['deadline_monotonic_ms'])}


def check(value, workflow, *, clock=None):
    boot, now = T.workflow_clock() if clock is None else clock
    T.validate_workflow(workflow, boot, now)
    fields = {'schema_version', 'pool_workflow', 'sealed_monotonic_ms', 'deadline_monotonic_ms'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or T.canonical(value['pool_workflow']) != T.canonical(workflow)
            or any(type(value[k]) is not int or not 0 <= value[k] < 1 << 64
                   for k in ['sealed_monotonic_ms', 'deadline_monotonic_ms'])
            or not workflow['started_monotonic_ms'] <= value['sealed_monotonic_ms'] <= now
            or value['deadline_monotonic_ms'] != min(value['sealed_monotonic_ms'] + POST_SEAL_MS,
                                                    workflow['deadline_monotonic_ms'])
            or now >= value['deadline_monotonic_ms']):
        raise ValueError('pool original post-seal deadline expired or changed')
    return now - value['sealed_monotonic_ms']


def selection(intake, candidate, selection_id, workflow):
    selected = intake.check_selection(selection_id, candidate)
    value = selected.get('pool_seal')
    check(value, workflow)
    return copy.deepcopy(value)


def apply(intake, candidate, selection_id, proof, workflow, original_seal):
    """Recheck before application and measure through durable publication/replay.

    A commit may succeed before a later deadline check fails. Return its real
    receipt and mark the missed deadline; never describe that case as unapplied.
    The native host still independently verifies the root and atomically fences
    the chain head. A caller's timing or proof-availability flag grants nothing.
    """
    observed = selection(intake, candidate, selection_id, workflow)
    if T.canonical(observed) != T.canonical(original_seal):
        raise ValueError('native selection changed the original post-seal clock')
    before = check(original_seal, workflow)
    receipt = candidate.apply(proof, candidate.binding)
    intake.record_application(selection_id, candidate, receipt, proof)
    intake.verify_recorded_application(selection_id, candidate, receipt, proof)
    boot, now = T.workflow_clock()
    try:
        elapsed = check(original_seal, workflow, clock=(boot, now))
        met = True
    except ValueError:
        elapsed, met = now - original_seal['sealed_monotonic_ms'], False
    return {'native_applied': True, 'application': receipt, 'selection_id': selection_id,
            'pool_seal': copy.deepcopy(original_seal), 'before_application_post_seal_ms': before,
            'completed_post_seal_ms': elapsed, 'post_seal_deadline_met': met,
            'workflow_elapsed_ms': now - workflow['started_monotonic_ms']}
