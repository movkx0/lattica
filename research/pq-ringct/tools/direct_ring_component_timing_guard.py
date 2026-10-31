"""Strict C038 component timing; no complete-workflow or speedup credit."""
import re

TIMING = 'direct_ring_recursive_outer_component_timing'
ORCHESTRATION = 'direct_ring_recursive_outer_orchestration_bytes'
OUTER_REPORT = 'direct_ring_recursive_outer_report '
U128_MAX = (1 << 128) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def positive_u128(value, name):
    require(type(value) is int and 0 < value <= U128_MAX,
            'invalid positive u128: ' + name)
    return value


def orchestration(content, caller_position):
    """Child-only builds may omit it; outer qualification must require it."""
    require(TIMING not in content, 'CPU caller census emitted component timing')
    count = content.count(ORCHESTRATION)
    if count == 0:
        return None
    matches = list(re.finditer(
        r'^' + ORCHESTRATION
        + r' actual=([1-9][0-9]{0,4}) timing_additional=([1-9][0-9]{0,4}) allowance=32768$',
        content, re.M))
    require(count == 1 and len(matches) == 1, 'invalid outer orchestration census marker')
    found = matches[0]
    actual, additional = map(int, found.groups())
    require(found.start() < caller_position and 0 < additional < actual <= 32768,
            'outer orchestration census exceeds allowance or has wrong order')
    return dict(actual_bytes=actual, timing_additional_bytes=additional, allowance_bytes=32768)


def component(content, footer_position, child, outer, observation_ns):
    require(ORCHESTRATION not in content, 'outer component emitted caller-census evidence')
    matches = list(re.finditer(r'^' + TIMING + r' elapsed_ns=([1-9][0-9]{0,38})$', content, re.M))
    require(content.count(TIMING) == 1 and len(matches) == 1,
            'missing, duplicated or malformed component timing marker')
    found = matches[0]
    elapsed = positive_u128(int(found.group(1)), 'component elapsed')
    wall = positive_u128(observation_ns, 'runner observation before validation')
    child_ns = positive_u128(child.get('total_proving_lifecycle_ns'), 'child lifecycle')
    outer_ns = positive_u128(outer.get('total_qualification_ns'), 'outer qualification')
    report_position = content.find(OUTER_REPORT)
    require(0 <= report_position < found.start() < footer_position,
            'component timing is outside successful outer report/footer boundary')
    require(child_ns + outer_ns <= elapsed <= wall,
            'component timing disagrees with disjoint phases or runner wall')
    return dict(fresh_child_to_outer_component_ns=elapsed,
                timing_scope='fresh-child-through-outer-component-cleanup',
                complete_ringct_workflow=False, performance_qualified=False)


def child_only(content):
    require(TIMING not in content and ORCHESTRATION not in content,
            'child-only qualifier emitted outer timing or caller-census evidence')
