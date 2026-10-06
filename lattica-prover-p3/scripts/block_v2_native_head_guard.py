"""Stop obsolete proving work without confusing the owner's own publication."""
import json
import os
from pathlib import Path
import time
import block_v2_controller_bootstrap as C


def handoff_record(native, directory, pid):
    return dict(schema_version=1, record_type='native_application_handoff', owner_pid=pid,
                native_host_binding=native.binding, current_head_token=native.current_head.token,
                proof_sha256=C.G.digest(Path(directory) / 'root-only/node.6.0'))


def owner_pid(directory):
    pid = C.read(Path(directory) / 'coordinator-startup/started.json')['pid']
    if type(pid) is not int or pid <= 0:
        raise ValueError('native application handoff has no valid owner identity')
    return pid


def publish_handoff(native, directory):
    directory = Path(directory)
    if owner_pid(directory) != os.getpid():
        raise ValueError('native application handoff does not belong to this owner')
    C.publish(directory / 'native-application-started.json', handoff_record(native, directory, os.getpid()))


def head_change(native):
    if native is None:
        return None
    expected = native.current_head.token
    observed = native.store.published_head_token()
    if observed == expected:
        return None
    return dict(schema_version=1, reason='published_native_head_changed',
                expected_head_token=expected, observed_head_token=observed,
                expected_generation=native.current_head.generation,
                observed_monotonic_ns=time.monotonic_ns(), observed_unix_ns=time.time_ns(),
                observation_is_native_validation=False)


def observe(native, directory):
    change = head_change(native)
    if change is None:
        return None
    directory = Path(directory)
    path = directory / 'native-application-started.json'
    if path.exists():
        pid = owner_pid(directory)
        if json.dumps(C.read(path), sort_keys=True, allow_nan=False) != json.dumps(
                handoff_record(native, directory, pid), sort_keys=True, allow_nan=False):
            raise ValueError('native application handoff differs from the owner, binding or root')
        # The GPU fleet has already completed and drained. Native compare-and-
        # swap and receipt verification now fence this short application phase.
        return None
    return change


def failed_application(native, directory):
    path = Path(directory) / 'result.json'
    if native is None or not path.is_file():
        return None
    result = C.read(path)
    if (result.get('status') != 'failed' or not str(result.get('failure', '')).startswith('StaleHead:') or
            type(result.get('native_blocks_applied')) is not int or result['native_blocks_applied'] != 0 or
            result.get('native_application_status') == 'indeterminate'):
        return None
    change = head_change(native)
    if change is not None:
        change['detected_after_application_handoff'] = True
    return change
