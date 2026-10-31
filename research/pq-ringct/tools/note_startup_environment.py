"""Bounded parent-side environment for private-note research startup.

This constructs data for a future env_clear/exec boundary. It does not launch
a process, admit an OpenCL constructor, or authorize proving. Driver, runtime,
thread and payload owners require separate admission and qualification.
"""
from hashlib import sha256
from pathlib import Path
import re

GIB = 1 << 30
MAX_ENTRIES = 64
MAX_NAME_BYTES = 96
MAX_VALUE_BYTES = 1024
MAX_ENVIRONMENT_BYTES = 8192
ROOT = Path(__file__).resolve().parents[3]
GPU_SWITCHES = (
    'HASH', 'RETAIN_TREES', 'QUERY_GATHER', 'RESIDENT_LDE', 'OPENINGS',
    'QUOTIENT_LDE', 'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT', 'LOOKUP',
    'OPENING_EVAL', 'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS',
    'RANDOMNESS', 'TRANSCRIPT', 'FRI_FOLD',
)
FIXED = {'LATTICA_V2_GPU_' + name: '1' for name in GPU_SWITCHES}
FIXED.update({
    'LATTICA_V2_QUOTIENT_FUSION': '1',
    'LATTICA_PROVING_REPORT': '1',
    'LATTICA_PROVING_POLICY': 'gpu-required',
    'LATTICA_V2_GPU_PUBLIC_HASH': 'baseline',
    'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'device',
    'LATTICA_V2_GPU_PIPELINE': '0',
    'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * GIB),
    'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * GIB),
    'LATTICA_V2_HOST_OUTPUT_BYTES': str(24 * GIB),
    'RAYON_NUM_THREADS': '8',
})
BASE = {
    'PATH': '/home/access/code/lattica/.tools/rust-1.96.0/bin:/usr/bin:/bin',
    'HOME': '/home/access',
    'CARGO_HOME': str(ROOT / '.tools/cargo-opencl'),
    'CARGO_TARGET_DIR': str(ROOT / '.tools/target-opencl'),
    'CARGO_BUILD_JOBS': '2',
}
SELECTED = frozenset(('LATTICA_V2_GPU_DEVICE', 'LATTICA_GPU_DEVICE_UUID'))
KNOWN = frozenset(FIXED) | frozenset(BASE) | SELECTED


def require(ok, message):
    if not ok:
        raise ValueError(message)


def bounded_utf8(value, maximum, label):
    require(type(value) is str and len(value) <= maximum,
            'invalid or overlong ' + label)
    require('\0' not in value, 'NUL in ' + label)
    try:
        encoded = value.encode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('invalid UTF-8 ' + label) from error
    require(len(encoded) <= maximum, 'overlong encoded ' + label)
    return encoded


def validate_environment(entries):
    """Check bounded pairs before constructing the child environment dict.

    A tuple/list preserves duplicate names until they have been rejected.
    No arbitrary inherited environment is copied or accepted. The report is
    descriptive data only; no serialized field can grant dispatch authority.
    """
    require(type(entries) in (tuple, list) and len(entries) <= MAX_ENTRIES,
            'environment entry count or representation')
    result = {}
    total = 0
    for entry in entries:
        require(type(entry) in (tuple, list) and len(entry) == 2,
                'environment requires name/value pairs')
        name, value = entry
        encoded_name = bounded_utf8(name, MAX_NAME_BYTES, 'name')
        require(name and '=' not in name and name in KNOWN,
                'unknown or malformed environment name')
        require(name not in result, 'duplicate environment name')
        encoded_value = bounded_utf8(value, MAX_VALUE_BYTES, 'value')
        total += len(encoded_name) + len(encoded_value) + 2
        require(total <= MAX_ENVIRONMENT_BYTES, 'environment byte ceiling')
        result[name] = value
    require(set(result) == KNOWN, 'missing required startup environment')
    require(all(result[name] == value for name, value in FIXED.items()),
            'changed fixed note startup policy')
    require(all(result[name] == value for name, value in BASE.items()),
            'changed fixed campaign base environment')
    require(re.fullmatch(r'0|[1-9][0-9]{0,2}', result['LATTICA_V2_GPU_DEVICE']) is not None,
            'noncanonical OpenCL device index')
    require(re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',
                         result['LATTICA_GPU_DEVICE_UUID']) is not None,
            'invalid physical device UUID')
    digest = sha256()
    for name in sorted(result):
        digest.update(name.encode('utf-8'))
        digest.update(b'=')
        digest.update(result[name].encode('utf-8'))
        digest.update(b'\0')
    return result, {
        'schema': 'private-note-startup-environment-v1',
        'entry_count': len(result),
        'serialized_bytes': total,
        'sha256_sorted_name_equals_value_nul': digest.hexdigest(),
        'requires_env_clear_before_exec': True,
        'requires_immutable_environment_after_exec': True,
        'physical_identity_verified': False,
        'complete_external_admission': False,
        'dispatch_authority': False,
    }


def build_environment(device_index, device_uuid):
    require(type(device_index) is int and 0 <= device_index <= 999,
            'invalid OpenCL device index')
    entries = [*FIXED.items(), *BASE.items(),
               ('LATTICA_V2_GPU_DEVICE', str(device_index)),
               ('LATTICA_GPU_DEVICE_UUID', device_uuid)]
    return validate_environment(entries)
