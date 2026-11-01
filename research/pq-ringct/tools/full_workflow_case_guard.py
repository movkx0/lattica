"""Exact fresh N3/N4 screening. Acceptance is not a performance comparison."""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
from owned_workflow_case_receipts import parse_record, validate as validate_receipts

from host_memory_profiles import selected_host_profile

GIB = 1 << 30
PREFIX = 'RINGCT_FULL_WORKFLOW_CASE '
SCHEMA = 'lattica-research-ringct-complete-case-v2'
KEY = 'full_workflow_case_environment'
FAMILIES = ('sources', 'algebra', 'crypto', 'auxiliary', 'outer')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def configure(args, argv, environment, root, state):
    require(args.profile == 'full' and args.build_label,
            'complete RingCT case requires full profile and exact build label')
    require(not any((args.expect_tests, args.expect_result, args.expect_direct_result,
                     args.record_artifact, getattr(args, 'benchmark', False),
                     getattr(args, 'correctness_label', None))),
            'complete case requires its own screening acceptance mode')
    require(getattr(args, 'public_hash_kernel', 'baseline') in ('baseline', 'sbox-pair-v1')
            and getattr(args, 'retained_tree_storage', 'device') == 'host',
            'complete case requires a known hash selection and explicit host-retained trees')
    require(Path(argv[0]) == root / '.tools/target-opencl/release/pq-ringct-full-workflow',
            'complete case requires the exact release research executable')
    options = ['--case', '--layout', '--seed', '--context']
    selected = selected_host_profile(getattr(args, 'host_profile', 'standard'))
    driver_args = list(argv)
    if '--host-profile' in driver_args:
        require(len(driver_args) >= 3 and driver_args[-2] == '--host-profile',
                'host profile must be the final explicit option')
        require(driver_args[-1] == selected['name'], 'runner/driver host-memory profile mismatch')
        driver_args = driver_args[:-2]
    else:
        require(selected['name'] == 'standard', 'expanded host profile must be explicit in the driver')
    planning_cache = 'geometry-v1'
    if '--planning-cache' in driver_args:
        require(len(driver_args) >= 3 and driver_args[-2] == '--planning-cache',
                'planning cache must follow identity options and precede host profile')
        planning_cache = driver_args[-1]
        require(planning_cache in ('off', 'geometry-v1'), 'unknown planning cache')
        driver_args = driver_args[:-2]
    metadata_workers = 'auto'
    if '--metadata-cpu-workers' in driver_args:
        require(len(driver_args) >= 3 and driver_args[-2] == '--metadata-cpu-workers',
                'metadata workers must follow identity options and precede planning cache')
        metadata_workers = driver_args[-1]
        driver_args = driver_args[:-2]
    require(metadata_workers == 'auto' or metadata_workers in tuple(map(str, range(1, 17))),
            'invalid metadata CPU workers')
    require((len(driver_args) == 9 and driver_args[1::2] == options)
            or (len(driver_args) == 11 and driver_args[1::2] == options + ['--identity-cpu-workers']),
            'complete case requires ordered case/layout/seed/context and optional CPU worker ceiling')
    case, layout, seed, context = driver_args[2:9:2]
    workers = 'auto' if len(driver_args) == 9 else driver_args[10]
    require(workers == 'auto' or workers in tuple(map(str, range(1, 17))), 'invalid identity CPU workers')
    from opencl_private_spend_validate import identity_physical_cpus
    maximum = min(16 if workers == 'auto' else int(workers), len(identity_physical_cpus()))
    identity = {'requested_workers': None if workers == 'auto' else int(workers), 'max_streams': maximum}
    metadata = {'requested_workers': None if metadata_workers == 'auto' else int(metadata_workers),
                'max_workers': min(16 if metadata_workers == 'auto' else int(metadata_workers),
                                   len(identity_physical_cpus()))}
    require(case in ('n3', 'n4') and layout in ('singleton', 'paired-v1'),
            'unknown complete case or SHAKE layout')
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in (seed, context)),
            'complete case identities must be canonical lowercase hex')
    require(environment.get('LATTICA_PROVING_POLICY') == 'gpu-required'
            and environment.get('LATTICA_V2_GPU_MANAGED_BYTES') == str(8 * GIB)
            and environment.get('LATTICA_V2_GPU_CONTEXT_BYTES') == str(4 * GIB)
            and environment.get('LATTICA_V2_HOST_OUTPUT_BYTES') == str(32 * GIB)
            and environment.get('RAYON_NUM_THREADS') == '8',
            'complete case resource environment differs from full profile')
    require(environment.get('LATTICA_GPU_DEVICE_UUID'),
            'complete case requires an explicit physical GPU UUID')
    require(environment.get('LATTICA_V2_GPU_RETAINED_TREE_STORAGE') == 'host'
            and environment.get('LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES') == str(8 * GIB)
            and environment.get('LATTICA_V2_GPU_LDE_WORKSPACE_BYTES') == '0',
            'complete case requires the source-selected outer_host_v1 tree profile')
    # The concrete owned runtime requires a 24 GiB native/PCS cap. Its worker
    # ledger independently retains the unchanged 32 GiB allowance. Generic
    # full-profile setup above is checked before this narrower runtime choice.
    environment['LATTICA_V2_HOST_OUTPUT_BYTES'] = str(24 * GIB)
    environment['LATTICA_RINGCT_HOST_PROFILE'] = selected['name']
    destination = state / 'artifacts' / args.label / 'full-case'
    require(not destination.exists() and not destination.is_symlink(),
            'complete case artifact directory must be fresh')
    return {'schema': SCHEMA, 'case': case, 'layout': layout,
            'identity_cpu': identity,
            'metadata_cpu': metadata,
            'setup_seed': list(bytes.fromhex(seed)), 'context': list(bytes.fromhex(context)),
            'output_directory': str(destination), 'screening_only': True,
            'runtime_tree_profile': 'outer_host_v1', 'worker_host_bytes': selected['worker_host_bytes'], 'host_profile': selected['name'],
            'planning_cache': planning_cache,
            'native_host_bytes': 24 * GIB, 'retained_tree_host_bytes': 8 * GIB}


def prepare_directory(plan):
    destination = Path(plan[KEY]['output_directory'])
    require(not destination.exists() and not destination.is_symlink(),
            'complete case artifact directory is no longer fresh')
    require(not any(parent.is_symlink() for parent in destination.parents),
            'complete case artifact directory has a symlink ancestor')
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)


def natural(value, name, positive=False):
    require(type(value) is int and (value > 0 if positive else value >= 0)
            and value < (1 << 128),
            'invalid complete case counter: ' + name)
    return value


def validate_envelope(envelope, plan):
    expected = plan[KEY]
    require(type(envelope) is dict, 'invalid complete case envelope')
    require(envelope.get('schema') == SCHEMA and expected.get('schema') == SCHEMA,
            'wrong complete case schema')
    selected = selected_host_profile(expected.get('host_profile', 'standard'))
    require(envelope.get('host_profile', 'standard') == selected['name']
            and envelope.get('worker_host_bytes', 32 * GIB) == selected['worker_host_bytes']
            and expected.get('worker_host_bytes', 32 * GIB) == selected['worker_host_bytes'],
            'complete case host-memory profile mismatch')
    for key in ('case', 'layout', 'setup_seed', 'context'):
        require(envelope.get(key) == expected[key], 'complete case identity mismatch: ' + key)
    identity = expected.get('identity_cpu')
    reported_identity = envelope.get('identity_cpu')
    require(type(reported_identity) is dict and set(reported_identity) == {'requested_workers', 'max_streams'}
            and type(reported_identity['max_streams']) is int and 1 <= reported_identity['max_streams'] <= 16
            and (reported_identity['requested_workers'] is None or type(reported_identity['requested_workers']) is int
                 and 1 <= reported_identity['requested_workers'] <= 16)
            and reported_identity == identity,
            'complete case CPU identity selection mismatch')
    for key in ('setup_seed', 'context'):
        digest_bytes(envelope.get(key), key)
    require(envelope.get('proof_policy') == 'fresh-only'
            and envelope.get('proving_policy') == 'gpu-required',
            'complete case changed proving policy')
    report = envelope.get('report')
    require(type(report) is dict, 'missing complete case report')
    if 'metadata_cpu' in expected:
        selection = envelope.get('metadata_cpu')
        require(type(selection) is dict and selection == expected['metadata_cpu']
                and set(selection) == {'requested_workers', 'max_workers'}
                and type(selection['max_workers']) is int
                and (selection['requested_workers'] is None or type(selection['requested_workers']) is int),
                'complete case metadata CPU selection mismatch')
        metadata = report.get('metadata_planning')
        require(type(metadata) is dict, 'missing metadata planning report')
        for key in ('worker_ceiling', 'peak_active_workers', 'largest_cohort', 'envelopes',
                    'heights_completed', 'jobs_started', 'cohorts', 'budget_reductions',
                    'failed_envelopes', 'admitted_host_bytes_peak', 'wall_ns', 'worker_elapsed_ns'):
            natural(metadata.get(key), 'metadata_planning.' + key)
        for key in ('symbolic_preparations', 'shared_symbolic_bytes_peak', 'worker_auxiliary_bytes_peak'):
            natural(metadata.get(key), 'metadata_planning.' + key)
        active = metadata['heights_completed'] > 0
        geometry = report.get('source_geometry_cache')
        if active:
            require(1 <= metadata['peak_active_workers'] <= metadata['largest_cohort'] <= metadata['worker_ceiling']
                    and metadata['jobs_started'] >= metadata['heights_completed']
                    and metadata['symbolic_preparations'] == metadata['envelopes'] > 0
                    and metadata['cohorts'] > 0 and metadata['shared_symbolic_bytes_peak'] > 0
                    and metadata['worker_auxiliary_bytes_peak'] > 0, 'invalid metadata compiler accounting')
        else:
            require(expected.get('planning_cache') == 'geometry-v1' and type(geometry) is dict
                    and type(geometry.get('table_hits')) is int and geometry['table_hits'] > 0,
                    'no metadata compiler work or qualified table work')
            require(all(metadata[key] == 0 for key in metadata if key != 'worker_ceiling'),
                    'table-only metadata reported compiler activity')
        require(metadata['worker_ceiling'] == selection['max_workers']
                and metadata['failed_envelopes'] == 0
                and metadata['admitted_host_bytes_peak'] <= selected['worker_host_bytes'],
                'invalid metadata worker accounting')
    geometry = report.get('source_geometry_cache')
    if expected.get('planning_cache', 'off') == 'geometry-v1':
        require(type(geometry) is dict, 'missing selected geometry cache report')
        for key in ('hits', 'misses', 'evictions', 'failed_computations', 'planning_ns', 'entries', 'reserved_host_bytes'):
            natural(geometry.get(key), 'source_geometry_cache.' + key)
        natural(geometry.get('table_hits', 0), 'source_geometry_cache.table_hits')
        require(geometry.get('table_hits', 0) <= geometry['misses'], 'table hits exceed misses')
        require(geometry['reserved_host_bytes'] == 1 << 20 and geometry['entries'] <= 64
                and geometry['failed_computations'] == 0,
                'invalid geometry cache budget or failed source construction')
    else:
        require(geometry is None, 'unexpected planning cache work')
    if 'metadata_cpu' in expected:
        native = report.get('native_metadata_cache')
        if expected.get('planning_cache') == 'geometry-v1':
            require(type(native) is dict, 'missing native metadata cache report')
            for key in ('hits', 'misses', 'evictions', 'failed_computations', 'planning_ns', 'entries', 'reserved_host_bytes'):
                natural(native.get(key), 'native_metadata_cache.' + key)
            require(native['reserved_host_bytes'] == 1 << 20 and native['entries'] <= 256
                    and native['failed_computations'] == 0, 'invalid native metadata cache accounting')
        else:
            require(native is None, 'unexpected native metadata cache work')
    observed_identity = report.get('owned_observations', {}).get('identity_preprocessing')
    require(type(observed_identity) is dict and observed_identity.get('finalizations', 0) > 0,
            'complete case omitted CPU identity finalization')
    require(report.get('cache_counter_scope') == 'instrumented-cache-paths'
            and report.get('qualification_scope') == 'final-aggregate',
            'complete case observation scope is ambiguous')
    require(natural(report.get('transactions'), 'transactions', positive=True)
            == {'n3': 3, 'n4': 4}[expected['case']],
            'wrong complete case transaction inventory')
    for name in ('native_proofs', 'recursive_proofs', 'completed_phases',
                 'generation_and_planning_ns', 'proving_and_verification_ns',
                 'final_cpu_verification_ns', 'complete_workflow_ns'):
        natural(report.get(name), name, positive=True)
    require(report['generation_and_planning_ns'] + report['proving_and_verification_ns']
            <= report['complete_workflow_ns']
            and report['final_cpu_verification_ns'] <= report['proving_and_verification_ns'],
            'complete case timings do not include the complete workflow')
    for name, limit in (('ledger_peak_host_bytes', selected['worker_host_bytes']),
                        ('ledger_peak_device_bytes', 8 * GIB)):
        require(natural(report.get(name), name, positive=True) <= limit,
                'complete case reservation peak exceeds allowance')
    require(report.get('artifacts_qualified') is True and report.get('mutations_qualified') is True,
            'complete case lacks artifact round-trip and mutation qualification')
    statistics = report.get('cache_statistics')
    require(type(statistics) is list and len(statistics) == len(FAMILIES),
            'complete case omitted fixed cache family counters')
    for name, counters in zip(FAMILIES, statistics):
        require(type(counters) is dict, 'invalid cache counters: ' + name)
        for counter in ('reads', 'hits', 'bypasses', 'proof_attempts', 'fresh_proofs'):
            natural(counters.get(counter), name + '.' + counter)
        require(counters['reads'] == counters['hits'] == 0,
                'complete case accessed a cached proof payload')
        require(counters['proof_attempts'] == counters['fresh_proofs'],
                'complete case contains incomplete proof attempts')
    # Owned producers that bypass Control are measured by actual report
    # observations. Cache counters describe only instrumented cache paths.
    require(sum(c['fresh_proofs'] for c in statistics[:4]) <= report['native_proofs']
            and statistics[4]['fresh_proofs'] <= report['recursive_proofs'],
            'cache path counters exceed the complete proof inventory')
    return report


def digest_bytes(value, name):
    require(type(value) is list and len(value) == 32
            and all(type(v) is int and 0 <= v <= 255 for v in value),
            'invalid artifact identity: ' + name)
    return bytes(value)


def validate_artifact(report, plan):
    qualification = report.get('final_qualification')
    require(type(qualification) is dict, 'missing actual final artifact qualification')
    for key in ('decoded_positive_checks', 'height', 'public_values', 'file_inode'):
        natural(qualification.get(key), key, positive=True)
    natural(qualification.get('file_device'), 'file_device')
    require(all(qualification.get(key) is True for key in
                ('artifact_round_trip', 'public_mutation_rejected', 'proof_mutation_rejected'))
            and qualification.get('decoded_positive_checks') == 3,
            'final artifact lacks successful decoded proof and mutation checks')
    digest = digest_bytes(qualification.get('packet_sha3_256'), 'packet_sha3_256')
    directory = Path(plan[KEY]['output_directory'])
    path = directory / ('ringct-final-' + digest.hex() + '.bin')
    require(list(directory.iterdir()) == [path], 'unexpected complete case artifact inventory')
    proof_bytes = natural(qualification.get('proof_bytes'), 'proof_bytes', positive=True)
    packet_bytes = natural(qualification.get('packet_bytes'), 'packet_bytes', positive=True)
    # Existing LBV2RP02 registered-proof limit; never raise the decoder ceiling.
    require(8 <= proof_bytes <= 2 * 1024 * 1024 and packet_bytes == 2456 + proof_bytes
            and packet_bytes <= 2 * 1024 * 1024,
            'final artifact violates existing wire format limits')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as artifact:
        before = os.fstat(artifact.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == packet_bytes
                and before.st_dev == qualification.get('file_device')
                and before.st_ino == qualification.get('file_inode'),
                'final artifact provenance or length mismatch')
        header = artifact.read(2456)
        require(len(header) == 2456 and header[:8] == b'LQRFN001'
                and struct.unpack_from('<Q', header, 8) == (1,),
                'final artifact version mismatch')
        for offset, key in ((16, 'compiled_source_fingerprint'), (48, 'source_fingerprint'),
                            (80, 'batch_profile'), (112, 'context')):
            require(header[offset:offset + 32] == digest_bytes(qualification.get(key), key),
                    'final artifact identity mismatch: ' + key)
        require(qualification['context'] == plan[KEY]['context'],
                'final artifact context differs from requested case')
        merge, first, count, total, height, public, caps, inner = struct.unpack_from('<8Q', header, 144)
        require(first == 0 and count == total == report['transactions'] and merge + 2 == total
                and height == qualification.get('height') and 8 <= height <= (1 << 20)
                and height & (height - 1) == 0
                and public == qualification.get('public_values') == 25 and caps == 64 and inner == proof_bytes,
                'final artifact aggregate coverage or shape mismatch')
        require(all(value[0] < 0xFFFFFFFF00000001 for value in struct.iter_unpack('<Q', header[208:])),
                'final artifact contains noncanonical field values')
        hasher = hashlib.sha3_256(header)
        inner_magic = artifact.read(8)
        require(inner_magic == b'LBV2RP02', 'final artifact inner proof schema mismatch')
        hasher.update(inner_magic)
        remaining = proof_bytes - 8
        while remaining:
            block = artifact.read(min(1 << 20, remaining))
            require(block, 'final artifact was truncated during audit')
            hasher.update(block)
            remaining -= len(block)
        require(artifact.read(1) == b'' and hasher.digest() == digest,
                'final artifact digest or EOF mismatch')
        after = os.fstat(artifact.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'final artifact changed during audit')
    return {'path': str(path), 'packet_sha3_256': digest.hex(), 'packet_bytes': packet_bytes,
            'file_device': before.st_dev, 'file_inode': before.st_ino}


def validate_log(content, plan, collect_gpu_receipts):
    envelopes = [parse_record(line[len(PREFIX):], PREFIX.rstrip()) for line in content.splitlines()
                 if line.startswith(PREFIX)]
    require(len(envelopes) == 1, 'expected exactly one complete RingCT case report')
    report = validate_envelope(envelopes[0], plan)
    observed_ns = natural(plan.get('observation_before_validation_ns'), 'runner observation', positive=True)
    require(report['complete_workflow_ns'] <= observed_ns,
            'complete workflow time exceeds runner observation')
    receipts = validate_receipts(content, report, collect_gpu_receipts, verification_mode='exact-dispatch-v1')
    require(receipts['identity_preprocessing']['max_streams']
            <= plan[KEY].get('identity_preprocessing', {'max_streams': 1})['max_streams'],
            'identity cohort exceeds selected ceiling')
    artifact = validate_artifact(report, plan)
    return {'schema': SCHEMA, 'case': envelopes[0]['case'], 'layout': envelopes[0]['layout'],
            'setup_seed': envelopes[0]['setup_seed'], 'context': envelopes[0]['context'],
            'report': report, 'receipts': receipts, 'artifact': artifact,
            'qualification_scope': 'final-aggregate', 'screening_only': True,
            'comparison_baseline': False, 'performance_qualified': False}
