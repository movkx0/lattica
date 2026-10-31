"""Source/build-bound complete N3/N4 research evidence; never protocol promotion.

The enclosing runner owns exclusive dispatch, process/swap limits, executable and
source hashes, and terminal reaping. This module cannot authorize GPU work. Its
artifact checks bind the files to the independently verified driver output; they
are not a standalone cryptographic verifier for arbitrary archived artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from opencl_direct_spend_audit import native, terminal, phase_bounds
from public_hash_evidence import require_requested

GIB = 1 << 30
P = 0xffffffff00000001
SELECTOR = ('ring_circuit::aggregation::tests::complete::'
            'direct_ring_n3_n4_complete_owned_aggregates_roundtrip_and_retire')
FEATURE = 'ring-direct-aggregate-experiment'
FILES = frozenset(('N3.aggregate', 'N3.report.json', 'N4.aggregate', 'N4.report.json', 'complete.json'))
MAX_ARTIFACT = (2 << 20) + 212
MAX_JSON = 4 << 20


def require(value, message):
    if not value:
        raise ValueError('direct aggregate: ' + message)


def integer(value, low=0, high=(1 << 128) - 1):
    require(type(value) is int and low <= value <= high, 'invalid bounded integer')
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), 'report fields changed')
    return value


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON field')
        value[key] = item
    return value


def decode_json(data):
    def invalid_constant(_):
        raise ValueError('direct aggregate: nonfinite JSON number')
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def read_bounded(path, maximum):
    # Refuse substituted symlink/special files and never read beyond the bound.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                'missing, special, empty or oversized evidence')
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        require(len(data) == before.st_size and (before.st_dev, before.st_ino,
                before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'evidence changed while read')
    return data


def environment(args, argv, trees, kernel, base, state):
    require(args.profile == 'direct-full' and args.expect_tests and args.build_label,
            'exact direct-full recorded test required')
    require(not args.expect_result and not getattr(args, 'expect_direct_result', False)
            and not getattr(args, 'benchmark', False) and not getattr(args, 'correctness_label', None),
            'research workflow cannot qualify a faithful benchmark')
    require(trees == 'host' and kernel == 'baseline' and getattr(args, 'device_uuid', None),
            'baseline public hash, host trees and physical GPU pin required')
    require(Path(argv[0]).name.startswith('lattica_pq_direct_spend_research-') and argv[1:] == [
        SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
        'exact single complete driver required')
    requested = Path(state) / 'artifacts' / args.label
    require(not requested.exists() and not requested.is_symlink(), 'destination must be new')
    output = requested.resolve()
    require(len(str(output).encode('utf-8')) <= 384, 'destination exceeds driver path bound')
    value = dict(base)
    value.update(LATTICA_DIRECT_RING_AGGREGATE_QUALIFICATION='1',
                 LATTICA_DIRECT_RING_AGGREGATE_OUTPUT=str(output))
    serialized = b''.join((name + '=' + value[name] + '\0').encode('utf-8') for name in sorted(value))
    return value, dict(schema='direct-ring-complete-n3-n4-environment-v1', selector=SELECTOR,
        output_directory=str(output), entry_count=len(value), serialized_bytes=len(serialized),
        sha256_sorted_name_equals_value_nul=hashlib.sha256(serialized).hexdigest(),
        requires_env_clear_before_exec=True, requires_immutable_environment_after_exec=True,
        dispatch_authority=False, complete_faithful_ringct_workflow=False,
        performance_qualified=False, security_adoption_review_complete=False)


def require_build(plan, executable, root):
    if plan.get('direct_ring_aggregate_environment') is None:
        return
    # Normal runner provenance already verifies the exact binary, Cargo emitted
    # inventory, terminal build and entire source map, before this feature check.
    path = Path(executable['build_record'])
    data = read_bounded(path, 16 << 20)
    require(hashlib.sha256(data).hexdigest() == executable['build_record_sha256'], 'build record changed')
    build = decode_json(data)
    argv = build.get('command', [])
    require(argv and Path(argv[0]).name == 'cargo' and argv[1:2] == ['test']
            and all(flag in argv for flag in ('--release', '--locked', '--offline',
                        '--no-default-features', '--lib', '--no-run'))
            and not any(arg == '--profile' or arg.startswith('--profile=')
                        or arg == '--all-features' for arg in argv), 'release isolated build required')
    features, manifests = [], []
    for index, arg in enumerate(argv):
        for flag, output in (('--features', features), ('--manifest-path', manifests)):
            if arg == flag:
                require(index + 1 < len(argv), 'missing build argument')
                output.append(argv[index + 1])
            elif arg.startswith(flag + '='):
                output.append(arg.split('=', 1)[1])
    require(len(features) == len(manifests) == 1
            and re.split(r'[,\s]+', features[0]) == [FEATURE], 'exact default-disabled feature required')
    manifest = Path(manifests[0])
    require((manifest if manifest.is_absolute() else Path(root) / manifest).resolve() ==
            (Path(root) / 'research/pq-direct-spend/Cargo.toml').resolve(), 'wrong research manifest')


def plan_contract(plan):
    selected = plan.get('direct_ring_aggregate_environment')
    require(type(selected) is dict and selected.get('selector') == SELECTOR, 'wrong driver selection')
    require(plan.get('profile') == 'direct-full' and plan.get('expect_tests') is True
            and plan.get('expect_result') is False and plan.get('expect_direct_result') is False
            and plan.get('benchmark') is False and plan.get('performance_qualified') is False
            and plan.get('correctness_label') is None and plan.get('record_artifacts') == [],
            'wrong research execution scope')
    require((plan.get('memory_max_bytes'), plan.get('memory_high_bytes'),
             plan.get('fresh_memavailable_required_bytes'), plan.get('cpu_quota')) ==
            (45 * GIB, 43 * GIB, 47 * GIB, '800%'), 'original process envelope changed')
    argv = plan.get('command', [])
    require(argv and Path(argv[0]).name.startswith('lattica_pq_direct_spend_research-')
            and argv[1:] == [SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            'complete test selector changed')
    env = plan.get('environment', {})
    expected = dict(LATTICA_PROVING_POLICY='gpu-required', LATTICA_PROVING_REPORT='1',
        LATTICA_V2_GPU_MANAGED_BYTES=str(8 * GIB), LATTICA_V2_GPU_CONTEXT_BYTES=str(4 * GIB),
        LATTICA_V2_HOST_OUTPUT_BYTES=str(32 * GIB), LATTICA_V2_GPU_RETAINED_TREE_STORAGE='host',
        LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES=str(8 * GIB), LATTICA_V2_GPU_LDE_WORKSPACE_BYTES='0',
        LATTICA_V2_GPU_PUBLIC_HASH='baseline', RAYON_NUM_THREADS='8',
        LATTICA_DIRECT_RING_AGGREGATE_QUALIFICATION='1',
        LATTICA_DIRECT_RING_AGGREGATE_OUTPUT=selected.get('output_directory'))
    require(all(env.get(key) == value for key, value in expected.items()), 'fixed environment changed')
    require(re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',
                        env.get('LATTICA_GPU_DEVICE_UUID', '')) is not None, 'missing physical GPU pin')
    serialized = b''.join((name + '=' + env[name] + '\0').encode('utf-8') for name in sorted(env))
    require(selected.get('entry_count') == len(env) and selected.get('serialized_bytes') == len(serialized)
            and selected.get('sha256_sorted_name_equals_value_nul') == hashlib.sha256(serialized).hexdigest(),
            'sanitized environment differs from selection')
    return selected, list(bytes.fromhex(env['LATTICA_GPU_DEVICE_UUID'][4:].replace('-', '')))


def descriptor(value):
    fields(value, 'active_rows padded_rows wires witness_values canonical_manifest_digest registered_program_id')
    active = integer(value['active_rows'], 1, 1 << 20)
    padded = integer(value['padded_rows'], 8, 1 << 20)
    require(padded & (padded - 1) == 0 and active <= padded, 'invalid recursive row closure')
    integer(value['wires'], 4, 1 << 26)
    integer(value['witness_values'], 1, (1 << 24) - 4)
    digest = value['canonical_manifest_digest']
    require(type(digest) is list and len(digest) == 32, 'manifest length')
    for word in digest:
        integer(word, 0, 255)
    identity = value['registered_program_id']
    require(type(identity) is list and len(identity) == 4, 'registered identity length')
    for word in identity:
        integer(word, 0, P - 1)
    return tuple(digest), tuple(identity)


def storage(value, n):
    fields(value, '''worker_host_bytes device_bytes context_reserve_bytes native_host_ceiling_bytes
        caller_reserved_bytes expected_statement_bytes native_witness_bytes verifier_lifecycle_bytes_each
        verifier_slots proof_slots proof_bytes_each all_retained_reservation_bytes active_host_partition_bytes''')
    for field, exact in (('worker_host_bytes', 32 * GIB), ('device_bytes', 8 * GIB),
            ('context_reserve_bytes', 4 * GIB), ('native_host_ceiling_bytes', 24 * GIB),
            ('caller_reserved_bytes', 4 << 20), ('verifier_slots', n + 1),
            ('proof_slots', n + 1), ('proof_bytes_each', 64 << 20)):
        require(integer(value[field]) == exact, 'retained source allowance changed: ' + field)
    statements = integer(value['expected_statement_bytes'], 1, 32 * GIB)
    witnesses = integer(value['native_witness_bytes'], 1, 32 * GIB)
    cpu = integer(value['verifier_lifecycle_bytes_each'], 64 << 20, 32 * GIB)
    retained = integer(value['all_retained_reservation_bytes'], 1, 32 * GIB)
    active = integer(value['active_host_partition_bytes'], 1, 32 * GIB)
    require(retained == (4 << 20) + statements + witnesses + (n + 1) * (cpu + (64 << 20))
            and active + retained == 32 * GIB, 'simultaneous retained owners escaped original worker')
    return active


def phase(value, kind, index, active, uuid, native_reports, public_hash):
    fields(value, '''kind child_index fresh_proof descriptor footprint registration proving public_hash terminal
        setup_ns proving_ns teardown_ns total_ns''')
    fresh = kind in ('fresh_whole_transaction_proof', 'fresh_fixed_aggregate_proof')
    require(value['kind'] == kind and value['child_index'] == index
            and (index is None or type(value['child_index']) is int)
            and value['fresh_proof'] is fresh, 'phase order, exact child or proof scope changed')
    descriptor(value['descriptor'])
    native(value['registration'], False)
    native_reports.append(value['registration'])
    if fresh:
        native(value['proving'], True)
        native_reports.append(value['proving'])
    else:
        require(value['proving'] is None, 'public-only setup claims proving')
    terminal(value['terminal'], fresh)
    observed = require_requested(value['public_hash'], 'baseline', 'baseline')
    require(not public_hash or public_hash[0] == observed, 'public hash changed between phases')
    public_hash[:] = [observed]
    footprint = value['footprint']
    require(type(footprint) is dict and footprint.get('host_phase_bound_complete') is True
            and footprint.get('device_phase_bound_complete') is True, 'incomplete memory admission')
    require(footprint.get('physical_device_uuid') == uuid and footprint.get('rows') == value['descriptor']['padded_rows']
            and footprint.get('tree_storage_mode') == 'host_backing'
            and footprint.get('host_tree_quota_bytes') == 8 * GIB, 'phase device/geometry/tree drift')
    inputs = ((1 << 20) if index is None else (1 << 24) - 4) * 8
    require(footprint.get('input_backing_host_bytes') == inputs
            and footprint.get('caller_reserved_host_bytes') == 1 << 20
            and footprint.get('runtime_host_reserved_bytes') == 2 << 20, 'fixed phase input/caller reserve drift')
    native_host = min(24 * GIB, active - inputs - (1 << 20) - 8 * GIB)
    require(native_host > 2 << 20 and footprint.get('native_host_budget_bytes') == native_host
            and footprint.get('backend_host_budget_bytes') == native_host - (2 << 20)
            and footprint.get('worker_committed_host_bytes') == native_host + inputs + (1 << 20) + 8 * GIB,
            'phase exceeds original active/native partition')
    phase_bounds(footprint, worker_host_limit=active)
    setup = integer(value['setup_ns'], 1)
    prove = integer(value['proving_ns'], 1 if fresh else 0)
    require(fresh or prove == 0, 'setup claims fresh proving time')
    teardown = integer(value['teardown_ns'], 1)
    require(setup + prove + teardown <= integer(value['total_ns'], 1), 'phase timing overlaps')


def profile_digest(n):
    # Exact source constants for the isolated wide-lane, capacity64 build.
    local = hashlib.sha3_256()
    for part in (b'lattica/research/direct-ring/full-proof/profile/v1',
                 b'lattica/research/ring-direct-v1/n10/in2/out2/bits52',
                 b'fused-ternary-ranges-v1', b'LATTICA-BLOCK-V2-CANDIDATE-00001'):
        local.update(part)
    for word in (P, 167770241, 3489661057, 256, 10, 2, 2, 52, 23, 94, 3, 64, 2, 128, 4, 6, 4, 16, 191, 127):
        local.update(struct.pack('<Q', word))
    return hashlib.sha3_256(b'lattica/research/direct-ring/fixed-flat-aggregate/artifact/v1'
                           + local.digest() + struct.pack('<QQ', n, 4)).digest()


def artifact(data, n, desc, roundtrip):
    require(220 <= len(data) <= MAX_ARTIFACT and data[:8] == (b'LDAGG301' if n == 3 else b'LDAGG401')
            and data[212:220] == b'LBV2RP02', 'wrong aggregate count/domain or registered codec')
    require(data[8:40] == profile_digest(n) and struct.unpack_from('<I', data, 40)[0] == 5
            and data[44:76] == bytes([0x73] * 32), 'wrong isolated profile or fixture context')
    for word in struct.unpack_from('<4Q', data, 76):
        integer(word, 0, P - 1)
    require(tuple(desc[field] for field in ('active_rows', 'padded_rows', 'wires', 'witness_values')) ==
            struct.unpack_from('<4Q', data, 108), 'artifact geometry differs from independent source')
    require(bytes(desc['canonical_manifest_digest']) == data[140:172]
            and tuple(desc['registered_program_id']) == struct.unpack_from('<4Q', data, 172),
            'artifact identity differs from independent source')
    length = integer(struct.unpack_from('<Q', data, 204)[0], 8, 2 << 20)
    require(length + 212 == len(data) == roundtrip['encoded_bytes'], 'artifact length or roundtrip size changed')
    digest = roundtrip['artifact_sha3_256']
    require(type(digest) is list and len(digest) == 32, 'missing exact disk digest')
    for word in digest:
        integer(word, 0, 255)
    require(bytes(digest) == hashlib.sha3_256(data).digest(), 'disk bytes differ from independently verified roundtrip')


def case(report, summary, n, start, data, uuid, native_reports, public_hash):
    fields(report, '''schema scope selection proof_generation fresh_whole_transaction_proofs
        fresh_recursive_aggregate_proofs independent_child_cpu_acceptances independent_final_cpu_acceptances
        public_mutation_rejections opening_mutation_rejections restored_proof_acceptances envelope_rejections
        public_setup_reused_for_child_cpu_checks synthetic_hints_evaluated faithful_ringct_protocol
        production_acceptance redesign_2x_gate_passed security_adoption_review_complete compilation_ns
        source_planning_ns cpu_verification_ns mutation_checks_ns owned_workflow_ns source storage
        artifact_roundtrip phases''')
    fields(summary, '''selection fixture_start transactions whole_transaction_proofs recursive_aggregate_proofs
        independent_cpu_acceptances public_mutation_rejections opening_mutation_rejections setup_ns proving_ns
        cpu_verification_ns complete_workflow_ns''')
    name = 'N' + str(n)
    require(report['schema'] == 'lattica-research-direct-ring-fixed-aggregate-v1'
            and report['scope'] == 'complete owned direct-ring N3/N4 research aggregation'
            and report['selection'] == summary['selection'] == name
            and report['proof_generation'] == 'FreshOnly', 'wrong complete case/profile')
    for field in ('synthetic_hints_evaluated', 'faithful_ringct_protocol', 'production_acceptance',
                  'redesign_2x_gate_passed', 'security_adoption_review_complete'):
        require(report[field] is False, 'unqualified research promotion or synthetic execution')
    for field, count in (('fresh_whole_transaction_proofs', n), ('fresh_recursive_aggregate_proofs', 1),
            ('independent_child_cpu_acceptances', n), ('independent_final_cpu_acceptances', 1),
            ('public_mutation_rejections', 4 * (n + 1)), ('opening_mutation_rejections', n + 1),
            ('restored_proof_acceptances', n + 1), ('envelope_rejections', 3),
            ('public_setup_reused_for_child_cpu_checks', n)):
        require(integer(report[field]) == count, 'missing exact proof/verification/mutation credit: ' + field)
    for field, count in (('fixture_start', start), ('transactions', n), ('whole_transaction_proofs', n),
            ('recursive_aggregate_proofs', 1), ('independent_cpu_acceptances', n + 1),
            ('public_mutation_rejections', 4 * (n + 1)), ('opening_mutation_rejections', n + 1)):
        require(integer(summary[field]) == count, 'complete summary/case differs: ' + field)
    active = storage(report['storage'], n)
    source = fields(report['source'], '''children scalar_operations_upper_bound cubic_operations_upper_bound
        poseidon_operations_upper_bound active_rows_upper_bound padded_rows_upper_bound wires_upper_bound
        input_values_upper_bound construction_reserved_bytes source_closed_before_setup''')
    require(integer(source['children']) == n and source['source_closed_before_setup'] is True,
            'source closure did not precede setup')
    for field in ('scalar_operations_upper_bound', 'cubic_operations_upper_bound', 'poseidon_operations_upper_bound'):
        integer(source[field], 1)
    integer(source['construction_reserved_bytes'], 1, active)
    phases = report['phases']
    order = ([('expected_child_source', i) for i in range(n)]
             + [('fresh_whole_transaction_proof', i) for i in range(n)]
             + [('fresh_fixed_aggregate_proof', None)]
             + [('final_independent_child_source', i) for i in range(n)]
             + [('final_independent_root_source', None)])
    require(type(phases) is list and len(phases) == len(order) <= 16, 'missing or repeated phase')
    for item, (kind, index) in zip(phases, order):
        phase(item, kind, index, active, uuid, native_reports, public_hash)
    for index in range(n):
        require(phases[index]['descriptor'] == phases[n + index]['descriptor'] ==
                phases[2 * n + 1 + index]['descriptor'], 'child independent source changed')
    root = phases[2 * n]['descriptor']
    require(root == phases[-1]['descriptor'], 'final independent root source changed')
    for key, high in (('active_rows', 1 << 20), ('padded_rows', 1 << 20),
                      ('wires', 1 << 26), ('input_values', 1 << 20)):
        actual = root['witness_values' if key == 'input_values' else key]
        require(actual <= integer(source[key + '_upper_bound'], 1, high), 'actual root escapes source closure')
    transport = fields(report['artifact_roundtrip'], '''encoded_bytes decoded_proof_retained_bytes
        artifact_sha3_256 distinct_aggregate_domain exact_disk_roundtrip total_ns''')
    require(transport['distinct_aggregate_domain'] is True and transport['exact_disk_roundtrip'] is True,
            'actual final disk roundtrip missing')
    integer(transport['encoded_bytes'], 220, MAX_ARTIFACT)
    integer(transport['decoded_proof_retained_bytes'], 1, 64 << 20)
    artifact(data, n, root, transport)
    parts = sum(integer(report[field], 1) for field in ('compilation_ns', 'source_planning_ns',
        'cpu_verification_ns', 'mutation_checks_ns')) + integer(transport['total_ns'], 1)
    parts += sum(item['total_ns'] for item in phases)
    require(parts <= integer(report['owned_workflow_ns'], 1) <= integer(summary['complete_workflow_ns'], 1),
            'complete time omits a sequential lifecycle')
    require(integer(summary['setup_ns'], 1) == sum(item['setup_ns'] for item in phases)
            and integer(summary['proving_ns'], 1) == sum(item['proving_ns'] for item in phases)
            and integer(summary['cpu_verification_ns'], 1) == report['cpu_verification_ns'],
            'summary timing disagrees with complete phases')
    return [descriptor(item['descriptor']) for item in phases[n:2 * n]]


def validate(content, plan):
    selected, uuid = plan_contract(plan)
    content = re.sub(r'^test ' + re.escape(SELECTOR) + r' \.\.\. ', '', content, flags=re.M)
    require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;.*$', content, re.M)) == 1
            and len(re.findall(r'^test result:', content, re.M)) == 1, 'exact passing driver missing')
    require(not any(marker in content for marker in ('OPENCL_OPT_RESULT', 'DIRECT_SPEND_RESULT',
            'DIRECT_RING_RESULT', 'complete direct aggregate failed:', 'panicked at')), 'failure/unrelated workflow in log')
    directory = Path(selected['output_directory'])
    require(directory.is_dir() and not directory.is_symlink(), 'missing/symlink output directory')
    names = set()
    for path in directory.iterdir():
        names.add(path.name)
        require(len(names) <= len(FILES), 'unexpected extra/failure evidence')
    require(names == FILES, 'incomplete evidence or failure file present')
    raw = {name: read_bounded(directory / name, MAX_ARTIFACT if name.endswith('.aggregate') else MAX_JSON)
           for name in FILES}
    suite = fields(decode_json(raw['complete.json']), '''schema distinct_transactions cases complete_workflow_ns
        final_artifacts_destroyed faithful_ringct_protocol redesign_2x_gate_passed security_adoption_review_complete''')
    require(suite['schema'] == 'lattica-research-direct-ring-complete-n3-n4-v1'
            and integer(suite['distinct_transactions']) == 7 and suite['final_artifacts_destroyed'] is True,
            'incomplete exact seven-case suite/owner retirement')
    for field in ('faithful_ringct_protocol', 'redesign_2x_gate_passed', 'security_adoption_review_complete'):
        require(suite[field] is False, 'unqualified suite promotion')
    require(type(suite['cases']) is list and len(suite['cases']) == 2, 'exact N3/N4 cases required')
    reports = [decode_json(raw[name + '.report.json']) for name in ('N3', 'N4')]
    receipts, public_hash, identities = [], [], []
    for index, (n, start) in enumerate(((3, 0), (4, 3))):
        identities.extend(case(reports[index], suite['cases'][index], n, start,
            raw['N' + str(n) + '.aggregate'], uuid, receipts, public_hash))
    require(len(identities) == len(set(identities)) == 7, 'seven distinct whole-transaction identities missing')
    a, b = [report['storage'] for report in reports]
    require(a['verifier_lifecycle_bytes_each'] == b['verifier_lifecycle_bytes_each']
            and a['expected_statement_bytes'] * 4 == b['expected_statement_bytes'] * 3
            and a['native_witness_bytes'] * 4 == b['native_witness_bytes'] * 3,
            'fixed source census changed between N3 and N4')
    logged = []
    for line in content.splitlines():
        if line.startswith('proving_stage_report '):
            require(len(line) <= MAX_JSON and len(logged) < 34, 'extra/oversized native execution report')
            logged.append(decode_json(line.removeprefix('proving_stage_report ')))
    require(len(receipts) == 34 and logged == receipts, 'native stdout scopes differ from complete owned phases')
    total = integer(suite['complete_workflow_ns'], 1)
    require(sum(item['complete_workflow_ns'] for item in suite['cases']) <= total
            <= integer(plan.get('observation_before_validation_ns'), 1), 'workflow time escapes runner observation')
    return dict(scope='complete-direct-ring-N3-N4-research', distinct_transactions=7,
        fresh_whole_transaction_proofs=7, fresh_recursive_aggregate_proofs=2,
        fresh_registration_scopes=25, fresh_proof_scopes=9, independent_cpu_acceptances=9,
        public_mutation_rejections=36, opening_mutation_rejections=9, restored_proof_acceptances=9,
        envelope_rejections=6, disk_roundtrips=2, terminal_phases=25,
        final_artifacts_destroyed=True, complete_workflow_ns=total, public_hash=public_hash[0],
        evidence_sha256={name: hashlib.sha256(data).hexdigest() for name, data in sorted(raw.items())},
        exact_source_bound_complete_driver=True, standalone_archived_artifact_qualified=False,
        complete_faithful_ringct_workflow=False, performance_qualified=False,
        redesign_2x_gate_passed=False, security_adoption_review_complete=False)
