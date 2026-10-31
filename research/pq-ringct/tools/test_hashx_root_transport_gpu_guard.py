"""Synthetic guard policy fixtures; these tests never qualify real GPU work."""
from copy import deepcopy
import json
from types import SimpleNamespace
import unittest

import hashx_root_transport_gpu_guard as guard

ROOT = '/tmp/recorded-root-transport'
UUID = 'GPU-00000000-1111-2222-3333-444444444444'
COMMAND = [ROOT + '/target/lattica_pq_ringct_research-recorded', guard.SELECTOR,
           '--exact', '--ignored', '--test-threads=1', '--nocapture']
GROWTH = 'bounded_proof_input_growth old_values=0 new_values=4 live_bytes=32 value_limit=1048576'
NATIVE_STAGES = set('public_values witness_trace preprocessing transform quotient randomness hiding '
                    'commitment opening fri_fold fri_query final_polynomial scalar transcript grinding'.split())


def arguments(**changes):
    result = dict(owned_hashx_root_transport_test='gpu', command=list(COMMAND), profile='full',
                  expect_tests=True, build_label='root-transport-build', device_uuid=UUID)
    result.update(changes)
    return SimpleNamespace(**result)


def base_environment():
    result = guard.expected_environment(ROOT, UUID)
    for key in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION', 'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES'):
        result.pop(key)
    result['LATTICA_V2_GPU_RETAINED_TREE_STORAGE'] = 'device'
    return result


def bound_plan():
    environment = guard.expected_environment(ROOT, UUID)
    sources = {path: 'a' * 64 for path in guard.REQUIRED_SOURCES}
    executable = dict(path=COMMAND[0], resolved_path=COMMAND[0], sha256='b' * 64,
                      build_record=ROOT + '/.tools/pq-opencl-opt/runs/root-transport-build.json',
                      build_record_sha256='c' * 64)
    plan = dict(command=list(COMMAND), environment=environment, profile='full', expect_tests=True,
                memory_max_bytes=47 * guard.GIB, memory_high_bytes=45 * guard.GIB,
                fresh_memavailable_required_bytes=49 * guard.GIB, cpu_quota='800%',
                benchmark=False, performance_qualified=False, comparison_baseline=False,
                public_hash_kernel='baseline', expect_result=False, expect_direct_result=False,
                correctness_label=None, record_artifacts=[], runtime_seconds=3600,
                build_label='root-transport-build', input_sha256=sources, executable_provenance=executable,
                observation_before_validation_ns=1000)
    plan[guard.ENV_KEY] = guard.receipt(environment)
    plan[guard.BINDING_KEY] = guard.bind_execution(plan, sources, executable, ROOT)
    return plan


def stage_report(entry):
    if entry == 'ringct_owned_native_shake':
        scope, stages = 'proof_request', NATIVE_STAGES
    elif entry == 'block_v2_preprocessing':
        scope, stages = 'preprocessing', set('preprocessing randomness transform commitment'.split())
    else:
        assert entry == 'block_v2_registered_program'
        scope, stages = 'registered_proof', (NATIVE_STAGES - {'public_values'}) | {'lookup'}
    return dict(schema='lattica-proving-stages-v1', entry_point=entry, policy='gpu_required',
                capabilities=dict(scope=scope, profile='block_v2_cubic', max_log_fri_arity=1,
                                  stages=[dict(stage=stage, backend='open_cl') for stage in sorted(stages)]),
                elapsed_ns=10, succeeded=True, stage_coverage_complete=True, completion_rejected=False,
                observation_errors=0, observations=[dict(stage=stage, backend='open_cl', calls=1,
                    completed_calls=1, device_calls=1, inclusive_ns=1, device_ns=1) for stage in sorted(stages)],
                components=[])


def records():
    fixed, verifier, caller = 1 << 20, 16 << 20, 256 << 10
    packets = guard.DECODE_LIMIT + 2 * guard.PACKET_LIMIT
    additional = fixed + packets + verifier
    values = [
        (guard.ROOT_CLAIMS, dict(guard.ROOT_FIXED, fixed_host_bytes=fixed,
            packet_and_decoder_host_bytes=packets, verifier_host_bytes=verifier,
            additional_host_bytes=additional, packet_limit_bytes=guard.PACKET_LIMIT,
            decoder_limit_bytes=guard.DECODE_LIMIT, max_inner_bytes=4096,
            max_packet_bytes=4096 + guard.HEADER_BYTES, max_packet_and_probe_bytes=4097 + guard.HEADER_BYTES,
            max_decoder_cumulative_bytes=16384, caller_host_bytes=caller, total_host_bytes=additional + caller)),
        (guard.SOURCE_CLAIMS, dict(guard.SOURCE_FIXED, host_bytes=9 * guard.GIB, device_bytes=0)),
    ]
    values.extend(('receipt', stage_report(entry)) for entry in guard.ENTRIES)
    metrics = dict(active_rows=100, padded_rows=128, wires=200, input_values=100,
                   compiler_ns=20, source_cpu_verification_ns=5)
    for ordinal, (first, units) in enumerate(guard.LEAF_SPANS):
        values.append((guard.LEAF, dict(guard.PROVISIONAL, **metrics, ordinal=ordinal,
            first_segment=2 * ordinal, segment_count=2, first_unit=first, units=units)))
    for ordinal, (first, units, level) in enumerate(guard.PARENT_SPANS):
        values.append((guard.PARENT, dict(guard.PROVISIONAL, **metrics, ordinal=ordinal,
            first_unit=first, units=units, level=level)))
    values += [
        (guard.ACCEPTANCE, dict(guard.PROVISIONAL, first_unit=0, units=122, level=3,
            mutation_checks_complete='false', artifact_roundtrip_complete='false', preparation_through_acceptance_ns=600)),
        (guard.DECODE, dict(vector_bytes=8192, canonical_bytes=1016, admitted_bytes=9208,
            allocations=20, limit_bytes=guard.DECODE_LIMIT, rejected='false')),
        (guard.ROOT_SCOPE, dict(guard.ROOT_SCOPE_FIXED, packet_bytes=1024 + guard.HEADER_BYTES,
            inner_bytes=1024, original_verification_ns=20, encoding_ns=20, header_checks_ns=20,
            decoding_ns=20, decoded_verification_ns=20, reencoding_ns=20, transport_action_ns=150)),
        (guard.COMPLETE, dict(guard.COMPLETE_FIXED, component_through_destruction_ns=800,
            terminal_observer_fixed_host_bytes=65536)),
        (guard.TERMINAL, dict(guard.TERMINAL_FIXED, peak_host_bytes=guard.HOST,
            peak_device_bytes=guard.DEVICE, component_through_destruction_ns=800,
            terminal_observer_fixed_host_bytes=65536)),
    ]
    return values


def record(values, name, ordinal=0):
    return [value for kind, value in values if kind == name][ordinal]


def fixture(values=None, same_line=False, header_payload=''):
    values = records() if values is None else values
    lines = ['test ' + guard.SELECTOR + ' ... ' + header_payload]
    for name, value in values:
        lines.append('proving_stage_report ' + json.dumps(value) if name == 'receipt'
                     else name + ' ' + ' '.join(f'{key}={item}' for key, item in value.items()))
    if same_line:
        lines[:2] = [lines[0] + lines[1]]
    return '\n'.join([*lines, 'ok', 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                     '515 filtered out; finished in 0.01s', ''])


class HashxRootTransportGpuGuardTests(unittest.TestCase):
    def test_exact_environment_and_isolated_gpu_selector(self):
        environment, note = guard.build_environment(arguments(), base_environment(), ROOT, 'baseline', 'host')
        self.assertEqual(environment, guard.expected_environment(ROOT, UUID))
        self.assertEqual(note, guard.receipt(environment))
        for flag in (guard.FLAG, 'LATTICA_OWNED_HASHX_SEQUENCE_QUALIFICATION'):
            self.assertEqual(environment[flag], '1')
        for flag in ('LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_ROOT_PUBLIC_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_ROOT_TRANSPORT_SOURCE_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_SOURCE_QUALIFICATION',
                     'LATTICA_OWNED_HASHX_SEQUENCE_REFUSAL_QUALIFICATION'):
            self.assertNotIn(flag, environment)
        self.assertEqual(environment['LATTICA_PROVING_POLICY'], 'gpu-required')
        self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * guard.GIB))
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
        self.assertEqual(environment['RAYON_NUM_THREADS'], '8')
        self.assertEqual(guard.build_environment(arguments(command=['--', *COMMAND]), base_environment(),
                         ROOT, 'baseline', 'host'), (environment, note))

    def test_environment_rejects_sibling_selectors_foreign_modes_and_drift(self):
        prefix = guard.SELECTOR.split('qualification::')[0] + 'qualification::'
        for tail in ('transport::cpu_original_hashx_sequence_root_transport_capacity',
                     'gpu_original_hashx_sequence_root_transport_roundtrip',
                     'gpu_original_hashx_sequence_root_public_recheck',
                     'cpu_original_hashx_sequence_root_public_capacity',
                     'gpu_original_hashx_sequence_source_authenticated', 'gpu_original_hashx_sequence_preissue',
                     'gpu_original_hashx_sequence_refusal_after_preissue'):
            command = [COMMAND[0], prefix + tail, *COMMAND[2:]]
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'host')
        for changes in ({'owned_hashx_root_transport_test': 'capacity'}, {'profile': 'direct-full'},
                        {'expect_tests': False}, {'build_label': None}, {'device_uuid': None},
                        *({key: True} for key in guard.EXCLUSIVE)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                guard.build_environment(arguments(**changes), base_environment(), ROOT, 'baseline', 'host')
        for command in (COMMAND[:-1], COMMAND + ['--skip', guard.SELECTOR], ['/tmp/other', *COMMAND[1:]]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                guard.build_environment(arguments(command=command), base_environment(), ROOT, 'baseline', 'host')
        for kernel, storage in (('sbox-pair-v1', 'host'), ('baseline', 'device')):
            with self.subTest(kernel=kernel), self.assertRaises(ValueError):
                guard.build_environment(arguments(), base_environment(), ROOT, kernel, storage)
        for key, value in (('EXTRA', '1'), ('RAYON_NUM_THREADS', '4'), (guard.FLAG, '1')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.build_environment(arguments(), dict(base_environment(), **{key: value}), ROOT, 'baseline', 'host')

    def test_binding_rejects_changed_resources_or_other_qualification_receipts(self):
        for key, value in (('memory_max_bytes', 48 * guard.GIB), ('memory_high_bytes', 46 * guard.GIB),
                           ('fresh_memavailable_required_bytes', 48 * guard.GIB), ('cpu_quota', '900%'),
                           ('benchmark', True), ('performance_qualified', True), ('comparison_baseline', True),
                           ('expect_result', True), ('expect_direct_result', True), ('correctness_label', 'other'),
                           ('record_artifacts', ['/tmp/other']), ('runtime_seconds', True),
                           ('runtime_seconds', 0), ('runtime_seconds', 86401),
                           *((key, {}) for key in guard.FOREIGN_RECEIPTS)):
            plan = bound_plan()
            plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)

    def test_provenance_binds_source_build_resolved_executable_environment_and_uuid(self):
        for section, key, value in ((guard.BINDING_KEY, 'source_manifest_sha256', 'd' * 64),
                                    (guard.BINDING_KEY, 'selected_physical_device_uuid', 'GPU-invalid'),
                                    (guard.BINDING_KEY, 'dispatch_authority', 0),
                                    ('input_sha256', guard.REQUIRED_SOURCES[0], 'd' * 64),
                                    ('input_sha256', '../escape', 'd' * 64),
                                    ('input_sha256', 'research//alias.rs', 'd' * 64),
                                    ('environment', 'LATTICA_GPU_DEVICE_UUID', 'GPU-invalid'),
                                    ('environment', 'RAYON_NUM_THREADS', '4'),
                                    (guard.ENV_KEY, 'dispatch_authority', 0),
                                    ('executable_provenance', 'sha256', 'd' * 64),
                                    ('executable_provenance', 'build_record_sha256', 'd' * 64),
                                    ('executable_provenance', 'resolved_path', ROOT + '/target/other'),
                                    ('executable_provenance', 'build_record', ROOT + '/other.json')):
            plan = bound_plan()
            plan[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        for path in guard.REQUIRED_SOURCES:
            plan = bound_plan()
            plan['input_sha256'].pop(path)
            with self.subTest(missing=path), self.assertRaises(ValueError):
                guard.bind_execution(plan, plan['input_sha256'], plan['executable_provenance'], ROOT)

    def test_source_requirements_cover_new_semantics_and_not_only_old_pins(self):
        required = set(guard.REQUIRED_SOURCES)
        self.assertEqual(len(required), len(guard.REQUIRED_SOURCES))
        for suffix in ('root_transport.rs', 'root_transport/BOUNDS.md', 'root_transport/admission.rs',
                       'root_transport/admission/claims.rs', 'root_transport/admission/codec_frames.rs',
                       'root_transport/admission/source.rs', 'root_transport/admission/tests.rs',
                       'root_transport/admission/API.md', 'root_transport/admission/BOUNDS.md',
                       'root_transport/header.rs', 'root_transport/header/probes.rs',
                       'root_transport/header/tests.rs', 'root_transport/header/BOUNDS.md',
                       'qualification/transport.rs', 'qualification/transport/BOUNDS.md',
                       'qualification/transport/claims.rs', 'qualification/transport/claims/BOUNDS.md',
                       'qualification/transport/claims/tests.rs'):
            self.assertIn(guard.SEQUENCE + '/' + suffix, required)
        for path in ('lattica-prover-p3/src/block_v2/codec.rs',
                     'lattica-prover-p3/src/block_v2/codec/proofs.rs',
                     'lattica-prover-p3/src/block_v2/codec/proofs/schema.rs',
                     'research/pq-ringct/tools/hashx_root_transport_gpu_guard.py',
                     'research/pq-ringct/tools/test_hashx_root_transport_gpu_guard.py'):
            self.assertIn(path, required)

    def test_positive_result_keeps_numerical_header_decode_and_observer_scopes_distinct(self):
        for content in (fixture(), fixture(same_line=True), fixture(header_payload=GROWTH)):
            result = guard.validate_log(content, bound_plan())
            self.assertEqual(result['scope'], 'single-root-in-memory')
            self.assertEqual((result['native_proofs'], result['recursive_proofs'], result['stage_receipts']), (10, 9, 28))
            self.assertEqual((result['numerical_positive_checks'], result['header_positive_checks'],
                              result['bounded_decode_successes'], result['typed_header_refusals']), (2, 2, 1, 629))
            self.assertEqual(tuple(result[key] for key in ('header_syntax_rejections', 'header_public_rejections',
                'header_cap_rejections', 'header_height_rejections', 'header_canonical_rejections')), (24, 46, 256, 1, 302))
            self.assertTrue(result['root_transport_roundtrip_complete'])
            self.assertTrue(result['owner_quota_cleanup_complete'])
            self.assertEqual(result['terminal_observer_scope'], 'process-audit-only')
            self.assertLessEqual(result['terminal_observer_event_bytes'], 4096)
            self.assertEqual(result['receipt_phase_identity'], 'pinned-source-order-only')
            for key in ('process_engine_device_audit_complete', 'transaction_context_authenticated',
                        'raw_proof_mutation_checks_complete', 'interior_mutation_checks_complete',
                        'mutation_checks_complete', 'artifact_roundtrip_complete', 'disk_artifact_roundtrip_complete',
                        'decoder_failures_classified', 'complete_ringct_workflow', 'performance_qualified',
                        'released_claims_cover_terminal_observer', 'terminal_observer_census_is_physical_measurement'):
                self.assertFalse(result[key], key)
            self.assertEqual([(v['kind'], v['ordinal']) for v in result['recursive_phases']], list(guard.ORDER))

    def test_receipt_position_mapping_is_source_order_not_cryptographic_ordinal(self):
        values = records()
        for index in range(28):
            record(values, 'receipt', index)['elapsed_ns'] = index + 1
        record(values, guard.ACCEPTANCE)['preparation_through_acceptance_ns'] = 700
        for name in (guard.COMPLETE, guard.TERMINAL):
            record(values, name)['component_through_destruction_ns'] = 900
        result = guard.validate_log(fixture(values), bound_plan())
        for position, phase in enumerate(result['recursive_phases']):
            self.assertEqual((phase['setup_ns'], phase['proving_ns']), (11 + 2 * position, 12 + 2 * position))

    def test_rejects_missing_duplicated_or_reordered_events_including_single_decode(self):
        values = records()
        cases = []
        for index in range(len(values)):
            cases.extend((values[:index] + values[index + 1:], values[:index] + [values[index]] + values[index:]))
        for left, right in ((1, 2), (11, 12), (12, 13), (29, 30), (30, 31), (35, 36),
                            (39, 40), (40, 41), (41, 42), (42, 43)):
            changed = deepcopy(values)
            changed[left], changed[right] = changed[right], changed[left]
            cases.append(changed)
        for ordinal, changed in enumerate(cases):
            with self.subTest(case=ordinal), self.assertRaises(ValueError):
                guard.validate_log(fixture(changed), bound_plan())

    def test_rejects_receipt_policy_schema_and_gpu_execution_gaps(self):
        for section, key, value in ((None, 'policy', 'cpu_required'), (None, 'succeeded', False),
                                   (None, 'stage_coverage_complete', False), (None, 'completion_rejected', True),
                                   (None, 'observation_errors', True), (None, 'components', [{}]),
                                   (None, 'elapsed_ns', 0), (None, 'elapsed_ns', True),
                                   (None, 'elapsed_ns', 1.5), (None, 'elapsed_ns', float('nan')),
                                   (None, 'elapsed_ns', 1 << 128),
                                   ('capabilities', 'max_log_fri_arity', 2),
                                   ('capabilities', 'scope', 'registered_proof'),
                                   ('capabilities', 'profile', 'legacy_quadratic')):
            values = records()
            target = record(values, 'receipt')
            if section:
                target = target[section]
            target[key] = value
            with self.subTest(section=section, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for key, value in (('backend', 'cpu'), ('calls', 0), ('calls', True), ('calls', 1 << 64),
                           ('completed_calls', 0), ('device_calls', 0), ('device_calls', 2),
                           ('device_ns', 0), ('inclusive_ns', -1), ('inclusive_ns', 1 << 128), ('stage', [])):
            values = records()
            record(values, 'receipt')['observations'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for section in ('capabilities', 'observations'):
            values = records()
            target = record(values, 'receipt')[section]
            target = target['stages'] if section == 'capabilities' else target
            target[1] = deepcopy(target[0])
            with self.subTest(section=section), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for section in (None, 'capabilities'):
            values = records()
            target = record(values, 'receipt')
            if section:
                target = target[section]
            target['invented'] = True
            with self.subTest(section=section), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        duplicated = fixture().replace('"schema": "lattica-proving-stages-v1"',
            '"schema": "lattica-proving-stages-v1", "schema": "lattica-proving-stages-v1"', 1)
        with self.assertRaises(ValueError):
            guard.validate_log(duplicated, bound_plan())

    def test_rejects_incomplete_admission_and_packet_decoder_arithmetic(self):
        for name, key, value in ((guard.ROOT_CLAIMS, 'actual_root_transports', 1),
                (guard.ROOT_CLAIMS, 'cpu_heights', 17), (guard.ROOT_CLAIMS, 'codec_heights', 17),
                (guard.ROOT_CLAIMS, 'fixed_host_bytes', 0), (guard.ROOT_CLAIMS, 'caller_host_bytes', 64 << 10),
                (guard.ROOT_CLAIMS, 'verifier_host_bytes', 0), (guard.ROOT_CLAIMS, 'additional_host_bytes', 1),
                (guard.ROOT_CLAIMS, 'total_host_bytes', 1), (guard.ROOT_CLAIMS, 'packet_and_decoder_host_bytes', 1),
                (guard.ROOT_CLAIMS, 'packet_limit_bytes', guard.PACKET_LIMIT + 1),
                (guard.ROOT_CLAIMS, 'decoder_limit_bytes', guard.DECODE_LIMIT + 1),
                (guard.ROOT_CLAIMS, 'max_inner_bytes', 8), (guard.ROOT_CLAIMS, 'max_packet_bytes', 4096),
                (guard.ROOT_CLAIMS, 'max_packet_and_probe_bytes', 4096 + guard.HEADER_BYTES),
                (guard.ROOT_CLAIMS, 'max_decoder_cumulative_bytes', 1),
                (guard.ROOT_CLAIMS, 'max_decoder_cumulative_bytes', guard.DECODE_LIMIT + 1),
                (guard.SOURCE_CLAIMS, 'host_bytes', 1), (guard.SOURCE_CLAIMS, 'device_bytes', 1),
                (guard.ROOT_SCOPE, 'packet_bytes', 1024), (guard.ROOT_SCOPE, 'inner_bytes', 4097),
                (guard.DECODE, 'vector_bytes', 0), (guard.DECODE, 'canonical_bytes', 1017),
                (guard.DECODE, 'admitted_bytes', 9209), (guard.DECODE, 'allocations', 0),
                (guard.DECODE, 'allocations', 8193), (guard.DECODE, 'rejected', 'true'),
                (guard.DECODE, 'limit_bytes', guard.DECODE_LIMIT - 1)):
            values = records()
            record(values, name)[key] = value
            with self.subTest(name=name, key=key, value=value), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        admission = record(values, guard.ROOT_CLAIMS)
        admission.update(max_inner_bytes=guard.PACKET_LIMIT - guard.HEADER_BYTES,
            max_packet_bytes=guard.PACKET_LIMIT, max_packet_and_probe_bytes=guard.PACKET_LIMIT + 1,
            max_decoder_cumulative_bytes=guard.DECODE_LIMIT)
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())
        values = records()
        record(values, guard.DECODE).update(vector_bytes=16384, admitted_bytes=17400)
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())

    def test_rejects_wrong_proof_coverage_and_noncanonical_geometry(self):
        for name, ordinal, key, value in ((guard.SOURCE_CLAIMS, 0, 'native_outputs', 9),
                (guard.LEAF, 0, 'segment_count', 1), (guard.LEAF, 1, 'first_segment', 0),
                (guard.LEAF, 4, 'units', 1), (guard.PARENT, 2, 'level', 1),
                (guard.PARENT, 3, 'units', 121), (guard.PARENT, 3, 'first_unit', 1),
                (guard.ACCEPTANCE, 0, 'level', 2), (guard.COMPLETE, 0, 'compiler_reclamations', 8)):
            values = records()
            record(values, name, ordinal)[key] = value
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        for key, value in (('active_rows', 0), ('active_rows', 129), ('padded_rows', 127),
                           ('padded_rows', 1 << 21), ('wires', (1 << 26) + 1),
                           ('input_values', (1 << 20) + 1), ('source_cpu_verification_ns', 0),
                           ('compiler_ns', '020'), ('compiler_ns', 1 << 128)):
            values = records()
            record(values, guard.LEAF)[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())

    def test_rejects_merged_counts_or_wider_evidence_claims(self):
        for name, fixed in ((guard.ROOT_SCOPE, guard.ROOT_SCOPE_FIXED), (guard.COMPLETE, guard.COMPLETE_FIXED)):
            for key in guard.COUNTS:
                values = records()
                record(values, name)[key] = int(fixed[key]) + 1
                with self.subTest(name=name, count=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(values), bound_plan())
            for key in (*guard.NO_WIDER_CHECKS, 'transaction_context_authenticated'):
                values = records()
                record(values, name)[key] = 'true'
                with self.subTest(name=name, claim=key), self.assertRaises(ValueError):
                    guard.validate_log(fixture(values), bound_plan())
        for name, key, value in ((guard.ROOT_SCOPE, 'retained_output_immutable', 'false'),
                (guard.ROOT_SCOPE, 'source_key_authenticated', 'false'),
                (guard.ROOT_SCOPE, 'provisional', 'false'),
                (guard.ROOT_SCOPE, 'terminal_cleanup_complete', 'true'),
                (guard.ROOT_SCOPE, 'transport_scope', 'whole-workflow'),
                (guard.COMPLETE, 'root_transport_roundtrip_complete', 'false'),
                (guard.COMPLETE, 'owner_quota_cleanup_complete', 'false')):
            values = records()
            record(values, name)[key] = value
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())

    def test_terminal_observer_and_zero_accounting_cannot_borrow_released_claims(self):
        for name in (guard.COMPLETE, guard.TERMINAL):
            for key, value in (('terminal_observer_scope', 'worker-ledger'),
                               ('released_claims_cover_terminal_observer', 'true'),
                               ('process_engine_device_audit_complete', 'true'),
                               ('terminal_observer_fixed_host_bytes', 0),
                               ('terminal_observer_fixed_host_bytes', 65537),
                               ('terminal_observer_fixed_host_bytes', guard.OBSERVER_HOST_LIMIT + 1)):
                values = records()
                record(values, name)[key] = value
                with self.subTest(name=name, key=key, value=value), self.assertRaises(ValueError):
                    guard.validate_log(fixture(values), bound_plan())
        for key, value in (('current_host_bytes', 1), ('current_device_bytes', 1),
                           ('peak_host_bytes', 17 * guard.GIB - 1), ('peak_host_bytes', guard.HOST + 1),
                           ('peak_device_bytes', guard.DEVICE - 1), ('component_success', 'false')):
            values = records()
            record(values, guard.TERMINAL)[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())

    def test_timers_enclose_serialized_phases_and_disjoint_transport_subintervals(self):
        for name, key, value in (('receipt', 'elapsed_ns', 601), (guard.LEAF, 'compiler_ns', 601),
                (guard.PARENT, 'source_cpu_verification_ns', 601),
                (guard.ACCEPTANCE, 'preparation_through_acceptance_ns', 504),
                (guard.ROOT_SCOPE, 'transport_action_ns', 119),
                (guard.COMPLETE, 'component_through_destruction_ns', 799),
                (guard.TERMINAL, 'component_through_destruction_ns', 799),
                *((guard.ROOT_SCOPE, key, 0) for key in ('original_verification_ns', 'encoding_ns',
                    'header_checks_ns', 'decoding_ns', 'decoded_verification_ns', 'reencoding_ns'))):
            values = records()
            record(values, name)[key] = value
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                guard.validate_log(fixture(values), bound_plan())
        values = records()
        for name in (guard.COMPLETE, guard.TERMINAL):
            record(values, name)['component_through_destruction_ns'] = 749
        with self.assertRaises(ValueError):
            guard.validate_log(fixture(values), bound_plan())
        for observation in (None, True, 0, -1, 1000.0, 799, 1 << 128):
            plan = bound_plan()
            plan['observation_before_validation_ns'] = observation
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                guard.validate_log(fixture(), plan)
        values = records()
        for name, value in values:
            if name == 'receipt':
                for item in value['observations']:
                    item['inclusive_ns'] = item['device_ns'] = 9
        self.assertTrue(guard.validate_log(fixture(values), bound_plan())['root_transport_roundtrip_complete'])

    def test_rejects_foreign_synthetic_misplaced_or_failed_log_evidence(self):
        for payload in ('failed', 'ok', 'ignored', 'fixture', GROWTH + ' extra=1',
                        GROWTH.replace('live_bytes=32', 'live_bytes=31')):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                guard.validate_log(fixture(header_payload=payload), bound_plan())
        for token in ('ringct_hashx_sequence_complete native_proofs=10',
                      'ringct_hashx_sequence_capacity_complete native_proofs=0',
                      'ringct_hashx_root_public_recheck_complete positive_checks=2',
                      'ringct_unknown complete=true', 'transport_schema_case rows=8',
                      'OPENCL_OPT_RESULT {}', 'DIRECT_RING_RESULT {}', 'fallback=true', 'retry=true',
                      'test foreign::test ... ok', "thread 'test' panicked at fixture:1",
                      'prefixbounded_decoded_proof_storage rejected=false',
                      ' bounded_decoded_proof_storage rejected=false', 'bounded_decoded_proof_storage',
                      'proving_stage_report', 'prefixringct_unknown complete=true'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                guard.validate_log(fixture() + token + '\n', bound_plan())
        for old, new in (('\nok\n', '\n'), ('\nok\n', '\nok\nok\n'), ('1 passed;', '2 passed;'),
                         ('0 failed;', '1 failed;'), ('0 ignored;', '1 ignored;'),
                         ('cpu_heights=18 ', 'cpu_heights=18 extra=1 '),
                         ('cpu_heights=18 ', 'cpu_heights=18 cpu_heights=18 '),
                         ('vector_bytes=8192', 'vector_bytes=08192'),
                         ('vector_bytes=8192', 'vector_bytes=18446744073709551616')):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                guard.validate_log(fixture().replace(old, new), bound_plan())
        lines = fixture().splitlines()
        with self.assertRaises(ValueError):
            guard.validate_log('\n'.join([lines[1], lines[0], *lines[2:]]) + '\n', bound_plan())
        with self.assertRaises(ValueError):
            guard.validate_log(fixture() + ('x' * (16 << 20)), bound_plan())


if __name__ == '__main__':
    unittest.main()
