"""Synthetic receipt predicates only; these fixtures qualify no proof/workflow."""
import copy
import json
import unittest

from opencl_private_spend_validate import collect_gpu_receipts
from owned_workflow_case_receipts import parse_record, validate as _validate


def validate(content, report, collect_gpu_receipts):
    return _validate(content, report, collect_gpu_receipts, verification_mode='existing-format-partial')


NATIVE_STAGES = ('public_values', 'witness_trace', 'preprocessing', 'transform',
    'quotient', 'randomness', 'hiding', 'commitment', 'opening', 'fri_fold',
    'fri_query', 'final_polynomial', 'scalar', 'transcript', 'grinding')
FAMILIES = (
    ('owned_source_native_report', 'ringct_owned_native_graph_source'),
    ('owned_uniform_native_report', 'ringct_owned_native_uniform'),
    ('owned_sparse_native_report', 'ringct_owned_native_sparse'),
    ('owned_transcript_native_report', 'ringct_owned_native_transcript'),
    ('owned_affine_native_report', 'ringct_owned_native_affine'),
    ('owned_ntt_native_report', 'ringct_owned_native_ntt'),
    ('owned_mul_native_report', 'ringct_owned_native_mul'),
    ('owned_g_bound_native_report', 'ringct_owned_native_g_bound'),
    ('owned_permutation_native_report', 'ringct_owned_native_permutation'),
    ('owned_linear_map_native_report', 'ringct_owned_native_linear_map'),
    ('owned_native_report', 'ringct_owned_native_aes'),
    ('owned_native_report', 'ringct_owned_native_shake'))


def receipt(entry, elapsed_ns):
    profile, scope, arity = 'block_v2_cubic', 'proof_request', 1
    stages = NATIVE_STAGES
    if entry in ('native_matrict_spend', 'pq_graph_witness_preparation'):
        scope, stages = 'operation', ('witness_trace',)
        if entry == 'native_matrict_spend':
            profile, arity = 'matrict_n10', 0
    elif entry == 'block_v2_preprocessing':
        scope, stages = 'preprocessing', ('preprocessing', 'randomness', 'transform', 'commitment')
    elif entry == 'block_v2_registered_program':
        scope = 'registered_proof'
        stages = tuple(stage for stage in NATIVE_STAGES if stage != 'public_values') + ('lookup',)
    return {'schema': 'lattica-proving-stages-v1', 'entry_point': entry,
        'policy': 'gpu_required', 'capabilities': {'scope': scope, 'profile': profile,
            'max_log_fri_arity': arity,
            'stages': [{'stage': stage, 'backend': 'open_cl'} for stage in stages]},
        'elapsed_ns': elapsed_ns, 'succeeded': True, 'stage_coverage_complete': True,
        'completion_rejected': False, 'observation_errors': 0, 'components': [],
        'observations': [{'stage': stage, 'backend': 'open_cl', 'calls': 2 + index % 3,
            'completed_calls': 2 + index % 3, 'device_calls': 1,
            'inclusive_ns': 500, 'device_ns': 100 + index}
            for index, stage in enumerate(stages)]}


def totals(receipts):
    return {'reports': len(receipts), 'elapsed_ns': sum(item['elapsed_ns'] for item in receipts),
        'witness_completed_calls': sum(o['completed_calls'] for r in receipts for o in r['observations']),
        'witness_device_calls': sum(o['device_calls'] for r in receipts for o in r['observations']),
        'witness_device_ns': sum(o['device_ns'] for r in receipts for o in r['observations'])}


def fixture(count=3):
    events, generation_reports, source_reports, owned_reports, native_reports = [], [], [], [], []
    for ordinal in range(count):
        report = receipt('native_matrict_spend', 1000 + ordinal)
        generation_reports.append(report)
        events.append(['owned_generation_report', report])
        observed = report['observations'][0]
        events.append(['owned_generation_spend', {'session_id': 11, 'ordinal': ordinal,
            'elapsed_ns': report['elapsed_ns'], 'witness_completed_calls': observed['completed_calls'],
            'witness_device_calls': observed['device_calls'], 'witness_device_ns': observed['device_ns'],
            'managed_bytes': 2048 + ordinal, 'prelude_steps': 0x3f,
            'accepted_attempt_steps': 0x03ffffc0, 'source_fingerprint': list(range(32)),
            'kernel_source_sha256': 'a' * 64}])
    generation = totals(generation_reports)
    generation['spends'] = generation.pop('reports')
    generation['seconds'] = generation.pop('elapsed_ns') / 1e9 + 0.0002
    generation['managed_peak_bytes'] = 2048 + count - 1
    events.append(['owned_generation_terminal', {'schema': 'ringct-native-generation-terminal-v1',
        'session_id': 11, 'operations': copy.deepcopy(generation), 'stark_proofs': 0, 'registrations': 0,
        'session': {'allocations': count, 'commits': 0, 'managed_peak_bytes': 8192,
            'uploaded_bytes': 128, 'downloaded_bytes': 64, 'queue_drained': True,
            'context_closed': True, 'managed_live_bytes': 0, 'host_tree_live_bytes': 0}}])
    for ordinal in range(count):
        report = receipt('pq_graph_witness_preparation', 2000 + ordinal)
        source_reports.append(report)
        events.append(['proving_stage_report', report])
    for ordinal, (prefix, entry) in enumerate(FAMILIES):
        report = receipt(entry, 3000 + ordinal)
        native_reports.append({'entry_point': entry,
            'totals': {'reports': 1, 'elapsed_ns': report['elapsed_ns']}})
        events.append([prefix, report])
    owned_events = []
    for ordinal in range(count):
        prefix = 'owned_group_report' if ordinal == 0 else 'owned_final_compile_report'
        report = receipt('pq_graph_witness_preparation', 4000 + ordinal)
        owned_reports.append(report)
        owned_events.append([prefix, report])
    machine = {'machine_preprocessing': [], 'machine_proofs': []}
    for ordinal in range(count):
        events.append(owned_events[ordinal])
        for key, entry in (('machine_preprocessing', 'block_v2_preprocessing'),
                           ('machine_proofs', 'block_v2_registered_program')):
            report = receipt(entry, 5000 + ordinal)
            machine[key].append(report)
            events.append(['proving_stage_report', report])
    source = totals(source_reports)
    source['calls'] = source['succeeded'] = source['complete_reports'] = source.pop('reports')
    source['seconds'] = source.pop('elapsed_ns') / 1e9 + 0.0001
    source.update(session_id=12, native_cpu_calls=0, native_cpu_succeeded=0, failure_events=0)
    report = {'transactions': count, 'native_proofs': 12, 'recursive_proofs': count,
        'generation_session_id': 11, 'generation': generation, 'source_preparation': source,
        'generation_and_planning_ns': 10_000_000, 'proving_and_verification_ns': 10_000_000,
        'owned_observations': {'schema': 'ringct-owned-workflow-observations-v1', 'session_id': 12,
            **{key: {field: totals(values)[field] for field in ('reports', 'elapsed_ns')}
               for key, values in machine.items()},
            'native_proofs': native_reports, 'witness_preparation': totals(owned_reports)},
        'cache_statistics': [{'reads': 0, 'hits': 0, 'bypasses': 0, 'proof_attempts': 0,
                              'fresh_proofs': 0} for _ in range(5)]}
    owned = report['owned_observations']
    owned['schema'] = 'ringct-owned-workflow-observations-v2'
    owned['machine_rows'] = {'proofs': count, 'active_rows': count * 100, 'padded_rows': count * 128}
    for item in owned['native_proofs']:
        item['rows'] = {'proofs': 1, 'active_rows': None, 'padded_rows': 1024}
    with_rows, sequence = [], 0
    for prefix, value in events:
        with_rows.append([prefix, value])
        entry = value.get('entry_point')
        is_native = entry in {item[1] for item in FAMILIES}
        if is_native or entry == 'block_v2_registered_program':
            with_rows.append(['owned_proof_rows', {
                'schema': 'ringct-owned-proof-rows-v1', 'session_id': 12,
                'sequence': sequence, 'entry_point': entry,
                'active_rows': None if is_native else 100,
                'padded_rows': 1024 if is_native else 128,
                'native_degree_bits': 11 if is_native else None}])
            sequence += 1
    owned['row_receipts'] = sequence
    return with_cpu_epochs(with_rows, report), report


def epoch_lifetime():
    return {'startup': {'elapsed_ns': 100, 'succeeded': True, 'retained_tree_host_bytes': 8192},
        'retirement': {'managed_live_bytes': 0, 'managed_peak_bytes': 8192,
                       'host_tree_live_bytes': 0, 'lease_released': True}}


def final_qualification(completed=False):
    value = dict.fromkeys(('artifact_round_trip', 'public_mutation_rejected', 'proof_mutation_rejected'), completed)
    value.update(dict.fromkeys(('decoded_positive_checks', 'packet_bytes', 'proof_bytes',
        'file_device', 'file_inode', 'height', 'public_values', 'encoding_ns', 'disk_round_trip_ns',
        'decoding_ns', 'decoded_cpu_verification_ns', 'canonical_encoding_ns',
        'mutation_cpu_verification_ns', 'elapsed_ns'), 0))
    value.update({key: [0] * 32 for key in ('packet_sha3_256', 'source_fingerprint',
        'compiled_source_fingerprint', 'batch_profile', 'context')})
    if completed:
        value.update(decoded_positive_checks=3, packet_bytes=2464, proof_bytes=8,
            file_device=1, file_inode=2, height=8, public_values=25,
            decoded_cpu_verification_ns=100, mutation_cpu_verification_ns=200, elapsed_ns=500)
    return value


def final_stage_fixture(ordinal, count, proving_ns=0, setup_ns=0):
    verify = ordinal == 2 * (count - 1)
    stage = 'verify' if verify else ('outer' if ordinal % 2 else 'compile')
    merge = count - 2 if verify else ordinal // 2
    # Exact N3/N4 balanced merge order. These are transport fixtures, not proofs.
    spans = [(0, 2), (0, 3)] if count == 3 else [(0, 2), (2, 2), (0, 4)]
    first, covered = spans[merge]
    return {'schema': 'ringct-owned-final-stage-v1', 'ordinal': ordinal, 'stage': stage,
        'report': {'merge': merge, 'first': first, 'count': covered,
            'active_rows': 100, 'padded_rows': 128, 'recursive_proofs': int(stage == 'outer'),
            'compile_ns': 2000 if stage == 'compile' else 0, 'setup_ns': setup_ns,
            'proving_ns': proving_ns, 'cpu_verification_ns': 1000 if verify else 100,
            'qualification': final_qualification(verify)}}


def with_cpu_epochs(events, report):
    result, proof, final_merge, outer_index = [], None, 0, 0
    for prefix, value in events:
        result.append([prefix, value])
        if prefix in ('owned_group_report', 'owned_final_compile_report'):
            final = prefix == 'owned_final_compile_report'
            epoch = epoch_lifetime()
            epoch.update(preparation_ns=value['elapsed_ns'] + 100, preparation_complete=True)
            ordinal = 2 * final_merge if final else 0
            name = prefix.replace('_report', '_epoch')
            schema = 'ringct-owned-final-compile-epoch-v1' if final else 'ringct-owned-group-epoch-v1'
            result.append([name, {'schema': schema, 'ordinal': ordinal, 'epoch': epoch}])
            if final:
                result.append(['owned_final_stage', final_stage_fixture(ordinal, report['transactions'])])
                final_merge += 1
        elif (prefix != 'owned_proof_rows' and value.get('entry_point') in {entry for _, entry in FAMILIES}) or (
                prefix == 'proving_stage_report' and value.get('entry_point') == 'block_v2_registered_program'):
            proof = prefix, value
        elif prefix == 'owned_proof_rows':
            proof_prefix, proof_report = proof
            epoch = epoch_lifetime()
            epoch['independent_verification_complete'] = True
            if proof_prefix != 'proving_stage_report':
                epoch.update(preissue_ns=100, preparation_ns=200,
                    proving_ns=proof_report['elapsed_ns'], cpu_verification_ns=300)
                name = proof_prefix.replace('_report', '_epoch')
                source = name != 'owned_native_epoch'
                if source:
                    epoch['source'] = 'Statement' if name == 'owned_source_native_epoch' else {'fixture_descriptor': 1}
                schema = 'ringct-owned-source-native-epoch-v1' if source else 'ringct-owned-native-epoch-v1'
                # Local ordinals intentionally repeat across requests/families.
                result.append([name, {'schema': schema, 'ordinal': 0, 'epoch': epoch}])
            else:
                ordinal = 3 if outer_index == 0 else 2 * (outer_index - 1) + 1
                result.append(['owned_outer_epoch', {'schema': 'ringct-owned-outer-epoch-v1',
                    'ordinal': ordinal, 'epoch': epoch}])
                if outer_index:
                    result.append(['owned_final_stage', final_stage_fixture(ordinal, report['transactions'],
                        proof_report['elapsed_ns'], proof_report['elapsed_ns'])])
                outer_index += 1
            proof = None
    final = final_stage_fixture(2 * (report['transactions'] - 1), report['transactions'])
    result.append(['owned_final_stage', final])
    report.update(final_cpu_verification_ns=1000, qualification_scope='final-aggregate',
                  final_qualification=copy.deepcopy(final['report']['qualification']))
    return result


def render(events):
    return '\n'.join(prefix + ' ' + json.dumps(value) for prefix, value in events)


def index_of(events, prefix, entry=None):
    return next(index for index, (name, value) in enumerate(events)
                if name == prefix and (entry is None or value.get('entry_point') == entry))


class OwnedCaseReceiptTests(unittest.TestCase):
    def audit(self, events, report):
        return validate(render(events), report, collect_gpu_receipts)

    def test_n3_and_n4_reconcile_actual_entries_and_separate_preparation(self):
        for count in (3, 4):
            with self.subTest(count=count):
                events, report = fixture(count)
                result = self.audit(events, report)
                self.assertEqual(result['gpu_receipts']['native_reports'], 12)
                self.assertEqual(result['source_preparation']['reports'], count)
                self.assertEqual(result['owned_preparation']['reports'], count)
                self.assertEqual(result['final_compile_reports'], count - 1)
                self.assertEqual(result['generation_session_id'], 11)
                self.assertEqual(result['planning_session_id'], 12)

    def test_collector_receives_only_prefix_normalization_and_exact_native_names(self):
        calls = []
        def collect(content, *, native_entry_names):
            calls.append((content, native_entry_names))
            return collect_gpu_receipts(content, native_entry_names=native_entry_names)
        events, report = fixture()
        validate(render(events), report, collect)
        self.assertEqual(len(calls), 3)
        for _, names in calls:
            self.assertEqual(tuple(names), tuple(entry for _, entry in FAMILIES))
        self.assertIn('ringct_owned_native_aes', calls[0][0])
        self.assertNotIn('pq_aes_lane_native', calls[0][0])

    def test_partial_cache_and_unused_legacy_registry_do_not_define_coverage(self):
        events, report = fixture()
        empty = self.audit(events, report)
        report['cache_statistics'][2].update(proof_attempts=1, fresh_proofs=1)
        report['context'] = {'registrations': 0, 'operations': {'native_gpu_calls': 0}}
        self.assertEqual(self.audit(events, report), empty)
        del report['cache_statistics']
        self.assertEqual(self.audit(events, report), empty)
        self.assertIs(empty['cache_counters_used_for_proof_coverage'], False)

    def test_missing_and_duplicate_native_reports_fail(self):
        for duplicate in (False, True):
            events, report = fixture()
            index = index_of(events, 'owned_source_native_report')
            if duplicate:
                events.insert(index, copy.deepcopy(events[index]))
            else:
                del events[index]
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_owned_elapsed_totals_and_closed_graph_counts_must_match(self):
        for target in ('native', 'machine_preprocessing', 'machine_proofs',
                       'witness_preparation', 'native_proofs', 'recursive_proofs'):
            events, report = fixture()
            if target == 'native':
                report['owned_observations']['native_proofs'][0]['totals']['elapsed_ns'] += 1
            elif target in ('native_proofs', 'recursive_proofs'):
                report[target] += 1
            else:
                report['owned_observations'][target]['elapsed_ns'] += 1
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_source_and_owned_preparation_cannot_share_or_substitute_counts(self):
        for owned in (False, True):
            events, report = fixture()
            if owned:
                report['owned_observations']['witness_preparation']['witness_device_ns'] += 1
            else:
                report['source_preparation']['witness_completed_calls'] += 1
            with self.subTest(owned=owned), self.assertRaises(ValueError):
                self.audit(events, report)
        events, report = fixture()
        index = index_of(events, 'owned_group_report')
        events[index][0] = 'proving_stage_report'
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_raw_times_and_counts_require_present_bounded_integers(self):
        for key, observation, bits in (('elapsed_ns', False, 128), ('observation_errors', False, 64),
                ('device_ns', True, 128), ('inclusive_ns', True, 128),
                ('calls', True, 64), ('completed_calls', True, 64), ('device_calls', True, 64)):
            for invalid in (None, False, 1.5, -1, 1 << bits, '1'):
                events, report = fixture()
                value = events[index_of(events, 'owned_source_native_report')][1]
                target = value['observations'][0] if observation else value
                if invalid is None:
                    del target[key]
                else:
                    target[key] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                    self.audit(events, report)

    def test_cpu_incomplete_profile_scope_arity_and_components_fail(self):
        mutations = (
            lambda r: r.update(policy='cpu_required'),
            lambda r: r.update(succeeded=False),
            lambda r: r.update(stage_coverage_complete=False),
            lambda r: r.update(completion_rejected=True),
            lambda r: r.update(components=[{'cached': True}]),
            lambda r: r['capabilities'].update(profile='legacy_quadratic'),
            lambda r: r['capabilities'].update(scope='statement'),
            lambda r: r['capabilities'].update(max_log_fri_arity=4),
            lambda r: r['capabilities']['stages'][0].update(backend='cpu'),
            lambda r: r['observations'][0].update(backend='cpu'),
            lambda r: r['observations'].pop(),
            lambda r: r['observations'].append(copy.deepcopy(r['observations'][0])),
        )
        for ordinal, change in enumerate(mutations):
            events, report = fixture()
            change(events[index_of(events, 'owned_source_native_report')][1])
            with self.subTest(ordinal=ordinal), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_unknown_or_mislabelled_relevant_receipts_fail(self):
        for prefix in ('owned_unknown_report', 'mystery_report', 'proving_stage_report'):
            events, report = fixture()
            extra = copy.deepcopy(events[index_of(events, 'owned_source_native_report')])
            extra[0] = prefix
            events.append(extra)
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                self.audit(events, report)
        events, report = fixture()
        events[index_of(events, 'owned_native_report')][1]['entry_point'] = 'pq_aes_lane_native'
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_fixed_native_snapshot_identity_and_order_are_not_aliases(self):
        for duplicate in (False, True):
            events, report = fixture()
            entries = report['owned_observations']['native_proofs']
            if duplicate:
                entries[1] = copy.deepcopy(entries[0])
            else:
                entries[0], entries[1] = entries[1], entries[0]
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_generation_and_planning_sessions_are_bound_to_original_records(self):
        for target in ('spend', 'terminal', 'generation', 'source', 'owned'):
            events, report = fixture()
            if target in ('spend', 'terminal'):
                events[index_of(events, 'owned_generation_' + target)][1]['session_id'] += 1
            elif target == 'generation':
                report['generation_session_id'] = 12
            elif target == 'source':
                report['source_preparation']['session_id'] = 13
            else:
                report['owned_observations']['session_id'] = 11
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_generation_spend_identity_schedule_and_totals_are_checked(self):
        for key, invalid in (('ordinal', 1), ('elapsed_ns', 0), ('witness_device_calls', 0),
                ('managed_bytes', 0), ('prelude_steps', 0), ('accepted_attempt_steps', 0),
                ('source_fingerprint', [7] * 32), ('kernel_source_sha256', 'b' * 64)):
            events, report = fixture()
            events[index_of(events, 'owned_generation_spend')][1][key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_generation_terminal_requires_exact_typed_totals_and_actual_cleanup(self):
        for target, key, invalid in (('operations', 'spends', 3.0),
                ('operations', 'witness_device_ns', False), ('operations', 'seconds', 0.0),
                ('session', 'queue_drained', False), ('session', 'context_closed', 1),
                ('session', 'managed_live_bytes', 1), ('session', 'commits', 1)):
            events, report = fixture()
            events[index_of(events, 'owned_generation_terminal')][1][target][key] = invalid
            with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_generation_and_outer_sequences_reject_missing_duplicates_and_reordering(self):
        for action in ('missing_terminal', 'duplicate_terminal', 'reordered_spend', 'outer_first'):
            events, report = fixture()
            if action == 'missing_terminal':
                del events[index_of(events, 'owned_generation_terminal')]
            elif action == 'duplicate_terminal':
                index = index_of(events, 'owned_generation_terminal')
                events.insert(index, copy.deepcopy(events[index]))
            elif action == 'reordered_spend':
                events[0], events[1] = events[1], events[0]
            else:
                index = index_of(events, 'proving_stage_report', 'block_v2_preprocessing')
                events[index], events[index + 1] = events[index + 1], events[index]
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_source_cpu_failures_and_mismatched_successes_fail(self):
        for key in ('native_cpu_calls', 'native_cpu_succeeded', 'failure_events', 'succeeded'):
            events, report = fixture()
            report['source_preparation'][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.audit(events, report)

    def test_wrapper_durations_are_coverage_intervals_not_report_time_aliases(self):
        events, report = fixture()
        report['source_preparation']['seconds'] *= 1.1
        self.audit(events, report)  # Real wrapper overhead need not equal receipt duration.
        for invalid in (float('nan'), float('inf'), False, -1, 1e-12, 1e30):
            events, report = fixture()
            report['source_preparation']['seconds'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.audit(events, report)
        events, report = fixture()
        report['proving_and_verification_ns'] = 1
        with self.assertRaises(ValueError):
            self.audit(events, report)

    def test_duplicate_json_keys_and_malformed_receipt_framing_fail(self):
        events, report = fixture()
        content = render(events)
        invalid = (content.replace('{"schema":', '{"elapsed_ns": 1, "schema":', 1),
                   ' ' + content,
                   content.replace('owned_generation_report ', 'owned_generation_report\t', 1))
        for malformed in invalid:
            with self.subTest(prefix=malformed[:48]), self.assertRaises(ValueError):
                validate(malformed, report, collect_gpu_receipts)

    def test_record_parser_rejects_nonfinite_numbers_before_field_validation(self):
        self.assertEqual(parse_record('{"seconds": 1e3}', 'test'), {'seconds': 1000.0})
        for invalid in ('NaN', 'Infinity', '-Infinity', '1e999', '-1e999'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_record('{"seconds": ' + invalid + '}', 'test')


if __name__ == '__main__':
    unittest.main()
