"""Source/binary-bound recursive component admission; no compiler or GPU launched."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'recursion_guard', Path(__file__).with_name('opencl_private_spend_validate.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def arguments(mode='child', **changes):
    cpu = mode == 'caller-census'
    values = dict(
        profile='research-compile-large' if cpu else 'direct-full',
        label='recursive-census' if cpu else 'recursive-component', seconds=60,
        expect_tests=True, expect_result=False, expect_direct_result=False,
        execute=True, exclusive_window=True, build_label='recursive-build', record_artifact=[],
        direct_ring_recursion_test=mode,
        direct_ring_recursion_census_label=None if cpu else 'recursive-census',
        retained_tree_storage='device' if cpu else 'host', public_hash_kernel='baseline',
        device_uuid=None if cpu else 'GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c',
        command=['/tmp/lattica_pq_direct_spend_research-recorded', runner.DIRECT_RING_RECURSION_TESTS[mode],
                 '--exact', *([] if cpu else ['--ignored']), '--test-threads=1', '--nocapture'])
    values.update(changes)
    return argparse.Namespace(**values)


def census_output(actual=1009424):
    selector = runner.DIRECT_RING_RECURSION_TESTS['caller-census']
    return (f'running 1 test\ntest {selector} ... direct_ring_recursive_outer_orchestration_bytes '
            f'actual=30000 timing_additional=2000 allowance=32768\ndirect_ring_recursive_caller_bytes '
            f'actual={actual} allowance=1048576 remaining={1048576 - actual}\nok\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out\n')


class RecursionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        state = patch.object(runner, 'STATE', self.root)
        state.start()
        self.addCleanup(state.stop)

    def test_gpu_modes_preserve_original_limits_and_add_only_the_exact_flag(self):
        for mode, flag in runner.DIRECT_RING_RECURSION_FLAGS.items():
            plan = runner.build_plan(arguments(mode))
            base = runner.build_plan(arguments(mode, direct_ring_recursion_test=None,
                                               direct_ring_recursion_census_label=None))
            self.assertEqual(plan['environment'], dict(base['environment'], **{flag: '1'}))
            for key in ('memory_max_bytes', 'memory_high_bytes', 'fresh_memavailable_required_bytes',
                        'cpu_quota', 'profile', 'performance_qualified'):
                self.assertEqual(plan[key], base[key])
            self.assertEqual(plan['memory_max_bytes'], 45 * runner.GIB)
            self.assertEqual(plan['memory_high_bytes'], 43 * runner.GIB)
            self.assertEqual(plan['fresh_memavailable_required_bytes'], 47 * runner.GIB)
            self.assertEqual(plan['environment']['LATTICA_V2_HOST_OUTPUT_BYTES'], str(32 * runner.GIB))
            self.assertEqual(plan['environment']['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * runner.GIB))
            self.assertEqual(plan['environment']['LATTICA_V2_GPU_CONTEXT_BYTES'], str(4 * runner.GIB))
            selected = plan['direct_ring_recursion_environment']
            self.assertEqual(selected['caller_allowance_bytes'], 1 << 20)
            self.assertEqual(selected['recursive_caller_subceiling_bytes'], 192 << 10)
            self.assertTrue(selected['requires_same_source_build_and_executable_census'])
            for key in ('dispatch_authority', 'performance_qualified',
                        'complete_faithful_ringct_workflow', 'n3_n4_aggregate_qualification'):
                self.assertFalse(selected[key])
            self.assertIsNone(base['direct_ring_recursion_environment'])

    def test_caller_census_is_exact_cpu_only_and_keeps_original_envelope(self):
        plan = runner.build_plan(arguments('caller-census'))
        base = runner.build_plan(arguments('caller-census', direct_ring_recursion_test=None))
        self.assertEqual(plan['environment'], base['environment'])
        self.assertEqual(plan['memory_max_bytes'], 32 * runner.GIB)
        self.assertEqual(plan['memory_high_bytes'], 30 * runner.GIB)
        self.assertEqual(plan['fresh_memavailable_required_bytes'], 36 * runner.GIB)
        self.assertEqual(plan['cpu_quota'], '200%')
        self.assertEqual(plan['environment']['LATTICA_PROVING_POLICY'], 'cpu-required')
        self.assertFalse(any('GPU' in key or 'QUALIFICATION' in key for key in plan['environment']))
        self.assertIsNone(plan['direct_ring_recursion_environment']['prior_caller_census_label'])

    def test_gpu_profile_device_selection_and_census_are_required_before_launch(self):
        changes = [dict(profile=p) for p in ('build', 'research-compile-large', 'smoke', 'full')] + [
            dict(build_label=None), dict(device_uuid=None), dict(expect_tests=False),
            dict(public_hash_kernel='sbox-pair-v1'), dict(retained_tree_storage='device'),
            dict(direct_ring_recursion_census_label=None),
            dict(direct_ring_recursion_census_label='../unsafe'),
            dict(direct_ring_recursion_census_label='recursive-component'),
            dict(direct_ring_screen=True), dict(direct_ring_identity_test='baseline'),
            dict(note_owned_proof=True), dict(owned_request_source_test='parent-sources'),
            dict(record_artifact=['/tmp/unrelated']), dict(benchmark=True),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(arguments(**change))
        with self.assertRaises(ValueError):
            runner.build_plan(arguments(direct_ring_recursion_test=None))

    def test_census_cannot_acquire_gpu_environment_or_use_ignored_filter(self):
        for change in (dict(profile='direct-full'), dict(retained_tree_storage='host'),
                       dict(device_uuid='GPU-b28db334-b11d-c7ec-1e24-d2f408b0a55c'),
                       dict(direct_ring_recursion_census_label='earlier'),
                       dict(owned_source_shape_test=True)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.build_plan(arguments('caller-census', **change))
        command = arguments('caller-census').command
        with self.assertRaises(ValueError):
            runner.build_plan(arguments('caller-census', command=[*command, '--ignored']))

    def test_only_exact_single_selector_and_thread_count_are_accepted(self):
        original = arguments().command
        commands = [
            ['/usr/bin/cargo', *original[1:]],
            ['/tmp/lattica_prover_p3-recorded', *original[1:]],
            [original[0], original[1] + 'wrong', *original[2:]],
            [original[0], *original[2:]], [*original, '--exact'],
            [arg for arg in original if arg != '--ignored'],
            [arg.replace('--test-threads=1', '--test-threads=2') for arg in original],
        ]
        for command in commands:
            with self.subTest(command=command), self.assertRaises(ValueError):
                runner.build_plan(arguments(command=command))

    def test_census_parser_requires_real_fitting_report_and_exact_footer(self):
        accepted = runner.validate_direct_ring_caller_census(census_output())
        self.assertEqual(accepted['caller_requested_bytes'], 1009424)
        self.assertEqual(accepted['caller_remaining_bytes'], 39152)
        for content in (
            census_output(1048577), census_output(0), census_output() + census_output(),
            census_output().replace('remaining=39152', 'remaining=39151'),
            census_output().replace('allowance=1048576', 'allowance=2097152'),
            census_output().replace('1 passed', '0 passed'),
            census_output().replace('0 ignored', '1 ignored'),
            census_output() + 'PUBLIC_HASH_EXECUTION {}\n',
            census_output().replace('direct_ring_recursive_caller_bytes', 'other_census'),
        ):
            with self.subTest(content=content), self.assertRaises(ValueError):
                runner.validate_direct_ring_caller_census(content)

    def evidence(self, mode='child'):
        runs = self.root / 'runs'
        runs.mkdir(exist_ok=True)
        binary = self.root / 'lattica_pq_direct_spend_research-recorded'
        binary.write_text('never executed')
        binary.chmod(0o755)
        sources = {'research/source.rs': 'source-digest'}
        build_log = runs / 'recursive-build.log'
        build_log.write_text(f'  Executable unittests src/lib.rs ({binary})\n')
        build = dict(status='passed', profile='build', source_inputs_unchanged=True,
                     all_subprocesses_terminal_and_reaped=True, input_sha256=sources,
                     built_artifact_sha256={str(binary): runner.sha(binary)},
                     raw_log=str(build_log), raw_log_sha256=runner.sha(build_log),
                     command=['/toolchain/cargo', 'test', '--manifest-path',
                              str(runner.ROOT / 'research/pq-direct-spend/Cargo.toml'),
                              '--release', '--features', 'ring-recursive-outer-experiment', '--no-run'])
        build_path = runs / 'recursive-build.json'
        build_path.write_text(json.dumps(build))
        census_command = arguments('caller-census').command
        census_command[0] = str(binary)
        census = runner.build_plan(arguments('caller-census', command=census_command))
        executable = runner.executable_provenance(census, sources, runs)
        log = runs / 'recursive-census.log'
        log.write_text(census_output())
        census.update(status='passed', source_inputs_unchanged=True, executable_unchanged=True,
                      all_subprocesses_terminal_and_reaped=True, service_stop_completed=True,
                      input_sha256=sources, executable_provenance=executable,
                      raw_log=str(log), raw_log_sha256=runner.sha(log),
                      direct_ring_recursion_acceptance=runner.validate_direct_ring_caller_census(log.read_text()))
        record = runs / 'recursive-census.json'
        record.write_text(json.dumps(census))
        gpu_command = arguments(mode).command
        gpu_command[0] = str(binary)
        plan = runner.build_plan(arguments(mode, command=gpu_command))
        return plan, sources, executable, runs, record

    def test_prior_census_binds_exact_source_emitted_binary_build_policy_and_log(self):
        for mode in ('child', 'outer'):
            plan, sources, executable, runs, record = self.evidence(mode)
            runner.require_direct_ring_recursion_build(plan, executable)
            accepted = runner.prior_direct_ring_caller_census(plan, sources, executable, runs)
            self.assertEqual(accepted['record_sha256'], runner.sha(record))
            self.assertEqual(accepted['executable_sha256'], executable['sha256'])
            self.assertEqual(accepted['acceptance']['caller_remaining_bytes'], 39152)

    def test_failed_stale_mismatched_or_unretired_census_refuses(self):
        plan, sources, executable, runs, path = self.evidence()
        original = json.loads(path.read_text())
        changes = [
            ('status', 'failed_or_incomplete'), ('profile', 'direct-full'),
            ('source_inputs_unchanged', False), ('executable_unchanged', False),
            ('all_subprocesses_terminal_and_reaped', False), ('service_stop_completed', False),
            ('input_sha256', {'research/source.rs': 'other'}), ('build_label', 'other-build'),
            ('executable_provenance', dict(executable, sha256='other')),
            ('command', [plan['command'][0], 'other', '--exact']),
            ('environment', dict(original['environment'], LATTICA_PROVING_POLICY='gpu-required')),
            ('memory_max_bytes', 33 * runner.GIB), ('raw_log_sha256', 'other'),
            ('direct_ring_recursion_acceptance', {}), ('expect_result', True),
        ]
        for field, value in changes:
            changed = copy.deepcopy(original)
            changed[field] = value
            path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.prior_direct_ring_caller_census(plan, sources, executable, runs)
        path.write_text(json.dumps(original))
        (runs / 'recursive-census.log').write_text('test result: ok. 1 passed; 0 failed;\n')
        with self.assertRaises(ValueError):
            runner.prior_direct_ring_caller_census(plan, sources, executable, runs)

    def test_changed_binary_and_stale_cargo_inventory_are_rejected_by_original_provenance(self):
        plan, sources, executable, runs, _ = self.evidence()
        binary = Path(executable['path'])
        binary.write_text('changed executable')
        with self.assertRaises(ValueError):
            runner.executable_provenance(plan, sources, runs)
        binary.write_text('never executed')
        build_path = Path(executable['build_record'])
        build = json.loads(build_path.read_text())
        log = runs / 'recursive-build.log'
        log.write_text(' Executable unittests src/lib.rs (/tmp/another-binary)\n')
        build['raw_log_sha256'] = runner.sha(log)
        build_path.write_text(json.dumps(build))
        with self.assertRaises(ValueError):
            runner.executable_provenance(plan, sources, runs)

    def test_release_feature_and_exact_research_manifest_are_required(self):
        plan, _, executable, _, _ = self.evidence('outer')
        path = Path(executable['build_record'])
        original = json.loads(path.read_text())
        command = original['command']
        for changed in (
            [arg for arg in command if arg != '--release'],
            [arg.replace('ring-recursive-outer-experiment', 'ring-recursion-experiment') for arg in command],
            [*command, '--profile', 'dev'],
            [arg.replace('pq-direct-spend/Cargo.toml', 'pq-ringct/Cargo.toml') for arg in command],
            [arg for arg in command if arg != '--no-run'],
        ):
            record = dict(original, command=changed)
            path.write_text(json.dumps(record))
            identity = dict(executable, build_record_sha256=runner.sha(path))
            with self.subTest(command=changed), self.assertRaises(ValueError):
                runner.require_direct_ring_recursion_build(plan, identity)

    def test_use_time_recheck_changes_when_consistent_census_files_change(self):
        plan, sources, executable, runs, path = self.evidence()
        before = runner.prior_direct_ring_caller_census(plan, sources, executable, runs)
        log = runs / 'recursive-census.log'
        log.write_text(census_output(1009423))
        record = json.loads(path.read_text())
        record.update(raw_log_sha256=runner.sha(log),
                      direct_ring_recursion_acceptance=runner.validate_direct_ring_caller_census(log.read_text()))
        path.write_text(json.dumps(record))
        after = runner.prior_direct_ring_caller_census(plan, sources, executable, runs)
        self.assertNotEqual(before, after)


    def test_missing_orchestration_is_valid_only_for_child_with_rebound_evidence(self):
        for mode in ('child', 'outer'):
            plan, sources, executable, runs, record_path = self.evidence(mode)
            record = json.loads(record_path.read_text())
            log_path = Path(record['raw_log'])
            text = log_path.read_text().replace(
                'direct_ring_recursive_outer_orchestration_bytes '
                'actual=30000 timing_additional=2000 allowance=32768\n', '')
            log_path.write_text(text)
            record['raw_log_sha256'] = runner.sha(log_path)
            record['direct_ring_recursion_acceptance'] = runner.validate_direct_ring_caller_census(text)
            self.assertIsNone(record['direct_ring_recursion_acceptance']['outer_orchestration'])
            record_path.write_text(json.dumps(record))
            if mode == 'outer':
                with self.assertRaisesRegex(ValueError, 'orchestration census'):
                    runner.prior_direct_ring_caller_census(plan, sources, executable, runs)
            else:
                runner.prior_direct_ring_caller_census(plan, sources, executable, runs)


OUTER_TRANSPORT_PEAK_BYTES = 70_283_356  # Compiled phase plus unchanged 1 MiB caller.


class RecursionOutputTests(unittest.TestCase):
    def phase(self, proof, worker):
        import opencl_direct_spend_audit as audit

        def native(completed):
            stages = sorted(audit.PROOF_STAGES if completed else audit.SETUP_STAGES)
            return dict(schema='lattica-proving-stages-v1',
                        entry_point='block_v2_registered_program' if completed else 'block_v2_preprocessing',
                        policy='gpu_required', succeeded=True, stage_coverage_complete=True,
                        completion_rejected=False, observation_errors=0, components=[],
                        capabilities=dict(profile='block_v2_cubic',
                            scope='registered_proof' if completed else 'preprocessing', max_log_fri_arity=1,
                            stages=[dict(stage=stage, backend='open_cl') for stage in stages]),
                        observations=[dict(stage=stage, calls=1, device_calls=1, completed_calls=1,
                                           backend='open_cl') for stage in stages])
        return dict(registration=native(False), proving=native(True),
                    public_hash=dict(kernel='baseline', gpu_tuning_compiled=True, nvidia_supported=True),
                    terminal=dict(context_closed=True, queue_drained=True, completion_claimed=proof,
                        host_allowance_bytes=32 * runner.GIB, device_allowance_bytes=8 * runner.GIB,
                        gpu_context_allowance_bytes=4 * runner.GIB, max_rows=1 << 20,
                        managed_peak_bytes=1, commits=1, allocations=1, uploaded_bytes=1, downloaded_bytes=1),
                    footprint=dict(managed_limit_bytes=8 * runner.GIB, context_reserve_bytes=4 * runner.GIB,
                        worker_host_limit_bytes=worker, host_tree_quota_bytes=8 * runner.GIB,
                        caller_reserved_host_bytes=1 << 20,
                        physical_device_uuid=list(bytes.fromhex('b28db334b11dc7ec1e24d2f408b0a55c')),
                        backend_host_budget_bytes=24 * runner.GIB, host_phase_peak_bytes=worker,
                        device_phase_peak_bytes=8 * runner.GIB, tree_storage_mode='host_backing',
                        requires_consuming_registration=True, witness_instructions_retired_before_quotient_required=True))

    def test_actual_receipt_auditor_and_partition_device_checks_are_applied(self):
        plan = runner.build_plan(arguments('outer'))
        plan['observation_before_validation_ns'] = 104
        for proof, worker in ((True, 32 * runner.GIB), (False, 32 * runner.GIB - (64 << 20))):
            report = self.phase(proof, worker)
            runner.recursive_phase_receipts(report, plan, proof, worker)
            for section, field, value in (
                ('registration', 'succeeded', False), ('terminal', 'queue_drained', False),
                ('footprint', 'physical_device_uuid', [0] * 16),
                ('footprint', 'worker_host_limit_bytes', worker + 1),
                ('footprint', 'host_phase_peak_bytes', worker + 1),
                ('footprint', 'backend_host_budget_bytes', 24 * runner.GIB + 1),
                ('footprint', 'tree_storage_mode', 'device'),
                ('public_hash', 'kernel', 'sbox-pair-v1'),
            ):
                changed = copy.deepcopy(report)
                changed[section][field] = value
                with self.subTest(proof=proof, field=field), self.assertRaises(ValueError):
                    runner.recursive_phase_receipts(changed, plan, proof, worker)

    def reports(self, mode):
        child = dict(schema='lattica-research-direct-ring-gpu-proof-v1', proof_generation='fresh-only',
                     policy='gpu_required', registration_lifetime='consumed-once',
                     witness_instructions_retired_before_quotient=True, independent_verification_required=True,
                     total_proving_lifecycle_ns=100)
        verified = dict(schema='lattica-research-direct-ring-independent-verification-v1', verified=True,
                        reused_prover_state=False, synthetic_hints_evaluated=False,
                        public_reconstruction='complete-program-and-fresh-preprocessing-cap',
                        verifier_preprocessing_policy='gpu_required', proof_verification_backend='cpu', mutation_checks=2)
        result = dict(independently_verified_children=1, complete_transaction_aggregate=False,
                      final_aggregate=False, child_verification=verified)
        if mode == 'child':
            result.update(schema='lattica-research-direct-ring-recursive-constraints-v1',
                          scope='one-full-direct-ring-child-recursive-constraints-only',
                          recursive_proofs_generated=0, all_recursive_constraints_satisfied=True,
                          public_binding_mutation_rejections=4)
        else:
            result.update(schema='lattica-research-direct-ring-single-child-recursive-proof-v1',
                          scope='one-direct-ring-child-one-outer-proof', proof_generation='fresh-only',
                          outer_recursive_proofs_generated=1, independently_verified_outer_proofs=1,
                          artifact_roundtrip=True,
                          artifact_transport=dict(encoded_bytes=220, decoded_proof_retained_bytes=2, total_ns=1),
                          total_qualification_ns=3,
                          source_cap_provenance='private-expected-public-independent-child-reconstruction',
                          proving={'descriptor': {'test': 'same-exact-descriptor'}, 'retained_proof_bytes': 1, 'total_ns': 2},
                          independent_verification=dict(cpu_verified=True, source_manifest_matches=True,
                              synthetic_hints_evaluated=False, public_mutation_rejections=4,
                              opening_mutation_rejections=1, descriptor={'test': 'same-exact-descriptor'}),
                          storage=dict(independent_registration_host_partition_bytes=32 * runner.GIB - (64 << 20),
                                       retained_outer_proof_allowance_bytes=64 << 20, caller_reserved_bytes=1 << 20,
                                       source_construction_bytes=1, source_comparison_peak_bytes=1,
                                       reconstruction_with_retained_outer_peak_bytes=1,
                                       cpu_verifier_with_proof_reserved_bytes=1, cpu_phase_peak_bytes=1,
                                       artifact_roundtrip_peak_bytes=OUTER_TRANSPORT_PEAK_BYTES))
        return child, result

    def content(self, mode, child, result):
        child_marker = ('direct_ring_recursive_child_proving_report ' if mode == 'child'
                        else 'direct_ring_recursive_outer_child_proving_report ')
        marker = 'direct_ring_recursive_constraint_report ' if mode == 'child' else 'direct_ring_recursive_outer_report '
        return (f'test {runner.DIRECT_RING_RECURSION_TESTS[mode]} ... ' + child_marker + json.dumps(child) + '\n'
                + marker + json.dumps(result) + '\n'
                + ('direct_ring_recursive_outer_component_timing elapsed_ns=103\n' if mode == 'outer' else '')
                + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out\n')

    def test_component_scopes_and_receipt_phases_remain_separate(self):
        for mode in ('child', 'outer'):
            plan = runner.build_plan(arguments(mode))
            plan['observation_before_validation_ns'] = 104
            child, result = self.reports(mode)
            with patch.object(runner, 'recursive_phase_receipts') as receipts:
                accepted = runner.validate_direct_ring_recursion(self.content(mode, child, result), plan)
            self.assertEqual(receipts.call_count, 2 if mode == 'child' else 4)
            self.assertEqual(accepted['fresh_outer_proofs'], 0 if mode == 'child' else 1)
            self.assertFalse(accepted['complete_faithful_ringct_workflow'])
            self.assertFalse(accepted['performance_qualified'])
            self.assertEqual(accepted['artifact_roundtrip'], mode == 'outer')
            self.assertFalse(accepted['archived_artifact_qualified'])

    def test_missing_negative_probes_false_scope_and_proof_claims_refuse(self):
        for mode in ('child', 'outer'):
            plan = runner.build_plan(arguments(mode))
            plan['observation_before_validation_ns'] = 104
            child, original = self.reports(mode)
            variants = []
            for field, value in [('independently_verified_children', 0), ('complete_transaction_aggregate', True),
                                 ('final_aggregate', True), ('schema', 'other')]:
                variants.append(dict(original, **{field: value}))
            bad = copy.deepcopy(original)
            bad['child_verification']['mutation_checks'] = 1
            variants.append(bad)
            if mode == 'child':
                variants += [dict(original, recursive_proofs_generated=1),
                             dict(original, public_binding_mutation_rejections=3)]
            else:
                variants += [dict(original, artifact_roundtrip=False), dict(original, outer_recursive_proofs_generated=0)]
                bad = copy.deepcopy(original)
                bad['independent_verification']['opening_mutation_rejections'] = 0
                variants.append(bad)
                bad = copy.deepcopy(original)
                bad['storage']['independent_registration_host_partition_bytes'] = 32 * runner.GIB
                variants.append(bad)
            for result in variants:
                with self.subTest(mode=mode, result=result), patch.object(runner, 'recursive_phase_receipts'), self.assertRaises(ValueError):
                    runner.validate_direct_ring_recursion(self.content(mode, child, result), plan)

    def test_failure_duplicate_and_zero_test_output_cannot_qualify(self):
        plan = runner.build_plan(arguments('outer'))
        plan['observation_before_validation_ns'] = 104
        child, result = self.reports('outer')
        valid = self.content('outer', child, result)
        for content in (valid + valid, valid.replace('1 passed', '0 passed'),
                        valid + 'direct_ring_recursive_outer_failure {}\n',
                        valid + 'DIRECT_RING_RESULT {}\n', valid.replace('opening_mutation_rejections', 'missing'),
                        valid.replace('"opening_mutation_rejections": 1',
                                      '"opening_mutation_rejections": 1, "opening_mutation_rejections": 1')):
            with self.subTest(content=content), patch.object(runner, 'recursive_phase_receipts'), self.assertRaises(ValueError):
                runner.validate_direct_ring_recursion(content, plan)

    def test_outer_transport_types_bounds_and_time_containment_refuse(self):
        plan = runner.build_plan(arguments('outer'))
        plan['observation_before_validation_ns'] = 104
        child, original = self.reports('outer')
        variants = []
        for field in ('encoded_bytes', 'decoded_proof_retained_bytes', 'total_ns'):
            for value in (True, 1.0, '1', None, 0):
                changed = copy.deepcopy(original)
                changed['artifact_transport'][field] = value
                variants.append(changed)
        for field, value in (
            ('encoded_bytes', 219), ('encoded_bytes', 2_097_365),
            ('decoded_proof_retained_bytes', (64 << 20) + 1),
            ('total_ns', 3), ('total_ns', 1 << 128),
        ):
            changed = copy.deepcopy(original)
            changed['artifact_transport'][field] = value
            variants.append(changed)
        for field in ('encoded_bytes', 'decoded_proof_retained_bytes', 'total_ns'):
            changed = copy.deepcopy(original)
            del changed['artifact_transport'][field]
            variants.append(changed)
        changed = copy.deepcopy(original)
        changed['artifact_transport']['file_verified'] = True
        variants.append(changed)
        for field in original['storage']:
            changed = copy.deepcopy(original)
            changed['storage'][field] = True
            variants.append(changed)
        for value in (OUTER_TRANSPORT_PEAK_BYTES - 1, OUTER_TRANSPORT_PEAK_BYTES + 1):
            changed = copy.deepcopy(original)
            changed['storage']['artifact_roundtrip_peak_bytes'] = value
            variants.append(changed)
        for section, field, value in (
            ('proving', 'total_ns', True), ('proving', 'total_ns', 4),
            ('proving', 'retained_proof_bytes', 0),
            ('proving', 'retained_proof_bytes', (64 << 20) + 1),
            ('child_verification', 'mutation_checks', 2.0),
            ('independent_verification', 'public_mutation_rejections', 4.0),
            ('independent_verification', 'opening_mutation_rejections', True),
        ):
            changed = copy.deepcopy(original)
            changed[section][field] = value
            variants.append(changed)
        variants += [dict(original, total_qualification_ns=True),
                     dict(original, total_qualification_ns=1),
                     dict(original, total_qualification_ns=1 << 128)]
        for index, result in enumerate(variants):
            with self.subTest(case=index), patch.object(runner, 'recursive_phase_receipts'), self.assertRaises(ValueError):
                runner.validate_direct_ring_recursion(self.content('outer', child, result), plan)


    def test_component_wrapper_requires_runner_observation_only_for_outer(self):
        child, result = self.reports('child')
        plan = runner.build_plan(arguments('child'))
        self.assertNotIn('observation_before_validation_ns', plan)
        with patch.object(runner, 'recursive_phase_receipts'):
            runner.validate_direct_ring_recursion(self.content('child', child, result), plan)
        child, result = self.reports('outer')
        for value in [None, True, False, 0, -1, 104.0, '104', 1 << 128]:
            plan = runner.build_plan(arguments('outer'))
            if value is not None:
                plan['observation_before_validation_ns'] = value
            with self.subTest(value=value), patch.object(runner, 'recursive_phase_receipts'):
                with self.assertRaisesRegex(ValueError, 'runner observation before validation'):
                    runner.validate_direct_ring_recursion(self.content('outer', child, result), plan)


if __name__ == '__main__':
    unittest.main()
