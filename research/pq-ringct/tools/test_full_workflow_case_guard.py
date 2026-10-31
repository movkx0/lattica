"""Pure admission/report checks; these tests create no proving context."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

import full_workflow_case_guard as guard
import opencl_private_spend_validate as runner


class CompleteCaseGuardTests(unittest.TestCase):
    def test_expanded_profile_requires_matching_driver_and_receipt(self):
        for name, gib in [('expanded-36', 36), ('expanded-40', 40)]:
            self.args.host_profile = name
            with self.assertRaises(ValueError):
                self.configure()
            argv = self.argv + ['--host-profile', name]
            environment = self.environment.copy()
            selected = guard.configure(self.args, argv, environment, self.root, self.state)
            self.assertEqual(selected['worker_host_bytes'], gib * guard.GIB)
            self.assertEqual(environment['LATTICA_RINGCT_HOST_PROFILE'], name)
            self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
            plan = {guard.KEY: selected}
            with self.assertRaises(ValueError):
                guard.validate_envelope(self.envelope, plan)
            envelope = copy.deepcopy(self.envelope)
            envelope.update(host_profile=name, worker_host_bytes=gib * guard.GIB)
            envelope['report']['ledger_peak_host_bytes'] = gib * guard.GIB
            guard.validate_envelope(envelope, plan)
            envelope['report']['ledger_peak_host_bytes'] += 1
            with self.assertRaises(ValueError):
                guard.validate_envelope(envelope, plan)
            with self.assertRaises(ValueError):
                guard.configure(self.args, self.argv + ['--host-profile', 'standard'],
                                self.environment.copy(), self.root, self.state)

    def test_geometry_cache_selection_requires_bounded_matching_report(self):
        selected = guard.configure(self.args, self.argv + ['--planning-cache', 'geometry-v1'],
                                   self.environment.copy(), self.root, self.state)
        plan = {guard.KEY: selected}
        with self.assertRaises(ValueError):
            guard.validate_envelope(self.envelope, plan)
        envelope = copy.deepcopy(self.envelope)
        envelope['report']['source_geometry_cache'] = dict(
            hits=10, misses=2, evictions=0, failed_computations=0,
            planning_ns=1, entries=2, reserved_host_bytes=1 << 20)
        guard.validate_envelope(envelope, plan)
        for field, value in [('entries', 65), ('failed_computations', 1),
                             ('reserved_host_bytes', (1 << 20) + 1), ('hits', True)]:
            bad = copy.deepcopy(envelope)
            bad['report']['source_geometry_cache'][field] = value
            with self.assertRaises(ValueError):
                guard.validate_envelope(bad, plan)
        with self.assertRaises(ValueError):
            guard.validate_envelope(envelope, self.plan)

    def setUp(self):
        self.root = Path('/tmp/ringct-guard-test-source')
        self.state = self.root / '.tools/pq-opencl-opt'
        self.args = SimpleNamespace(profile='full', build_label='fullgpu-build-test',
                                    expect_tests=False, expect_result=False,
                                    expect_direct_result=False, record_artifact=[],
                                    retained_tree_storage='host',
                                    label='fullgpu-case-test')
        self.argv = [str(self.root / '.tools/target-opencl/release/pq-ringct-full-workflow'),
                     '--case', 'n3', '--layout', 'singleton', '--seed', '01' * 32,
                     '--context', '02' * 32]
        self.environment = {'LATTICA_PROVING_POLICY': 'gpu-required',
                            'LATTICA_V2_GPU_MANAGED_BYTES': str(8 * guard.GIB),
                            'LATTICA_V2_GPU_CONTEXT_BYTES': str(4 * guard.GIB),
                            'LATTICA_V2_HOST_OUTPUT_BYTES': str(32 * guard.GIB),
                            'RAYON_NUM_THREADS': '8',
                            'LATTICA_V2_GPU_RETAINED_TREE_STORAGE': 'host',
                            'LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES': str(8 * guard.GIB),
                            'LATTICA_V2_GPU_LDE_WORKSPACE_BYTES': '0',
                            'LATTICA_GPU_DEVICE_UUID': 'GPU-00000000-0000-0000-0000-000000000000'}
        self.plan = {guard.KEY: self.configure()}
        statistics = [dict(reads=0, hits=0, bypasses=1, proof_attempts=1, fresh_proofs=1)
                      for _ in guard.FAMILIES]
        self.envelope = dict(schema=guard.SCHEMA, case='n3', layout='singleton',
                             setup_seed=[1] * 32, context=[2] * 32,
                             proof_policy='fresh-only', proving_policy='gpu-required',
                             report=dict(transactions=3, native_proofs=20, recursive_proofs=10,
                                         cache_counter_scope='instrumented-cache-paths',
                                         qualification_scope='final-aggregate',
                                         completed_phases=90, generation_and_planning_ns=100,
                                         proving_and_verification_ns=200, final_cpu_verification_ns=10,
                                         complete_workflow_ns=350, ledger_peak_host_bytes=1000,
                                         ledger_peak_device_bytes=1000, cache_statistics=statistics,
                                         artifacts_qualified=True, mutations_qualified=True))

    def configure(self):
        return guard.configure(self.args, self.argv, self.environment.copy(), self.root, self.state)

    def test_exact_screening_command_and_partial_counters(self):
        self.assertTrue(self.plan[guard.KEY]['screening_only'])
        self.assertEqual(guard.validate_envelope(self.envelope, self.plan)['native_proofs'], 20)

    def test_native_cap_is_narrowed_with_worker_allowance_preserved(self):
        environment = self.environment.copy()
        selected = guard.configure(self.args, self.argv, environment, self.root, self.state)
        self.assertEqual(environment['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 * guard.GIB))
        self.assertEqual(selected['worker_host_bytes'], 32 * guard.GIB)
        self.assertEqual(selected['retained_tree_host_bytes'], 8 * guard.GIB)
        self.assertEqual(environment['LATTICA_V2_GPU_MANAGED_BYTES'], str(8 * guard.GIB))

    def test_cpu_profile_unpinned_gpu_and_changed_limits_refused(self):
        self.args.profile = 'build'
        with self.assertRaises(ValueError):
            self.configure()
        self.args.profile = 'full'
        for key, bad in [('LATTICA_GPU_DEVICE_UUID', ''), ('LATTICA_PROVING_POLICY', 'cpu-required'),
                         ('LATTICA_V2_GPU_MANAGED_BYTES', str(16 * guard.GIB))]:
            original = self.environment[key]
            self.environment[key] = bad
            with self.assertRaises(ValueError):
                self.configure()
            self.environment[key] = original

    def test_duplicate_extra_and_reordered_options_refused(self):
        original = self.argv[:]
        for argv in [original + ['--case', 'n4'], original + ['--benchmark'],
                     original[:1] + original[3:5] + original[1:3] + original[5:]]:
            self.argv = argv
            with self.assertRaises(ValueError):
                self.configure()

    def test_hash_candidates_are_screening_only_and_tree_profile_is_fixed(self):
        self.args.public_hash_kernel = 'sbox-pair-v1'
        self.assertTrue(self.configure()['screening_only'])
        self.args.public_hash_kernel = 'unknown'
        with self.assertRaises(ValueError):
            self.configure()
        self.args.public_hash_kernel = 'baseline'
        self.args.retained_tree_storage = 'device'
        with self.assertRaises(ValueError):
            self.configure()

    def test_identity_schedule_is_explicit_bounded_and_receipt_bound(self):
        self.argv += ['--identity-preprocessing', 'batched-v1', '--identity-max-streams', '2']
        selected = self.configure()
        self.assertEqual(selected['identity_preprocessing'], {'schedule': 'batched-v1', 'max_streams': 2})
        with self.assertRaises(ValueError):
            guard.validate_envelope(self.envelope, {guard.KEY: selected})
        for value in ('0', '3', '02', '17'):
            self.argv[-1] = value
            with self.assertRaises(ValueError):
                self.configure()
        self.envelope['identity_preprocessing'] = {'schedule': 'serial', 'max_streams': True}
        with self.assertRaises(ValueError):
            guard.validate_envelope(self.envelope, self.plan)

    def test_case_layout_seed_and_context_are_bound(self):
        for key, wrong in [('case', 'n4'), ('layout', 'paired-v1'),
                           ('setup_seed', [3] * 32), ('context', [4] * 32)]:
            envelope = copy.deepcopy(self.envelope)
            envelope[key] = wrong
            with self.assertRaises(ValueError):
                guard.validate_envelope(envelope, self.plan)

    def test_equal_boolean_or_float_identities_are_not_canonical(self):
        for value in (True, 1.0):
            envelope = copy.deepcopy(self.envelope)
            envelope['setup_seed'][0] = value
            with self.assertRaises(ValueError):
                guard.validate_envelope(envelope, self.plan)
        envelope = copy.deepcopy(self.envelope)
        envelope['report']['transactions'] = 3.0
        with self.assertRaises(ValueError):
            guard.validate_envelope(envelope, self.plan)

    def test_cached_proof_failed_attempt_and_false_qualification_refused(self):
        for change in ('reads', 'hits', 'proof_attempts', 'artifacts_qualified', 'mutations_qualified'):
            envelope = copy.deepcopy(self.envelope)
            if change.endswith('_qualified'):
                envelope['report'][change] = False
            else:
                envelope['report']['cache_statistics'][0][change] += 1
            with self.assertRaises(ValueError):
                guard.validate_envelope(envelope, self.plan)

    def test_invalid_complete_time_or_resource_peak_refused(self):
        for key, wrong in [('complete_workflow_ns', 250), ('native_proofs', True),
                           ('ledger_peak_device_bytes', 8 * guard.GIB + 1)]:
            envelope = copy.deepcopy(self.envelope)
            envelope['report'][key] = wrong
            with self.assertRaises(ValueError):
                guard.validate_envelope(envelope, self.plan)

    def test_duplicate_result_and_incomplete_acceptance_refused(self):
        line = guard.PREFIX + json.dumps(self.envelope) + '\n'
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            guard.validate_log(line + line, self.plan, None)
        with self.assertRaises(ValueError):
            guard.validate_log(line, self.plan, runner.collect_gpu_receipts)

    def test_complete_time_cannot_exceed_independent_runner_interval(self):
        self.plan['observation_before_validation_ns'] = 300
        line = guard.PREFIX + json.dumps(self.envelope)
        with self.assertRaisesRegex(ValueError, 'exceeds runner observation'):
            guard.validate_log(line, self.plan, runner.collect_gpu_receipts)

    def test_duplicate_json_keys_and_nonfinite_envelope_refused(self):
        for payload in ('{"case":"n3","case":"n3"}', '{"case":NaN}', '{"case":Infinity}'):
            with self.assertRaises(ValueError):
                guard.validate_log(guard.PREFIX + payload, self.plan, None)


class GpuReceiptCollectorTests(unittest.TestCase):
    def report(self):
        stages = ('preprocessing', 'randomness', 'transform', 'commitment')
        return dict(schema='lattica-proving-stages-v1', entry_point='block_v2_preprocessing',
                    policy='gpu_required', succeeded=True, stage_coverage_complete=True,
                    completion_rejected=False, observation_errors=0,
                    capabilities=dict(profile='block_v2_cubic', scope='preprocessing',
                                      stages=[dict(stage=s, backend='open_cl') for s in stages]),
                    observations=[dict(stage=s, backend='open_cl', calls=2,
                                       completed_calls=2, device_calls=1) for s in stages])

    def collect(self, report):
        return runner.collect_gpu_receipts('proving_stage_report ' + json.dumps(report))

    def test_actual_completed_and_device_calls_are_kept(self):
        result = self.collect(self.report())
        self.assertEqual(result['counts']['block_v2_preprocessing'], 1)
        self.assertEqual(result['by_entry']['block_v2_preprocessing'],
                         dict(reports=1, completed_calls=8, device_calls=4, elapsed_ns=0, device_ns=0))

    def test_cpu_failed_incomplete_or_duplicate_stages_are_rejected(self):
        for kind in ('cpu', 'failed', 'incomplete', 'duplicate', 'missing', 'no_device'):
            report = self.report()
            if kind == 'cpu':
                report['policy'] = 'cpu_required'
            elif kind == 'failed':
                report['succeeded'] = False
            elif kind == 'incomplete':
                report['observations'][0]['completed_calls'] = 1
            elif kind == 'duplicate':
                report['observations'].append(report['observations'][0])
            elif kind == 'missing':
                report['observations'].pop()
            else:
                report['observations'][0]['device_calls'] = 0
            with self.assertRaises(ValueError):
                self.collect(report)


class FinalArtifactBindingTests(unittest.TestCase):
    """Check disk evidence binding only; the fixture is not a cryptographic proof."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ringct-artifact-guard-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        header = bytearray(2456)
        header[:8] = b'LQRFN001'
        struct.pack_into('<Q', header, 8, 1)
        for offset, value in [(16, 1), (48, 2), (80, 3), (112, 4)]:
            header[offset:offset + 32] = bytes([value] * 32)
        struct.pack_into('<8Q', header, 144, 1, 0, 3, 3, 8, 25, 64, 8)
        self.packet = bytes(header) + b'LBV2RP02'
        digest = hashlib.sha3_256(self.packet).digest()
        self.path = self.directory / ('ringct-final-' + digest.hex() + '.bin')
        self.path.write_bytes(self.packet)
        info = self.path.stat()
        self.qualification = dict(artifact_round_trip=True, public_mutation_rejected=True,
                                  proof_mutation_rejected=True, decoded_positive_checks=3,
                                  packet_sha3_256=list(digest), proof_bytes=8,
                                  packet_bytes=len(self.packet), file_device=info.st_dev,
                                  file_inode=info.st_ino, compiled_source_fingerprint=[1] * 32,
                                  source_fingerprint=[2] * 32, batch_profile=[3] * 32,
                                  context=[4] * 32, height=8, public_values=25)
        self.report = dict(transactions=3, final_qualification=self.qualification)
        self.plan = {guard.KEY: dict(output_directory=str(self.directory), context=[4] * 32)}

    def test_exact_disk_binding(self):
        result = guard.validate_artifact(self.report, self.plan)
        self.assertEqual(result['path'], str(self.path))
        self.assertEqual(result['packet_bytes'], len(self.packet))

    def test_changed_digest_or_provenance_rejected(self):
        self.path.write_bytes(self.packet[:-1] + b'3')
        with self.assertRaises(ValueError):
            guard.validate_artifact(self.report, self.plan)
        self.path.write_bytes(self.packet)
        self.qualification['file_inode'] += 1
        with self.assertRaises(ValueError):
            guard.validate_artifact(self.report, self.plan)

    def test_wrong_case_context_and_extra_artifact_rejected(self):
        self.plan[guard.KEY]['context'] = [5] * 32
        with self.assertRaises(ValueError):
            guard.validate_artifact(self.report, self.plan)
        self.plan[guard.KEY]['context'] = [4] * 32
        (self.directory / 'extra.bin').write_bytes(b'')
        with self.assertRaises(ValueError):
            guard.validate_artifact(self.report, self.plan)

    def test_symlink_artifact_rejected(self):
        original = self.directory / 'original.bin'
        self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises((ValueError, OSError)):
            guard.validate_artifact(self.report, self.plan)

    def test_equal_float_provenance_or_qualification_is_rejected(self):
        for field in ('file_inode', 'file_device', 'height', 'public_values', 'decoded_positive_checks'):
            original = self.qualification[field]
            self.qualification[field] = float(original)
            with self.assertRaises(ValueError):
                guard.validate_artifact(self.report, self.plan)
            self.qualification[field] = original

    def test_consistently_encoded_height_still_obeys_unchanged_row_limit(self):
        packet = bytearray(self.packet)
        struct.pack_into('<Q', packet, 176, 1 << 21)
        digest = hashlib.sha3_256(packet).digest()
        self.path.unlink()
        self.path = self.directory / ('ringct-final-' + digest.hex() + '.bin')
        self.path.write_bytes(packet)
        self.qualification.update(height=1 << 21, packet_sha3_256=list(digest),
                                  file_inode=self.path.stat().st_ino)
        with self.assertRaises(ValueError):
            guard.validate_artifact(self.report, self.plan)


if __name__ == '__main__':
    unittest.main()
