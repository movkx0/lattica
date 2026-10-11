#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import block_v2_resources as R

spec = importlib.util.spec_from_file_location('multi', Path(__file__).with_name('block-v2-multi-gpu-run.py'))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def host():
    return {'physical_bytes': 64 * R.GIB, 'available_bytes': 58 * R.GIB,
            'cgroup_memory_headroom': None, 'cpu_capacity': '24', 'effective_cpus': list(range(24)),
            'scratch': {'capacity_bytes': 32 * R.GIB, 'available_bytes': 30 * R.GIB,
                        'quota_bytes': None, 'device': 9, 'path': '/tmp', 'tmpfs': True}}


def device(uuid='GPU-a', total=16 * R.GIB, free=15 * R.GIB):
    return {'uuid': uuid, 'opencl': {'global_bytes': total, 'max_allocation_bytes': total // 4, 'driver': 'CL'},
            'nvidia': {'total_bytes': total, 'free_bytes': free, 'driver': 'NV'}}


def calibration(uuid='GPU-a', overhead=600 * R.MIB):
    return {'uuid': uuid, 'driver': 'NV', 'runtime': 'CL', 'peak_context_bytes': overhead}


class ResourceTests(unittest.TestCase):
    def test_coordinator_jobs_split_only_within_an_admitted_cap(self):
        floor = R.COORDINATOR_JOB_HOST_BYTES
        shared = R.COORDINATOR_SHARED_HOST_BYTES
        self.assertEqual(floor, 337 * R.MIB)
        self.assertEqual(shared, 512 * R.MIB)
        self.assertEqual(R.coordinator_job_budgets(shared + floor, 1), [floor])
        self.assertEqual(R.coordinator_job_budgets(shared + 2 * floor + 1, 2), [floor + 1, floor])
        for total, workers in [(floor - 1, 1), (2 * floor - 1, 2), (0, 1),
                               (floor, 0), (floor, -1), (True, 1), (floor, True)]:
            with self.assertRaises(ValueError):
                R.coordinator_job_budgets(total, workers)

    def test_coordinator_partitions_preserve_caps_for_all_worker_counts(self):
        floor = R.COORDINATOR_JOB_HOST_BYTES
        for workers in range(1, 17):
            for extra in (0, 1, workers - 1, 3 * workers + 1):
                for shared in (R.COORDINATOR_SHARED_HOST_BYTES,
                               R.COORDINATOR_SHARED_HOST_BYTES + 1, R.GIB):
                    total = shared + workers * floor + extra
                    with self.subTest(workers=workers, extra=extra, shared=shared):
                        jobs = R.coordinator_job_budgets(total, workers, shared)
                        self.assertEqual(len(jobs), workers)
                        self.assertEqual(sum(jobs) + shared, total)
                        self.assertGreaterEqual(min(jobs), floor)
                        self.assertLessEqual(max(jobs) - min(jobs), 1)
                        self.assertEqual(jobs, sorted(jobs, reverse=True))
                        with self.assertRaisesRegex(ValueError, 'coordinator RAM'):
                            R.coordinator_job_budgets(shared + workers * floor - 1, workers, shared)
        total = R.COORDINATOR_SHARED_HOST_BYTES + floor
        for invalid in (None, True, -1, 0, '536870912', 536870912.0,
                        R.COORDINATOR_SHARED_HOST_BYTES - 1, total + 1):
            with self.subTest(shared=invalid), self.assertRaises(ValueError):
                R.coordinator_job_budgets(total, 1, invalid)
        for invalid in (True, 0, -1, 17, '1', 1.0):
            with self.subTest(workers=invalid), self.assertRaises(ValueError):
                R.coordinator_job_budgets(total, invalid)
        with self.assertRaises(ValueError):
            R.coordinator_job_budgets(1 << 63, 1)

    def test_automatic_coordinator_floor_reduces_worker_ram_within_fleet_cap(self):
        machine = host()
        machine.update(physical_bytes=16 * R.GIB, available_bytes=14 * R.GIB)
        budgets = R.shared_budgets(machine, ['GPU-a', 'GPU-b'])
        coordinator = budgets['GPU-a']['host']['coordinator_bytes']
        self.assertEqual(coordinator, R.up(2 * R.COORDINATOR_JOB_HOST_BYTES))
        with self.assertRaisesRegex(ValueError, 'coordinator RAM'):
            R.coordinator_job_budgets(coordinator, 2)
        used = coordinator + sum(b['host']['worker_bytes'] for b in budgets.values())
        self.assertLessEqual(used, budgets['GPU-a']['host']['fleet_bytes'])

    def test_explicit_pool_coordinator_shortfall_is_rejected(self):
        policy = {'wallet_threads': 4, 'wallet_bytes': 4 * R.GIB,
                  'coordinator_threads': 2, 'coordinator_bytes': 512 * R.MIB,
                  'weights': {'GPU-a': 1, 'GPU-b': 1}}
        with self.assertRaisesRegex(ValueError, 'coordinator RAM'):
            R.shared_budgets(host(), ['GPU-a', 'GPU-b'], policy)
        policy['coordinator_bytes'] = R.up(R.COORDINATOR_SHARED_HOST_BYTES + 2 * R.COORDINATOR_JOB_HOST_BYTES)
        budgets = R.shared_budgets(host(), ['GPU-a', 'GPU-b'], policy)
        self.assertEqual(budgets['GPU-a']['host']['coordinator_bytes'], policy['coordinator_bytes'])

    def test_worker_protocol_storage_is_additive_without_changing_witness_geometry(self):
        profile = self.witness_profile()
        witness = R.witness_reservation(profile)
        total = R.extra_host_reserve(profile)
        with patch.object(R, 'WORKER_PROTOCOL_HOST_BYTES', 0):
            self.assertEqual(total - R.extra_host_reserve(profile), 8 * R.MIB)
            self.assertEqual(R.witness_reservation(profile), witness)
        legacy = json.loads(Path(__file__).with_name(
            'block-v2-multi-gpu-direct-readback-workload.json').read_text())
        baseline = R.extra_host_reserve(legacy)
        with patch.object(R, 'WORKER_PROTOCOL_HOST_BYTES', 0):
            self.assertEqual(baseline - R.extra_host_reserve(legacy), 8 * R.MIB)

    def test_decoded_inputs_remain_reserved_beside_cached_proving(self):
        profiles = [self.witness_profile(), json.loads(Path(__file__).with_name(
            'block-v2-multi-gpu-direct-readback-workload.json').read_text())]
        for profile in profiles:
            with self.subTest(witness=R.gpu_witness(profile)):
                witness = R.witness_reservation(profile)
                total = R.extra_host_reserve(profile)
                with patch.object(R, 'WORKER_INPUT_HOST_BYTES', 0):
                    self.assertEqual(total - R.extra_host_reserve(profile), 64 * R.MIB)
                    self.assertEqual(R.witness_reservation(profile), witness)
        profile = profiles[1]
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        profile['phases'] = [dict(name='decoded-input-overlap',
            heap_bytes=budget['host']['worker_bytes'] - R.extra_host_reserve(profile),
            pinned_bytes=0, driver_host_bytes=0, resident_spill_bytes=0,
            managed_gpu_bytes=0, max_gpu_allocation_bytes=0, spill_payloads=[])]
        self.assertTrue(R.workload_fits(budget, profile))
        profile['phases'][0]['heap_bytes'] += 1
        self.assertTrue(any('host RAM' in failure for failure in R.workload_failures(budget, profile)))
        with patch.object(R, 'WORKER_INPUT_HOST_BYTES', 0):
            self.assertTrue(R.workload_fits(budget, profile))

    def transcript_profile(self):
        profile = self.randomness_profile()
        profile['geometry']['gpu_transcript'] = True
        return profile

    def test_transcript_reservation_matches_rust_and_is_additive(self):
        profile = self.transcript_profile()
        reserve = R.transcript_reservation(profile)
        self.assertEqual(reserve, dict(managed_bytes=723272,
                         max_allocation_bytes=524288, host_bytes=1048576))
        baseline = copy.deepcopy(profile)
        baseline['geometry']['gpu_transcript'] = False
        self.assertEqual(R.extra_host_reserve(profile) - R.extra_host_reserve(baseline), R.MIB)

        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        self.assertTrue(budget['gpu_transcript'])
        self.assertEqual(budget['transcript_bounds'], R.transcript_bounds(profile))
        self.assertEqual(budget['transcript_reservation'], reserve)
        total = sum(budget[key]['managed_bytes'] for key in
                    ('owned_quotient_reservation', 'witness_reservation',
                     'randomness_reservation', 'transcript_reservation'))
        budget['gpu']['managed_bytes'] = total - 1
        self.assertTrue(any('managed VRAM' in error for error in R.workload_failures(budget, profile)))
        # Lower-bound admission is also enforced at worker launch.
        with self.assertRaisesRegex(ValueError, 'simultaneous GPU transcript'):
            R.validate_transcript_assignment(budget, True)
        budget['gpu']['managed_bytes'] = total
        R.validate_transcript_assignment(budget, True)

    def test_transcript_mode_overrides_inherited_environment_and_defaults_off(self):
        profile = self.transcript_profile()
        for selected in (True, False):
            profile['geometry']['gpu_transcript'] = selected
            budget = R.plan(host(), [device()], 1, profile)['GPU-a']
            budget['unit'] = 'lattica-transcript-test.service'
            with patch.dict('os.environ', {'LATTICA_V2_GPU_TRANSCRIPT': str(int(not selected))}):
                self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_TRANSCRIPT'],
                                 str(int(selected)))
        budget.pop('gpu_transcript')
        budget.pop('transcript_bounds')
        budget.pop('transcript_reservation')
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_TRANSCRIPT'], '0')
        R.validate_transcript_assignment({}, False)
        with self.assertRaises(ValueError):
            R.validate_transcript_assignment(budget, True)

    def test_transcript_rejects_every_changed_bound_and_reservation(self):
        budget = R.plan(host(), [device()], 1, self.transcript_profile())['GPU-a']
        budget['unit'] = 'lattica-transcript-test.service'
        for parent in ('transcript_bounds', 'transcript_reservation'):
            for key in budget[parent]:
                for value in (None, False, 0, 1 << 64, budget[parent][key] + 1):
                    bad = copy.deepcopy(budget)
                    bad[parent][key] = value
                    with self.subTest(parent=parent, key=key, value=value), self.assertRaises(ValueError):
                        S.environment(bad, Path('/tmp/test'))
            for replacement in (None, {}, dict(budget[parent], extra=1)):
                bad = copy.deepcopy(budget)
                bad[parent] = replacement
                with self.assertRaises(ValueError):
                    R.validate_transcript_assignment(bad, True)

    def test_transcript_rejects_incomplete_pipeline_and_invalid_modes(self):
        profile = self.transcript_profile()
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        for key in ('gpu_randomness', 'gpu_witness', 'gpu_pcs_device_only',
                    'gpu_lookup', 'gpu_fri_resident', 'gpu_opening_eval',
                    'gpu_quotient_resident', 'gpu_quotient_eval'):
            bad = copy.deepcopy(profile)
            bad['geometry'][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                R.plan(host(), [device()], 1, bad)
            with self.assertRaises(ValueError):
                R.validate_transcript_assignment(dict(budget, **{key: False}), True)
        for value in (None, 1, '1', [], {}):
            bad = copy.deepcopy(profile)
            bad['geometry']['gpu_transcript'] = value
            with self.assertRaises(ValueError):
                R.plan(host(), [device()], 1, bad)
            with self.assertRaises(ValueError):
                R.validate_transcript_assignment(dict(budget, gpu_transcript=value), True)
        with self.assertRaises(ValueError):
            R.validate_transcript_assignment(budget, False)

    def test_transcript_rejects_host_allocation_shortfalls_and_u64_overflow(self):
        budget = R.plan(host(), [device()], 1, self.transcript_profile())['GPU-a']
        host_total = sum(budget[key]['host_bytes'] for key in
                         ('witness_reservation', 'randomness_reservation', 'transcript_reservation'))
        for parent, key, amount in (
                ('host', 'worker_bytes', host_total - 1),
                ('gpu', 'max_allocation_bytes', budget['transcript_reservation']['max_allocation_bytes'] - 1),
                ('gpu', 'managed_bytes', 1 << 64),
                ('host', 'worker_bytes', 1 << 64)):
            bad = copy.deepcopy(budget)
            bad[parent][key] = amount
            with self.subTest(parent=parent, key=key), self.assertRaises(ValueError):
                R.validate_transcript_assignment(bad, True)
        bad = copy.deepcopy(budget)
        bad['gpu']['managed_bytes'] = (1 << 64) - 1
        bad['owned_quotient_reservation']['managed_bytes'] = ((1 << 64) - 1
            - bad['witness_reservation']['managed_bytes'] - bad['randomness_reservation']['managed_bytes'])
        with self.assertRaisesRegex(ValueError, 'overflow'):
            R.validate_transcript_assignment(bad, True)

    def randomness_profile(self):
        profile = self.witness_profile()
        profile['geometry'].update(gpu_randomness=True, quotient_matrices=16)
        return profile

    def test_randomness_reservation_matches_rust_and_keeps_cached_salts_live(self):
        profile = self.randomness_profile()
        bounds = R.randomness_bounds(profile)
        self.assertEqual(bounds, dict(rows=16, main_columns=98, preprocessing_columns=200,
                                     lookup_columns=55, quotient_rows=256, quotient_chunks=16))
        self.assertEqual(R.randomness_reservation(profile),
                         dict(managed_bytes=71144, max_allocation_bytes=16448, host_bytes=1048576))
        self.assertEqual(R.randomness_reservation_for_bounds(bounds, 3)['managed_bytes'], 103912)
        large = dict(rows=16384, main_columns=94, preprocessing_columns=200,
                     lookup_columns=60, quotient_rows=262144, quotient_chunks=16)
        self.assertEqual(R.randomness_reservation_for_bounds(large, 12),
                         dict(managed_bytes=248709352, max_allocation_bytes=16777216, host_bytes=1048576))
        baseline = copy.deepcopy(profile)
        baseline['geometry']['gpu_randomness'] = False
        removed = (R.lookup_random_sample_bytes(profile)
                   + R.opening_geometry(profile)[3] * 16 * 32)
        self.assertEqual(R.extra_host_reserve(profile) - R.extra_host_reserve(baseline),
                         R.MIB - removed)

    def test_device_randomness_removes_host_samples_without_shrinking_gpu_allocations(self):
        profile = self.randomness_profile()
        # Make the lookup samples large enough to affect the device plan.
        profile['geometry'].update(permutation_trace_columns_upper_bound=4092,
                                   permutation_columns_upper_bound=4096)
        baseline = copy.deepcopy(profile)
        baseline['geometry']['gpu_randomness'] = False
        samples = R.lookup_random_sample_bytes(profile)
        self.assertGreater(samples, 0)
        self.assertEqual(R.lookup_random_host_reserve(baseline), samples)
        self.assertEqual(R.lookup_random_host_reserve(profile), 0)
        self.assertEqual(R.owned_quotient_reservation(profile),
                         R.owned_quotient_reservation(baseline))
        self.assertGreaterEqual(R.owned_quotient_reservation(profile)['max_allocation_bytes'], samples)
        self.assertEqual(R.fri_resident_host_reserve(profile),
                         R.MIB + R.pcs_query_host_reserve(profile))
        self.assertEqual(R.fri_resident_host_reserve(baseline),
                         R.opening_geometry(profile)[3] * 16 * 32
                         + R.MIB + R.pcs_query_host_reserve(profile))
        # Dropping a host transfer must not bypass geometry or selection checks.
        for key, value in [('degree_prefix_rows', 3),
                           ('permutation_columns_upper_bound', 0), ('gpu_randomness', '1')]:
            bad = copy.deepcopy(profile)
            bad['geometry'][key] = value
            with self.assertRaises(ValueError):
                R.lookup_random_host_reserve(bad)

    def test_resident_openings_reserve_claims_but_no_host_fri_vectors(self):
        profile = self.randomness_profile()
        prefix, quotient, chunks, _, _, claims = R.opening_geometry(profile)
        self.assertEqual(R.opening_host_reserve(profile), 2 * claims + R.MIB)
        # Residency, not the RNG backend, determines whether FRI vectors are
        # downloaded. Mixed GPU/CPU paths must keep their actual transfers.
        profile['geometry']['gpu_randomness'] = False
        self.assertEqual(R.opening_host_reserve(profile), 2 * claims + R.MIB)
        profile['geometry']['gpu_fri_resident'] = False
        heights = {prefix * 16, 2 * quotient // chunks * 16}
        self.assertEqual(R.opening_host_reserve(profile),
                         2 * (sum(heights) * 24 + claims) + R.MIB)

    def test_randomness_mode_is_assigned_and_overrides_inherited_environment(self):
        profile = self.randomness_profile()
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-randomness-test.service'
        with patch.dict('os.environ', {'LATTICA_V2_GPU_RANDOMNESS': '0'}):
            self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_RANDOMNESS'], '1')
        profile['geometry']['gpu_randomness'] = False
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-randomness-test.service'
        with patch.dict('os.environ', {'LATTICA_V2_GPU_RANDOMNESS': '1'}):
            self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_RANDOMNESS'], '0')

    def test_randomness_rejects_aggregate_oversubscription_and_assignment_tampering(self):
        profile = self.randomness_profile()
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-randomness-test.service'
        total = sum(budget[key]['managed_bytes'] for key in
                    ('owned_quotient_reservation', 'witness_reservation', 'randomness_reservation'))
        bad = copy.deepcopy(budget)
        bad['gpu']['managed_bytes'] = total - 1
        with self.assertRaisesRegex(ValueError, 'simultaneous'):
            S.environment(bad, Path('/tmp/test'))
        self.assertTrue(any('managed VRAM' in error for error in R.workload_failures(bad, profile)))
        bad = copy.deepcopy(budget)
        bad['host']['worker_bytes'] = (bad['witness_reservation']['host_bytes']
                                      + bad['randomness_reservation']['host_bytes'] - 1)
        with self.assertRaisesRegex(ValueError, 'simultaneous'):
            S.environment(bad, Path('/tmp/test'))
        for key in ('gpu_witness', 'gpu_pcs_device_only', 'gpu_lookup', 'gpu_fri_resident'):
            bad = copy.deepcopy(budget)
            bad[key] = False
            with self.assertRaises(ValueError):
                S.environment(bad, Path('/tmp/test'))
        for key in ('managed_bytes', 'host_bytes', 'max_allocation_bytes'):
            bad = copy.deepcopy(budget)
            bad['randomness_reservation'][key] -= 1
            with self.assertRaises(ValueError):
                S.environment(bad, Path('/tmp/test'))
        bad = copy.deepcopy(budget)
        bad['randomness_bounds']['rows'] //= 2
        with self.assertRaises(ValueError):
            S.environment(bad, Path('/tmp/test'))

    def test_randomness_rejects_unsupported_geometry_and_modes(self):
        profile = self.randomness_profile()
        bounds = R.randomness_bounds(profile)
        for key in bounds:
            for value in (None, True, -1, 1 << 64):
                bad = dict(bounds, **{key: value})
                with self.assertRaises(ValueError):
                    R.randomness_reservation_for_bounds(bad)
        for cache in (0, True, 13):
            with self.assertRaises(ValueError):
                R.randomness_reservation_for_bounds(bounds, cache)
        for value in (None, 1, '1'):
            bad = copy.deepcopy(profile)
            bad['geometry']['gpu_randomness'] = value
            with self.assertRaises(ValueError):
                R.randomness_reservation(bad)
        bad = copy.deepcopy(profile)
        bad['witness_bounds']['rows'] = 32
        with self.assertRaises(ValueError):
            R.randomness_reservation(bad)

    def witness_profile(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        profile['height'] = 16
        profile['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                gpu_lookup=True, gpu_opening_eval=True, gpu_fri_resident=True,
                gpu_pcs_device_only=True, gpu_witness=True, degree_prefix_rows=32,
                retained_quotient_rows=256, main_trace_columns=98, main_columns=102,
                preprocessing_columns=200, permutation_trace_columns_upper_bound=55,
                permutation_columns_upper_bound=59)
        profile['witness_bounds'] = dict(rows=16, main_columns=98, preprocessing_columns=200,
                metadata_bytes=65536, compiler_host_bytes=262144,
                program_host_bytes=1048576, wires=4096, input_values=64)
        return profile

    def test_gpu_geometry_separates_raw_witness_and_committed_columns(self):
        profile = self.randomness_profile()
        profile['height'] = 262144
        profile['geometry'].update(degree_prefix_rows=524288, retained_quotient_rows=4194304,
                main_trace_columns=94, main_columns=98, permutation_trace_columns_upper_bound=51,
                permutation_columns_upper_bound=55)
        profile['witness_bounds'].update(rows=262144, main_columns=94,
                metadata_bytes=311642160, compiler_host_bytes=368417296,
                program_host_bytes=571816240, wires=1840284, input_values=211106)
        self.assertEqual(R.trace_columns(profile), [94, 200, 51])
        prefix, _, _, _, committed, claims = R.opening_geometry(profile)
        self.assertEqual(committed, [98, 200, 55])
        # Matches native LDE plans from the full-size finalizer: hiding adds
        # 16 MiB to the main capture and 16 MiB to the permutation capture.
        self.assertEqual([prefix * n * 8 for n in committed],
                         [411041792, 838860800, 230686720])
        self.assertEqual(claims, 362496)
        self.assertEqual(R.randomness_bounds(profile), dict(rows=262144, main_columns=94,
                preprocessing_columns=200, lookup_columns=51, quotient_rows=4194304, quotient_chunks=16))
        self.assertEqual(R.lookup_random_sample_bytes(profile), 123731968)
        self.assertEqual(R.witness_reservation(profile),
                         R.witness_reservation_for_bounds(profile['witness_bounds']))
        # A larger allocation bound must neither masquerade as actual trace
        # geometry nor lose its allowance when deriving RNG assignments.
        owned = R.owned_quotient_reservation(profile)
        profile['witness_bounds'].update(main_columns=100, preprocessing_columns=208)
        self.assertEqual(R.trace_columns(profile), [94, 200, 51])
        self.assertEqual(R.opening_geometry(profile)[4], committed)
        self.assertEqual(R.owned_quotient_reservation(profile), owned)
        self.assertEqual(R.randomness_bounds(profile)['main_columns'], 100)
        self.assertEqual(R.randomness_bounds(profile)['preprocessing_columns'], 208)

    def test_gpu_witness_rejects_ambiguous_or_inconsistent_raw_geometry(self):
        profile = self.randomness_profile()
        readers = (R.witness_reservation, R.randomness_reservation, R.owned_quotient_reservation,
                   R.opening_geometry, R.lookup_random_sample_bytes,
                   lambda p: R.plan(host(), [device()], 1, p))
        for key in ('main_trace_columns', 'permutation_trace_columns_upper_bound'):
            for value in (None, True, -1, 4097, '94'):
                bad = copy.deepcopy(profile)
                bad['geometry'][key] = value
                for reader in readers:
                    with self.subTest(key=key, value=value, reader=reader), self.assertRaisesRegex(ValueError, 'raw trace'):
                        reader(bad)
            bad = copy.deepcopy(profile)
            bad['geometry'].pop(key)
            for reader in readers:
                with self.subTest(key=key, reader=reader), self.assertRaisesRegex(ValueError, 'raw trace'):
                    reader(bad)
        for key, value in (('main_trace_columns', 94), ('main_trace_columns', 0),
                           ('permutation_trace_columns_upper_bound', 51),
                           ('main_columns', 98), ('permutation_columns_upper_bound', 55),
                           ('main_columns', 103), ('permutation_columns_upper_bound', 60)):
            bad = copy.deepcopy(profile)
            bad['geometry'][key] = value
            for reader in readers:
                with self.subTest(key=key, value=value, reader=reader), self.assertRaises(ValueError):
                    reader(bad)

    def test_explicit_empty_lookup_and_legacy_geometry_remain_distinct(self):
        profile = self.randomness_profile()
        profile['geometry'].update(permutation_trace_columns_upper_bound=0, permutation_columns_upper_bound=0)
        self.assertEqual(R.opening_geometry(profile)[4][2], 0)
        self.assertEqual(R.randomness_bounds(profile)['lookup_columns'], 0)
        # Match the Rust resource upper bound even when no lookup is drawn.
        self.assertEqual(R.lookup_random_sample_bytes(profile), 16 * 8 * 8)
        legacy = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        self.assertIsNone(R.trace_columns(legacy))
        self.assertEqual(R.opening_geometry(legacy)[4], [98, 200, 55])
        legacy['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True, gpu_lookup=True)
        self.assertEqual(R.lookup_random_sample_bytes(legacy), 262144 * (55 + 8) * 8)
        # Supplying only half of the new geometry must not silently select
        # legacy semantics, even when GPU witness construction is disabled.
        legacy['geometry']['main_trace_columns'] = 94
        with self.assertRaisesRegex(ValueError, 'raw trace'):
            R.opening_geometry(legacy)

    def test_witness_reservation_matches_rust_and_accounts_for_cache_and_staging(self):
        profile = self.witness_profile()
        # Shared arithmetic fixture in gpu_backend/resources.rs tests.
        self.assertEqual(R.witness_reservation(profile),
                         dict(managed_bytes=144168, max_allocation_bytes=65536, host_bytes=(3409416 + (192 + 257 + 64 + 2 + 72) * R.MIB + 16 * 1024)))
        cached = R.witness_reservation_for_bounds(profile['witness_bounds'], 3)
        self.assertEqual(cached['managed_bytes'], 144168 + 2 * 65536)
        self.assertEqual(cached['host_bytes'], (3409416 + (192 + 257 + 64 + 2 + 72) * R.MIB + 16 * 1024) + 2 * (1048576 + 262144 - 65536 + 65 * R.MIB + 16 * 1024))
        baseline = copy.deepcopy(profile)
        baseline['geometry']['gpu_witness'] = False
        self.assertEqual(R.extra_host_reserve(profile) - R.extra_host_reserve(baseline), (3409416 + (192 + 257 + 64 + 2 + 72) * R.MIB + 16 * 1024))
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-witness-test.service'
        with patch.dict('os.environ', {'LATTICA_V2_GPU_WITNESS': '0'}):
            self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_WITNESS'], '1')
        disabled = R.plan(host(), [device()], 1, baseline)['GPU-a']
        disabled['unit'] = budget['unit']
        with patch.dict('os.environ', {'LATTICA_V2_GPU_WITNESS': '1'}):
            self.assertEqual(S.environment(disabled, Path('/tmp/test'))['LATTICA_V2_GPU_WITNESS'], '0')

    def test_cached_pcs_distinguishes_host_salts_from_device_handles(self):
        historical = self.witness_profile()['witness_bounds']
        device = dict(historical, pcs_retained_host_bytes=R.MIB)
        for entries in [1, 3, 12]:
            old = R.witness_reservation_for_bounds(historical, entries)
            new = R.witness_reservation_for_bounds(device, entries)
            self.assertEqual(old['host_bytes'] - new['host_bytes'], entries * historical['rows'] * 1024)
            self.assertEqual(old['managed_bytes'], new['managed_bytes'])
            self.assertEqual(old['max_allocation_bytes'], new['max_allocation_bytes'])
            self.assertEqual(old, R.witness_reservation_for_bounds(dict(historical, pcs_retained_host_bytes=0), entries))
        for bad in [True, -1, 1, R.MIB - 1, R.MIB + historical['rows'] * 1024 + 1, (1 << 64) - 1]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                R.witness_reservation_for_bounds(dict(historical, pcs_retained_host_bytes=bad))

    def test_cached_lookup_graphs_overlap_incoming_source_and_verifier(self):
        bounds = dict(self.witness_profile()['witness_bounds'],
                      program_retained_host_bytes=262144, compiler_retained_host_bytes=8192)
        one = R.witness_reservation_for_bounds(bounds)
        for entries in [1, 3, 12]:
            with self.subTest(entries=entries):
                reserve = R.witness_reservation_for_bounds(bounds, entries)
                self.assertEqual(reserve['host_bytes'] - one['host_bytes'],
                                 (entries - 1) * (262144 + 8192 + 65 * R.MIB + 16 * 1024))
                incoming = dict(bounds, program_host_bytes=bounds['program_host_bytes'] + R.MIB)
                self.assertEqual(R.witness_reservation_for_bounds(incoming, entries)['host_bytes']
                                 - reserve['host_bytes'], R.MIB)
                self.assertGreaterEqual(reserve['host_bytes'],
                                        (entries * 64 + 192 + 257) * R.MIB + bounds['program_host_bytes'])

    def test_full_size_witness_host_bound_keeps_cache_and_incoming_source_live(self):
        # Shared full-size merge fixture in gpu_backend/resources.rs. The
        # device allocation is unchanged when its uploaded host copy expires.
        bounds = dict(rows=262144, main_columns=94, preprocessing_columns=200,
                      metadata_bytes=621708376, compiler_host_bytes=734973680,
                      program_host_bytes=1142607740, wires=3669207, input_values=419117)
        one = R.witness_reservation_for_bounds(bounds)
        self.assertEqual(one, dict(managed_bytes=1041171584,
                         max_allocation_bytes=621708376, host_bytes=2610980304 + (257 + 64 + 257 + 1 + 72) * R.MIB))
        larger = dict(bounds, program_host_bytes=bounds['program_host_bytes'] + R.MIB)
        self.assertEqual(R.witness_reservation_for_bounds(larger)['host_bytes'],
                         one['host_bytes'] + 2 * R.MIB)
        cached = R.witness_reservation_for_bounds(bounds, 3)
        self.assertEqual(cached['host_bytes'] - one['host_bytes'],
                         2 * (bounds['program_host_bytes'] + bounds['compiler_host_bytes']
                              - bounds['metadata_bytes'] + (64 + 257) * R.MIB))
        self.assertEqual(cached['managed_bytes'] - one['managed_bytes'],
                         2 * bounds['metadata_bytes'])

    def test_retained_source_is_cached_and_construction_peak_is_transient(self):
        historical = self.witness_profile()['witness_bounds']
        precise = dict(historical, program_retained_host_bytes=1 << 18)
        for entries in [1, 3, 12]:
            old = R.witness_reservation_for_bounds(historical, entries)
            new = R.witness_reservation_for_bounds(precise, entries)
            self.assertEqual(new['managed_bytes'], old['managed_bytes'])
            self.assertEqual(new['max_allocation_bytes'], old['max_allocation_bytes'])
            self.assertEqual(old['host_bytes'] - new['host_bytes'], entries * (3 << 18))
            higher_peak = dict(precise, program_host_bytes=2 << 20)
            self.assertEqual(R.witness_reservation_for_bounds(higher_peak, entries)['host_bytes']
                             - new['host_bytes'], R.MIB)
            higher_retained = dict(precise, program_retained_host_bytes=(1 << 18) + 4096)
            self.assertEqual(R.witness_reservation_for_bounds(higher_retained, entries)['host_bytes']
                             - new['host_bytes'], entries * 4096)
            self.assertEqual(R.witness_reservation_for_bounds(dict(historical, program_retained_host_bytes=0), entries), old)

    def test_retained_source_rejects_bad_capacity_and_preserves_worker_assignment(self):
        profile = self.witness_profile()
        bounds = profile['witness_bounds']
        for value in [None, True, -1, 1.5, '1', bounds['program_host_bytes'] + 1, 1 << 64]:
            with self.assertRaises(ValueError):
                R.witness_reservation_for_bounds(dict(bounds, program_retained_host_bytes=value))
        bounds['program_retained_host_bytes'] = 1 << 18
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        self.assertEqual(budget['witness_bounds'], bounds)
        self.assertEqual(budget['witness_reservation'], R.witness_reservation_for_bounds(bounds))
        budget['unit'] = 'lattica-retained-source-test.service'
        self.assertIn('LATTICA_V2_WORKER_BUDGET', S.environment(budget, Path('/tmp/test')))

    def test_schedule_cache_bound_keeps_compiler_workspace_transient(self):
        historical = dict(self.witness_profile()['witness_bounds'], program_host_bytes=1 << 16)
        precise = dict(historical, compiler_retained_host_bytes=8192)
        for entries in [1, 3, 12]:
            old = R.witness_reservation_for_bounds(historical, entries)
            new = R.witness_reservation_for_bounds(precise, entries)
            self.assertEqual(old['host_bytes'] - new['host_bytes'], entries * (196608 - 8192))
            self.assertEqual(old['managed_bytes'], new['managed_bytes'])
            self.assertEqual(old['max_allocation_bytes'], new['max_allocation_bytes'])
            larger_peak = dict(precise, compiler_host_bytes=precise['compiler_host_bytes'] + R.MIB)
            self.assertEqual(R.witness_reservation_for_bounds(larger_peak, entries)['host_bytes'] - new['host_bytes'], R.MIB)
            larger_schedule = dict(precise, compiler_retained_host_bytes=8320)
            self.assertEqual(R.witness_reservation_for_bounds(larger_schedule, entries)['host_bytes'] - new['host_bytes'], entries * 128)
            self.assertEqual(R.witness_reservation_for_bounds(dict(historical, compiler_retained_host_bytes=0), entries), old)

    def test_schedule_bound_rejects_bad_capacity_and_preserves_both_retained_components(self):
        profile = self.witness_profile()
        bounds = profile['witness_bounds']
        for invalid in [None, True, -1, 1.5, '1', 196609, 1 << 64]:
            with self.assertRaises(ValueError):
                R.witness_reservation_for_bounds(dict(bounds, compiler_retained_host_bytes=invalid))
        bounds.update(program_retained_host_bytes=1 << 18, compiler_retained_host_bytes=8192)
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        self.assertEqual(budget['witness_bounds'], bounds)
        self.assertEqual(budget['witness_reservation'], R.witness_reservation_for_bounds(bounds))
        budget['unit'] = 'lattica-schedule-storage-test.service'
        self.assertIn('LATTICA_V2_WORKER_BUDGET', S.environment(budget, Path('/tmp/test')))

    def test_witness_requires_exact_bounded_metadata_and_pipeline(self):
        profile = self.witness_profile()
        for field in profile['witness_bounds']:
            for bad in [None, True, -1, 1 << 64]:
                changed = copy.deepcopy(profile)
                changed['witness_bounds'][field] = bad
                with self.assertRaises(ValueError): R.plan(host(), [device()], 1, changed)
        for key in ['gpu_witness', 'gpu_pcs_device_only', 'gpu_lookup', 'gpu_fri_resident']:
            changed = copy.deepcopy(profile)
            changed['geometry'][key] = '1'
            with self.assertRaises(ValueError): R.plan(host(), [device()], 1, changed)
        for key in ['gpu_pcs_device_only', 'gpu_lookup', 'gpu_fri_resident', 'gpu_opening_eval', 'gpu_quotient_resident', 'gpu_quotient_eval']:
            changed = copy.deepcopy(profile)
            changed['geometry'][key] = False
            with self.assertRaises(ValueError): R.plan(host(), [device()], 1, changed)
        for key, bad in [('rows', 8), ('main_columns', 1), ('preprocessing_columns', 1)]:
            changed = copy.deepcopy(profile)
            changed['witness_bounds'][key] = bad
            with self.assertRaisesRegex(ValueError, 'workload geometry'): R.plan(host(), [device()], 1, changed)
        for bad in [None, {}, dict(profile['witness_bounds'], extra=1)]:
            changed = dict(profile, witness_bounds=bad)
            with self.assertRaisesRegex(ValueError, 'witness resource bounds'): R.plan(host(), [device()], 1, changed)
        for key in ['metadata_bytes', 'compiler_host_bytes', 'program_host_bytes']:
            changed = dict(profile['witness_bounds'], **{key: (1 << 64) - 8})
            with self.assertRaises(ValueError): R.witness_reservation_for_bounds(changed, 12)

    def test_witness_launch_rejects_changed_or_missing_reservations(self):
        budget = R.plan(host(), [device()], 1, self.witness_profile())['GPU-a']
        budget['unit'] = 'lattica-witness-test.service'
        for key in ['witness_bounds', 'witness_reservation', 'owned_quotient_reservation']:
            changed = copy.deepcopy(budget)
            changed.pop(key)
            with self.assertRaises(ValueError): S.environment(changed, Path('/tmp/test'))
        for key in ['managed_bytes', 'max_allocation_bytes', 'host_bytes']:
            changed = copy.deepcopy(budget)
            changed['witness_reservation'][key] -= 1
            with self.assertRaisesRegex(ValueError, 'witness buffers'): S.environment(changed, Path('/tmp/test'))
        for selected in [None, 1, '1']:
            with self.assertRaisesRegex(ValueError, 'witness construction'):
                S.environment(dict(budget, gpu_witness=selected), Path('/tmp/test'))

    def test_witness_adds_simultaneous_gpu_reservation_and_does_not_admit_full_workload(self):
        profile = self.witness_profile()
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        witness = R.witness_reservation(profile)
        base = max(p['managed_gpu_bytes'] for p in profile['phases']) + R.owned_quotient_reservation(profile)['managed_bytes']
        budget['gpu']['managed_bytes'] = base + witness['managed_bytes'] - 1
        self.assertTrue(any('managed VRAM' in e for e in R.workload_failures(budget, profile)))
        profile['geometry']['gpu_witness'] = False
        self.assertFalse(any('managed VRAM' in e for e in R.workload_failures(budget, profile)))
        profile['height'] = 262144
        profile['geometry'].update(gpu_witness=True, degree_prefix_rows=524288, retained_quotient_rows=4194304)
        profile['witness_bounds'].update(rows=262144, metadata_bytes=512 * R.MIB,
                compiler_host_bytes=R.GIB, program_host_bytes=2 * R.GIB, wires=1 << 24, input_values=1 << 20)
        with self.assertRaisesRegex(ValueError, 'managed VRAM'): R.plan(host(), [device()], 1, profile)

    def test_device_only_pcs_is_pinned_requires_consumers_and_keeps_reservations(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        geometry = profile['geometry']
        geometry.update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                        gpu_lookup=True, gpu_opening_eval=True, gpu_fri_resident=True,
                        degree_prefix_rows=32, retained_quotient_rows=256,
                        main_columns=10, preprocessing_columns=8, permutation_columns_upper_bound=13)
        host_before = R.extra_host_reserve(profile)
        device_before = R.owned_quotient_reservation(profile)
        for selected in [False, True]:
            geometry['gpu_pcs_device_only'] = selected
            self.assertEqual(R.extra_host_reserve(profile), host_before)
            self.assertEqual(R.owned_quotient_reservation(profile), device_before)
            budget = R.plan(host(), [device()], 1, profile)['GPU-a']
            budget['unit'] = 'lattica-device-pcs-test.service'
            with patch.dict('os.environ', {'LATTICA_V2_GPU_PCS_DEVICE_ONLY': str(int(not selected))}):
                self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_PCS_DEVICE_ONLY'],
                                 str(int(selected)))
        for invalid in ['1', 1, None]:
            geometry['gpu_pcs_device_only'] = invalid
            with self.assertRaisesRegex(ValueError, 'device-only GPU PCS'):
                R.plan(host(), [device()], 1, profile)
            with self.assertRaisesRegex(ValueError, 'device-only GPU PCS'):
                S.environment(dict(budget, gpu_pcs_device_only=invalid), Path('/tmp/test'))
        geometry['gpu_pcs_device_only'] = True
        for consumer in ['gpu_quotient_eval', 'gpu_quotient_resident', 'gpu_lookup',
                         'gpu_opening_eval', 'gpu_fri_resident']:
            missing = copy.deepcopy(profile)
            missing['geometry'][consumer] = False
            with self.assertRaises(ValueError):
                R.plan(host(), [device()], 1, missing)
            with self.assertRaises(ValueError):
                S.environment(dict(budget, **{consumer: False}), Path('/tmp/test'))

    def test_full_size_device_pcs_keeps_existing_aggregate_admission(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        profile['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                                   gpu_lookup=True, gpu_opening_eval=True, gpu_fri_resident=True)
        before = R.owned_quotient_reservation(profile)
        host_before = R.extra_host_reserve(profile)
        profile['geometry']['gpu_pcs_device_only'] = True
        self.assertEqual(R.owned_quotient_reservation(profile), before)
        self.assertEqual(R.extra_host_reserve(profile), host_before)
        with self.assertRaisesRegex(ValueError, 'managed VRAM'):
            R.plan(host(), [device()], 1, profile)

    def test_resident_fri_reserves_layers_salts_and_pins_selection(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        geometry = profile['geometry']
        geometry.update(gpu_quotient_eval=True, gpu_quotient_resident=True, gpu_opening_eval=True,
                        degree_prefix_rows=32, retained_quotient_rows=256,
                        main_columns=10, preprocessing_columns=8, permutation_columns_upper_bound=13)
        old = R.owned_quotient_reservation(profile)
        host_before = R.extra_host_reserve(profile)
        geometry['gpu_fri_resident'] = True
        self.assertEqual(R.extra_host_reserve(profile),
                         host_before - 2 * 32 * 16 * 24
                         + 32 * 16 * 32 + R.MIB + R.pcs_query_host_reserve(profile))
        self.assertGreater(R.owned_quotient_reservation(profile)['managed_bytes'], old['managed_bytes'])
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-resident-fri-test.service'
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_FRI_RESIDENT'], '1')
        for invalid in ['1', 1, None]:
            geometry['gpu_fri_resident'] = invalid
            with self.assertRaisesRegex(ValueError, 'resident GPU FRI'):
                R.plan(host(), [device()], 1, profile)
            budget['gpu_fri_resident'] = invalid
            with self.assertRaisesRegex(ValueError, 'resident GPU FRI'):
                S.environment(budget, Path('/tmp/test'))
        geometry['gpu_fri_resident'] = True
        geometry['gpu_opening_eval'] = False
        with self.assertRaisesRegex(ValueError, 'resident GPU FRI'):
            R.owned_quotient_reservation(profile)
        budget['gpu_fri_resident'] = True
        budget['gpu_opening_eval'] = False
        with self.assertRaisesRegex(ValueError, 'resident GPU FRI'):
            S.environment(budget, Path('/tmp/test'))

    def test_owned_pcs_queries_reserve_host_results_and_tiled_device_work(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        self.assertEqual(R.pcs_query_host_reserve(profile), 0)
        g = profile['geometry']
        g.update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                 gpu_opening_eval=True, gpu_fri_resident=True,
                 degree_prefix_rows=32, retained_quotient_rows=256,
                 main_columns=10, preprocessing_columns=8, permutation_columns_upper_bound=13)
        small = R.pcs_query_host_reserve(profile)
        self.assertGreater(small, 2 * 256 * sum([10, 8, 13]) * 8)
        g['main_columns'] = 4000
        self.assertGreater(R.pcs_query_host_reserve(profile), small)
        # Tall-domain scratch must account for at least two complete columns,
        # even when that minimum is larger than the preferred 64 MiB tile.
        g.update(degree_prefix_rows=1 << 20, retained_quotient_rows=1 << 23,
                 main_columns=1, preprocessing_columns=1, permutation_columns_upper_bound=1)
        reservation = R.owned_quotient_reservation(profile)
        degree = R.opening_geometry(profile)[3]
        self.assertGreaterEqual(reservation['managed_bytes'],
                                degree * 16 * 216 + 128 * R.MIB + degree * 16 * 16)

    def test_owned_openings_reserve_retained_prefixes_and_fri_boundary(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        geometry = profile['geometry']
        geometry.update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                        degree_prefix_rows=32, retained_quotient_rows=256,
                        main_columns=10, preprocessing_columns=8, permutation_columns_upper_bound=13)
        host_before = R.extra_host_reserve(profile)
        device_before = R.owned_quotient_reservation(profile)
        geometry['gpu_opening_eval'] = True
        self.assertGreater(R.extra_host_reserve(profile), host_before)
        self.assertGreater(R.owned_quotient_reservation(profile)['managed_bytes'], device_before['managed_bytes'])
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-v2-opening-test.service'
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_OPENING_EVAL'], '1')
        for invalid in ['1', 1, None]:
            budget['gpu_opening_eval'] = invalid
            with self.assertRaisesRegex(ValueError, 'opening evaluation'):
                S.environment(budget, Path('/tmp/test'))
            geometry['gpu_opening_eval'] = invalid
            with self.assertRaisesRegex(ValueError, 'opening evaluation'):
                R.plan(host(), [device()], 1, profile)
        geometry['gpu_opening_eval'] = True
        geometry['gpu_quotient_resident'] = False
        with self.assertRaisesRegex(ValueError, 'opening evaluation'):
            R.extra_host_reserve(profile)
        geometry['gpu_quotient_resident'] = True
        geometry['degree_prefix_rows'] = 1 << 22
        with self.assertRaisesRegex(ValueError, 'supported height'):
            R.opening_host_reserve(profile)
        geometry['degree_prefix_rows'] = 32
        geometry['main_columns'] = 4097
        with self.assertRaisesRegex(ValueError, 'column geometry'):
            R.opening_host_reserve(profile)

    def test_full_size_owned_opening_workload_remains_conservatively_rejected(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        profile['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                                   gpu_lookup=True, gpu_opening_eval=True)
        reserve = R.owned_quotient_reservation(profile)
        self.assertGreaterEqual(reserve['max_allocation_bytes'], 838860800)
        with self.assertRaisesRegex(ValueError, 'managed VRAM'):
            R.plan(host(), [device()], 1, profile)

    def test_lookup_selection_reserves_host_device_memory_and_is_pinned(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        geometry = profile['geometry']
        geometry.update(gpu_quotient_eval=True, gpu_quotient_resident=True,
                        degree_prefix_rows=32, retained_quotient_rows=256,
                        main_columns=10, preprocessing_columns=8, permutation_columns_upper_bound=13)
        baseline = R.extra_host_reserve(profile)
        previous = R.owned_quotient_reservation(profile)
        geometry['gpu_lookup'] = True
        expected_samples = 16 * (13 + 8) * 8
        self.assertEqual(R.extra_host_reserve(profile), baseline + expected_samples)
        reservation = R.owned_quotient_reservation(profile)
        self.assertGreaterEqual(reservation['managed_bytes'], previous['managed_bytes'])
        self.assertGreaterEqual(reservation['max_allocation_bytes'], expected_samples)
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-v2-lookup-test.service'
        self.assertTrue(budget['gpu_lookup'])
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_LOOKUP'], '1')
        budget['gpu_quotient_resident'] = False
        with self.assertRaisesRegex(ValueError, 'lookup'):
            S.environment(budget, Path('/tmp/test'))
        geometry['gpu_quotient_resident'] = False
        with self.assertRaisesRegex(ValueError, 'lookup'):
            R.extra_host_reserve(profile)
        geometry['gpu_quotient_resident'] = True
        for invalid in ['1', 1, None]:
            geometry['gpu_lookup'] = invalid
            with self.assertRaisesRegex(ValueError, 'lookup'):
                R.plan(host(), [device()], 1, profile)
        geometry['gpu_lookup'] = True
        geometry['degree_prefix_rows'] = 1
        with self.assertRaisesRegex(ValueError, 'lookup'):
            R.extra_host_reserve(profile)

    def test_owned_quotient_reserves_coset_buffers_and_rejects_aggregate_overcommit(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        profile['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True)
        reserved = R.owned_quotient_reservation(profile)
        self.assertEqual(reserved['max_allocation_bytes'], 838860800)
        self.assertLess(reserved['max_allocation_bytes'], device()['opencl']['max_allocation_bytes'])
        with self.assertRaisesRegex(ValueError, 'managed VRAM'):
            R.plan(host(), [device()], 1, profile)
        profile['geometry'].update(degree_prefix_rows=32, retained_quotient_rows=256,
                                   main_columns=10, preprocessing_columns=8,
                                   permutation_columns_upper_bound=7)
        reserved = R.owned_quotient_reservation(profile)
        self.assertGreater(reserved['managed_bytes'], 64 * R.MIB)
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-v2-owned-test.service'
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_QUOTIENT_RESIDENT'], '1')
        budget.pop('owned_quotient_reservation')
        with self.assertRaises(ValueError):
            S.environment(budget, Path('/tmp/test'))
        profile['geometry']['retained_quotient_rows'] = 32 * 512
        with self.assertRaisesRegex(ValueError, '256 cosets'):
            R.owned_quotient_reservation(profile)
        profile['geometry']['retained_quotient_rows'] = 256
        for chunks in [None, 1, 3, 32, True]:
            profile['geometry']['quotient_matrices'] = chunks
            with self.assertRaisesRegex(ValueError, 'equal chunks'):
                R.owned_quotient_reservation(profile)
        profile['geometry']['quotient_matrices'] = 16
        profile['geometry']['gpu_quotient_eval'] = False
        with self.assertRaises(ValueError):
            R.owned_quotient_reservation(profile)
        profile['geometry']['gpu_quotient_resident'] = '1'
        with self.assertRaises(ValueError):
            R.owned_quotient_reservation(profile)

    def test_owned_quotient_hiding_samples_are_reserved_when_wider_than_trace_inputs(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        profile['geometry'].update(gpu_quotient_eval=True, gpu_quotient_resident=True,
            degree_prefix_rows=1 << 18, retained_quotient_rows=1 << 22,
            main_columns=1, preprocessing_columns=0, permutation_columns_upper_bound=0)
        reservation = R.owned_quotient_reservation(profile)
        # Raw independent hiding masks exceed both the trace prefixes and the
        # cubic output; they must contribute to allocation and aggregate bounds.
        masks = (1 << 18) * 15 * 7 * 8
        self.assertGreaterEqual(reservation['max_allocation_bytes'], masks)
        self.assertGreaterEqual(reservation['managed_bytes'], masks + (1 << 22) * (3 + 4) * 8)

    def test_quotient_evaluation_is_explicit_and_reserves_host_staging(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        baseline = R.extra_host_reserve(profile)
        profile['geometry']['gpu_quotient_eval'] = True
        self.assertEqual(R.extra_host_reserve(profile), baseline + 256 * R.MIB)
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        budget['unit'] = 'lattica-v2-multi-test.service'
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_QUOTIENT_EVAL'], '1')
        profile['geometry']['gpu_quotient_eval'] = '1'
        with self.assertRaises(ValueError):
            R.extra_host_reserve(profile)
        budget['gpu_quotient_eval'] = '1'
        with self.assertRaises(ValueError):
            S.environment(budget, Path('/tmp/test'))

    def test_proving_policy_is_validated_and_frozen_in_worker_assignment(self):
        defaults = {'LATTICA_PROVING_POLICY': 'compatible', 'LATTICA_PROVING_REPORT': '0'}
        required = {'LATTICA_PROVING_POLICY': 'gpu-required', 'LATTICA_PROVING_REPORT': '1'}
        self.assertEqual(S.proving_environment({}), defaults)
        self.assertEqual(S.proving_environment(required), required)
        for key, values in [('LATTICA_PROVING_POLICY', ('gpu', '', None)),
                            ('LATTICA_PROVING_REPORT', ('yes', '', 1))]:
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    S.proving_environment({key: value})
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        budgets = R.plan(host(), [device()], 1, profile)
        budget = dict(budgets['GPU-a'], unit='lattica-v2-multi-test.service',
                      proving_environment=required)
        with patch.dict(S.os.environ, defaults):
            env = S.environment(budget, Path('/tmp/test'))
        self.assertEqual({name: env[name] for name in required}, required)

    def test_fri_and_preprocessing_reservations_survive_every_admission_check(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        budget = R.plan(host(), [device()], 1, profile)['GPU-a']
        profile['phases'] = [dict(name='boundary', heap_bytes=budget['host']['worker_bytes'] - R.WORKER_PROTOCOL_HOST_BYTES - R.WORKER_INPUT_HOST_BYTES,
            pinned_bytes=0, driver_host_bytes=0, resident_spill_bytes=0, managed_gpu_bytes=0,
            max_gpu_allocation_bytes=0, spill_payloads=[])]
        self.assertTrue(R.workload_fits(budget, profile))
        profile['geometry']['gpu_fri_fold'] = True
        self.assertTrue(any('host RAM' in failure for failure in R.workload_failures(budget, profile)))
        profile['phases'][0]['heap_bytes'] -= R.MIB
        self.assertTrue(R.workload_fits(budget, profile))
        profile['preprocessing_cache'] = {'entries': 2, 'reserve_bytes': R.GIB}
        self.assertFalse(R.workload_fits(budget, profile))
        profile['phases'][0]['heap_bytes'] -= R.GIB
        self.assertTrue(R.workload_fits(budget, profile))
        env = S.environment(dict(budget, gpu_fri_fold=True, unit='test.service'), Path('/tmp/test'))
        self.assertEqual(env['LATTICA_V2_GPU_FRI_FOLD'], '1')
        for invalid in (1, 'true', None):
            with self.assertRaises(ValueError):
                S.environment(dict(budget, gpu_fri_fold=invalid), Path('/tmp/test'))

    def test_pool_reserves_wallet_and_coordinator_before_weighted_workers(self):
        policy = {'wallet_threads': 4, 'wallet_bytes': 4 * R.GIB,
                  'coordinator_threads': 2, 'coordinator_bytes': 2 * R.GIB,
                  'weights': {'GPU-a': 2, 'GPU-b': 1}}
        budgets = R.shared_budgets(host(), ['GPU-b', 'GPU-a'], policy)
        a, b = budgets['GPU-a'], budgets['GPU-b']
        self.assertEqual(a['cpu']['rayon_threads'] + b['cpu']['rayon_threads'], 17)
        self.assertGreater(a['cpu']['rayon_threads'], b['cpu']['rayon_threads'])
        used = a['host']['worker_bytes'] + b['host']['worker_bytes'] + 6 * R.GIB
        self.assertLessEqual(used, a['host']['fleet_bytes'])
        self.assertEqual(a['wallet'], {'threads': 4, 'ram_bytes': 4 * R.GIB})
        for budget in budgets.values():
            self.assertLessEqual(budget['host']['spill_bytes'], budget['host']['worker_bytes'])
        policy['wallet_bytes'] = 128 * R.GIB
        with self.assertRaises(ValueError):
            R.shared_budgets(host(), ['GPU-a', 'GPU-b'], policy)

    def test_opening_denominator_cache_is_pinned_and_memory_bounded(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        cached = copy.deepcopy(profile)
        cached['geometry']['opening_denominator_cache'] = True
        self.assertNotEqual(S.profile_digest({'workload': profile}), S.profile_digest({'workload': cached}))
        control = R.plan(host(), [device()], 1, profile)['GPU-a']
        candidate = R.plan(host(), [device()], 1, cached)['GPU-a']
        for section in ('cpu', 'host', 'gpu'):
            self.assertEqual(control[section], candidate[section])
        for budget, expected in [(control, '0'), (candidate, '1')]:
            budget = dict(budget, unit='lattica-v2-multi-test.service')
            self.assertEqual(S.environment(budget, Path('/tmp/test'))[
                'LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE'], expected)
        cached['geometry']['opening_denominator_cache'] = 'true'
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            R.plan(host(), [device()], 1, cached)
        with self.assertRaisesRegex(ValueError, 'must be boolean'):
            S.environment(dict(candidate, opening_denominator_cache=1), Path('/tmp/test'))

    def test_query_gather_is_profile_bound_and_preserves_resource_reservations(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json').read_text())
        gathered = copy.deepcopy(profile)
        gathered['geometry']['query_readback_layout'] = 'gather'
        self.assertNotEqual(S.profile_digest({'workload': profile}), S.profile_digest({'workload': gathered}))
        controls = R.plan(host(), [device()], 1, profile)
        candidates = R.plan(host(), [device()], 1, gathered)
        for section in ('host', 'cpu', 'gpu'):
            self.assertEqual(controls['GPU-a'][section], candidates['GPU-a'][section])
        for budgets, expected in ((controls, '0'), (candidates, '1')):
            budget = dict(budgets['GPU-a'], unit='lattica-v2-multi-test.service')
            self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_QUERY_GATHER'], expected)
        gathered['geometry']['query_readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'query readback layout'):
            R.plan(host(), [device()], 1, gathered)
        budget = dict(candidates['GPU-a'], unit='lattica-v2-multi-test.service', query_readback_layout='typo')
        with self.assertRaisesRegex(ValueError, 'query readback layout'):
            S.environment(budget, Path('/tmp/test'))

    def test_direct_readback_admits_two_workers_without_relaxing_budgets(self):
        directory = Path(__file__).parent
        banded = json.loads((directory / 'block-v2-multi-gpu-workload.json').read_text())
        direct = json.loads((directory / 'block-v2-multi-gpu-direct-readback-workload.json').read_text())
        h = host()
        h['available_bytes'] = 43 * R.GIB
        devices = [device('GPU-a'), device('GPU-b')]
        calibrations = {d['uuid']: calibration(d['uuid']) for d in devices}
        with self.assertRaisesRegex(ValueError, 'host RAM|spill'):
            R.plan(h, devices, 2, banded, calibrations)
        budgets = R.plan(h, devices, 2, direct, calibrations)
        self.assertEqual(len(budgets), 2)
        unchanged = R.shared_budgets(h, ['GPU-a', 'GPU-b'])
        for uuid, b in budgets.items():
            self.assertEqual(b['host'], unchanged[uuid]['host'])
            self.assertEqual(b['cpu'], unchanged[uuid]['cpu'])
            self.assertEqual(b['readback_layout'], 'direct')
            self.assertEqual(R.workload_failures(b, direct), [])
            env = S.environment(dict(b, unit='lattica-v2-multi-test.service'), Path('/tmp/test'))
            self.assertEqual(env['LATTICA_V2_GPU_DIRECT_READBACK'], '1')
            self.assertEqual(env['LATTICA_SPILL_MAX_BYTES'], str(b['host']['spill_bytes']))
        for a, b in zip(banded['phases'], direct['phases']):
            self.assertEqual(a['heap_bytes'], b['heap_bytes'])
            self.assertEqual(a['driver_host_bytes'], b['driver_host_bytes'])
            self.assertEqual(a['managed_gpu_bytes'], b['managed_gpu_bytes'])

    def test_readback_layout_is_pinned_and_invalid_modes_fail_closed(self):
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-workload.json').read_text())
        reference = S.profile_digest({'workload': profile})
        profile['geometry']['host_readback_layout'] = 'direct'
        self.assertNotEqual(reference, S.profile_digest({'workload': profile}))
        profile['geometry']['host_readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'readback layout'):
            R.plan(host(), [device()], 1, profile)
        budget = {**R.shared_budgets(host(), ['GPU-a'])['GPU-a'],
                  'gpu': vars(R.gpu_budget(device())), 'unit': 'lattica-v2-multi-test.service'}
        self.assertEqual(S.environment(budget, Path('/tmp/test'))['LATTICA_V2_GPU_DIRECT_READBACK'], '0')
        budget['readback_layout'] = 'typo'
        with self.assertRaisesRegex(ValueError, 'readback layout'):
            S.environment(budget, Path('/tmp/test'))

    def test_heterogeneous_devices_never_share_vram(self):
        large = R.gpu_budget(device(), calibration())
        small = R.gpu_budget(device('GPU-b', 8 * R.GIB, 5 * R.GIB), calibration('GPU-b'))
        self.assertGreater(large.managed_bytes, small.managed_bytes)
        for b in (large, small):
            self.assertEqual(b.total_bytes, b.managed_bytes + b.context_bytes)
            self.assertLessEqual(b.total_bytes + b.headroom_bytes, b.available_bytes)
            self.assertEqual(b.managed_bytes % R.QUANTUM, 0)
            self.assertGreaterEqual(b.context_bytes * 4, 600 * R.MIB * 5)

    def test_bootstrap_uses_at_most_half_available_after_headroom(self):
        b = R.gpu_budget(device())
        self.assertTrue(b.bootstrap)
        self.assertLessEqual(b.managed_bytes * 2, b.available_bytes - b.headroom_bytes)

    def test_calibration_binding_and_low_gpu(self):
        c = calibration()
        c['driver'] = 'new'
        with self.assertRaises(ValueError):
            R.gpu_budget(device(), c)
        with self.assertRaises(ValueError):
            R.gpu_budget(device(free=512 * R.MIB))

    def test_cpu_budget_reserves_coordinator_and_orders_remainder_by_uuid(self):
        p = R.shared_budgets(host(), ['GPU-b', 'GPU-a'])
        self.assertEqual(p['GPU-a']['cpu']['rayon_threads'], 12)
        self.assertEqual(p['GPU-b']['cpu']['rayon_threads'], 11)
        self.assertEqual(p['GPU-a']['cpu']['allowed_cpus'], tuple(range(24)))

    def test_fractional_ancestor_quota_enforced(self):
        h = host()
        h['cpu_capacity'] = '7/2'
        p = R.shared_budgets(h, ['GPU-b', 'GPU-a'])
        self.assertEqual(p['GPU-a']['cpu']['rayon_threads'], 1)
        self.assertEqual(p['GPU-a']['cpu']['quota_percent'], '125%')
        h['cpu_capacity'] = '3/2'
        with self.assertRaises(ValueError):
            R.shared_budgets(h, ['GPU-a', 'GPU-b'])
        self.assertEqual(R.shared_budgets(h, ['GPU-a'])['GPU-a']['cpu']['quota_percent'], '150%')

    def test_worker_and_caller_ancestors_both_constrain_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            caller = root / 'session'
            parent = root / 'user' / 'lattica.slice'
            fleet = parent / 'lattica-v2-multi.slice'
            caller.mkdir()
            fleet.mkdir(parents=True)
            for path, values in [
                (root, {'cpu.max': '700000 100000', 'memory.max': str(64 * R.GIB),
                        'memory.current': str(R.GIB)}),
                (caller, {'cpuset.cpus.effective': '0-7', 'cpu.max': '600000 100000'}),
                (parent, {'cpuset.cpus.effective': '2-5', 'cpu.max': '350000 100000',
                          'memory.max': str(12 * R.GIB), 'memory.current': str(3 * R.GIB)}),
                (fleet, {'cpu.max': '250000 100000', 'memory.max': str(2 * R.GIB),
                         'memory.current': str(R.GIB)}),
            ]:
                for name, value in values.items():
                    (path / name).write_text(value)
            limits = R.cgroup_limits([caller, fleet], range(24), [fleet], root)
            self.assertEqual(limits['effective_cpus'], [2, 3, 4, 5])
            self.assertEqual(limits['cpu_capacity'], '5/2')
            self.assertEqual(limits['cgroup_memory_headroom'], 9 * R.GIB)
            rows = limits['ancestors']
            self.assertEqual(sum(row['path'] == str(root) for row in rows), 1)
            self.assertTrue(next(row for row in rows if row['path'] == str(fleet))
                            ['memory_limit_owned_by_controller'])
            # Without the explicit controller-owned exception, the fleet limit applies.
            self.assertEqual(R.cgroup_limits([fleet], range(24), root=root)
                             ['cgroup_memory_headroom'], R.GIB)

    def test_worker_inventory_uses_assigned_slice_instead_of_bounded_observer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            observer = root / 'observer.service'
            parent = root / 'user.slice'
            fleet = parent / 'fleet.slice'
            observer.mkdir()
            fleet.mkdir(parents=True)
            for path, values in [
                (root, {'cpu.max': '2400000 100000'}),
                (observer, {'cpu.max': '100000 100000', 'memory.max': str(2 * R.GIB),
                            'memory.current': str(R.GIB)}),
                (parent, {'cpu.max': '1200000 100000', 'memory.max': str(60 * R.GIB),
                          'memory.current': str(8 * R.GIB)}),
                (fleet, {'memory.max': str(40 * R.GIB), 'memory.current': str(R.GIB)}),
            ]:
                for name, value in values.items():
                    (path / name).write_text(value)
            original = R.cgroup_limits
            def limits(paths, cpus, ignored):
                return original(paths, cpus, ignored, root=root)
            filesystem = {'filesystems': [{'fstype': 'tmpfs', 'options': 'rw'}]}
            with patch.object(R, 'cgroup_path', return_value=observer), \
                 patch.object(R, 'cgroup_limits', side_effect=limits), \
                 patch.object(R.os, 'sched_getaffinity', return_value=set(range(24))), \
                 patch.object(R, 'command_json', return_value=filesystem):
                workers = R.detect_host(tmp, worker_cgroup=fleet)
                current = R.detect_host(tmp)
            self.assertEqual(workers['cpu_capacity'], '12')
            self.assertEqual(workers['cgroup_memory_headroom'], 52 * R.GIB)
            self.assertEqual(workers['resource_cgroup_scope'], 'assigned_workers')
            self.assertNotIn(str(observer), [group['path'] for group in workers['ancestors']])
            self.assertEqual(current['cpu_capacity'], '1')
            self.assertEqual(current['cgroup_memory_headroom'], R.GIB)
            self.assertEqual(current['resource_cgroup_scope'], 'current_process')

    def test_inactive_worker_slice_plan_still_observes_existing_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'cpu.max').write_text('150000 100000')
            missing = root / 'inactive.slice' / 'fleet.slice'
            limits = R.cgroup_limits([missing], range(24), root=root)
            self.assertEqual(limits['cpu_capacity'], '3/2')
            self.assertEqual(sum(row.get('present') is False for row in limits['ancestors']), 2)
        with patch.object(S, 'systemctl', return_value='/'), \
                patch.object(Path, 'is_dir', return_value=True):
            self.assertEqual(S.worker_cgroup(), Path('/sys/fs/cgroup/lattica.slice/lattica-v2.slice/lattica-v2-multi.slice'))
        with patch.object(S, 'systemctl', return_value=''):
            with self.assertRaises(ValueError):
                S.worker_cgroup()

    def test_host_adapts_to_cgroup_and_counts_tmpfs_in_ram(self):
        h = host()
        h['cgroup_memory_headroom'] = 12 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']['host']
        self.assertLessEqual(2 * b['worker_bytes'] + b['coordinator_bytes'], 12 * R.GIB)
        self.assertLessEqual(b['spill_bytes'], b['worker_bytes'])
        self.assertEqual(b['swap_bytes'], 0)
        h['available_bytes'] = R.GIB
        with self.assertRaises(ValueError):
            R.shared_budgets(h, ['GPU-a'])

    def test_spill_quota_and_mapping_headers_are_not_free(self):
        h = host()
        h['scratch']['quota_bytes'] = 2 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device()))
        self.assertEqual(b['host']['spill_bytes'], R.GIB)
        phase = dict(heap_bytes=0, pinned_bytes=0, driver_host_bytes=0, resident_spill_bytes=0,
                     spill_payloads=[R.GIB], managed_gpu_bytes=1, max_gpu_allocation_bytes=1)
        profile = {'version': 1, 'page_bytes': 4096, 'phases': [phase]}
        self.assertFalse(R.workload_fits(b, profile))
        phase['spill_payloads'] = [R.GIB - 4096]
        self.assertTrue(R.workload_fits(b, profile))
        phase['heap_bytes'] = b['host']['worker_bytes']
        self.assertFalse(R.workload_fits(b, profile))

    def test_qualification_uses_stricter_calculated_limits(self):
        h = host()
        h['scratch']['available_bytes'] = 32 * R.GIB
        b = R.shared_budgets(h, ['GPU-a', 'GPU-b'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device(), calibration()))
        profile = json.loads(Path(__file__).with_name('block-v2-multi-gpu-workload.json').read_text())
        q = R.qualification_budget(b, profile)
        self.assertLess(q['host']['worker_bytes'], b['host']['worker_bytes'])
        self.assertLess(q['gpu']['managed_bytes'], b['gpu']['managed_bytes'])
        self.assertEqual(q['cpu'], b['cpu'])
        self.assertTrue(R.workload_fits(q, profile))
        self.assertEqual(q['host']['worker_bytes'], 19 * R.GIB)

    def test_fallback_retains_specific_resource_failure(self):
        h = host()
        h['scratch']['quota_bytes'] = 2 * R.GIB
        phase = dict(name='commit', heap_bytes=0, pinned_bytes=0, driver_host_bytes=0,
                     resident_spill_bytes=0, spill_payloads=[R.GIB + 4096],
                     managed_gpu_bytes=1, max_gpu_allocation_bytes=1)
        config = {'max_concurrency': 2, 'jobs': [{}, {}],
                  'workload': {'version': 1, 'page_bytes': 4096, 'phases': [phase]}}
        devices = [device(), device('GPU-b')]
        failures = []
        budgets = S.choose_plan(config, h, devices, failures)
        self.assertEqual(len(budgets), 1)
        self.assertEqual(failures[0]['worker_slots'], 2)
        self.assertIn('commit: spill requires', failures[0]['reason'])
        config['worker_slots'] = 2
        with self.assertRaisesRegex(ValueError, 'commit: spill requires'):
            S.choose_plan(config, h, devices)

    def test_cpu_list_and_rounding(self):
        self.assertEqual(R.cpulist('0-3,8,10-11'), {0, 1, 2, 3, 8, 10, 11})
        with self.assertRaises(ValueError):
            R.cpulist('4-1')
        self.assertEqual(R.up(R.QUANTUM + 1), R.QUANTUM * 2)
        self.assertEqual(R.down(R.QUANTUM - 1), 0)

    def test_recovery_keeps_live_reservations_and_never_queues_retry(self):
        with tempfile.TemporaryDirectory() as d:
            a = {'unit': 'a', 'directory': d, 'status': 'running', 'reservation_released': False}
            ledger = {'attempts': [a], 'queued': []}
            S.reconcile(ledger, lambda _: {'ActiveState': 'active', 'ControlGroup': ''})
            self.assertEqual(a['status'], 'running')
            self.assertFalse(a['reservation_released'])
            S.reconcile(ledger, lambda _: {'ActiveState': 'failed', 'ControlGroup': ''})
            self.assertEqual(a['status'], 'interrupted')
            self.assertTrue(a['reservation_released'])
            self.assertEqual(ledger['queued'], [])

    def test_recovery_does_not_release_on_unknown_termination(self):
        a = {'unit': 'a', 'directory': '/missing', 'status': 'running', 'reservation_released': False}
        for state in ['activating', 'deactivating', 'active', 'reloading']:
            S.reconcile({'attempts': [a]}, lambda _: {'ActiveState': state})
            self.assertFalse(a['reservation_released'])

    def test_failed_service_or_missing_cpu_audit_cannot_count_as_success(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'result.json'
            path.write_text(json.dumps({'status': 'succeeded', 'cpu_audited': True}))
            state = {'Result': 'success', 'ExecMainStatus': '0'}
            self.assertTrue(S.attempt_succeeded(d, state))
            self.assertFalse(S.attempt_succeeded(d, {**state, 'Result': 'exit-code'}))
            self.assertFalse(S.attempt_succeeded(d, {**state, 'ExecMainStatus': '1'}))
            path.write_text(json.dumps({'status': 'succeeded', 'cpu_audited': False}))
            self.assertFalse(S.attempt_succeeded(d, state))

    def test_gpu_loss_stops_admissions_without_retry_and_preserves_uncertain_reservations(self):
        for exited in [False, True]:
            with tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / 'evidence'
                h = host()
                b = R.shared_budgets(h, ['GPU-a'])['GPU-a']
                b['gpu'] = R.asdict(R.gpu_budget(device()))
                config = {'scratch': tmp, 'max_concurrency': 1,
                          'jobs': [{'id': 'first'}, {'id': 'second'}]}
                state = {'ActiveState': 'failed' if exited else 'deactivating',
                         'ControlGroup': '', 'Result': 'signal', 'ExecMainStatus': '9'}
                def launched(config, job, budget, directory):
                    directory.mkdir()
                with patch.object(S, 'lock_fleet', return_value=[]), \
                     patch.object(S, 'verify_pins'), \
                     patch.object(S.R, 'detect_host', return_value=h), \
                     patch.object(S, 'worker_cgroup', return_value=Path('/sys/fs/cgroup/fleet.slice')), \
                     patch.object(S, 'selected_devices', return_value=[device()]), \
                     patch.object(S, 'choose_plan', return_value={'GPU-a': b}), \
                     patch.object(S, 'systemctl', return_value='[]'), \
                     patch.object(S, 'launch', side_effect=launched) as launch, \
                     patch.object(S, 'telemetry', side_effect=ValueError('GPU lost')), \
                     patch.object(S, 'unit_state', return_value=state), \
                     patch.object(S.subprocess, 'run'), \
                     patch.object(S.time, 'sleep'):
                    with self.assertRaisesRegex(ValueError, 'GPU lost'):
                        S.run(config, evidence)
                ledger = json.loads((evidence / 'ledger.json').read_text())
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(ledger['status'], 'failed')
                self.assertEqual(ledger['queued'], ['second'])
                self.assertEqual(len(ledger['attempts']), 1)
                self.assertEqual(ledger['attempts'][0]['reservation_released'], exited)

    def test_unqualified_concurrent_launch_refused(self):
        b = R.shared_budgets(host(), ['GPU-a'])['GPU-a']
        b['gpu'] = R.asdict(R.gpu_budget(device()))
        with self.assertRaises(ValueError):
            S.qualification_gate({'max_concurrency': 2}, {'GPU-a': b, 'GPU-b': b})

    def test_durable_assignment_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'budget.json'
            S.durable(path, {'version': 1}, True)
            with self.assertRaises(ValueError):
                S.durable(path, {'version': 2}, True)
            self.assertEqual(json.loads(path.read_text()), {'version': 1})


if __name__ == '__main__':
    unittest.main()
