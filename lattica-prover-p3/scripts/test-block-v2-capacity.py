#!/usr/bin/env python3
"""Block profile boundaries, cross-binary binding, and owned resource admission."""
import importlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import block_v2_capacity as C
import block_v2_host_store as H
import block_v2_owned_cli as O

T = importlib.import_module('block-v2-typed-gpu-run')


class CapacityTests(unittest.TestCase):
    def test_admitted_boundaries_and_planned_profiles(self):
        for count in (1, 63, 64):
            self.assertEqual(C.select(count), 64)
            self.assertEqual(C.select(count, 128), 128)
        for count in (65, 127, 128):
            self.assertEqual(C.select(count), 128)
            with self.assertRaises(ValueError): C.select(count, 64)
        for count in (0, 129, 256, 512, True):
            with self.assertRaises(ValueError): C.select(count)
        for capacity in C.PLANNED_CAPACITIES:
            with self.assertRaises(ValueError): C.validate(capacity)
        self.assertEqual(C.root_file({'block_capacity':128, 'count':64}), 'node.7.0')
        self.assertEqual(C.root_file({'count':64}), 'node.6.0')

    def test_binaries_must_agree_in_both_directions(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'probe'
            binary.touch()
            for capacity in C.SUPPORTED_CAPACITIES:
                receipt = {'schema':'lattica-block-capacity-v1',
                           'max_transactions':capacity, 'tree_depth':C.depth(capacity)}
                result = subprocess.CompletedProcess([], 0, json.dumps(receipt), '')
                with patch.object(C.subprocess, 'run', return_value=result):
                    C.require_binaries(capacity, binary, binary)
                    with self.assertRaises(ValueError):
                        C.require_binaries(192 - capacity, binary)
            with patch.object(C.subprocess, 'run', return_value=subprocess.CompletedProcess([],1,'','')):
                with self.assertRaises(ValueError): C.require_binaries(128, binary)

    def test_plan_capacity_and_depth_are_bound_even_for_small_blocks(self):
        plan = {'construction':'typed-paired-v1', 'registry_keys':12,
                'block_capacity':128, 'depth':7, 'count':4}
        T.validate_plan(plan, 'paired', 128)
        with self.assertRaises(ValueError): T.validate_plan(plan, 'paired', 64)
        with self.assertRaises(ValueError): T.validate_plan({**plan, 'depth':6}, 'paired', 128)

    def test_128_owned_model_is_separate_and_fits_unchanged_limits(self):
        fixture = importlib.import_module('test-block-v2-owned-cli').OwnedAdmission()
        fixture.setUp()
        profile = O.resource_profile(O.workload_path(128), 128)
        budget = fixture.plan()  # Historical profile remains accepted.
        module = importlib.import_module('block-v2-typed-multi-gpu-run')
        selected = module.plan_budgets(fixture.host, [fixture.device], profile)[fixture.device['uuid']]
        for kind, fields in [('host', ['worker_bytes','coordinator_bytes','fleet_bytes','spill_bytes']),
                             ('gpu', ['managed_bytes','context_bytes','headroom_bytes'])]:
            self.assertEqual([selected[kind][k] for k in fields], [budget[kind][k] for k in fields])
        self.assertEqual(profile['geometry']['tree_depth'], 7)
        self.assertNotEqual(selected['workload_kind'], budget['workload_kind'])
        self.assertGreater(selected['witness_bounds']['wires'], budget['witness_bounds']['wires'])
        self.assertFalse(profile['complete_lifetime_qualified'])
        with self.assertRaises(ValueError): O.resource_profile(O.WORKLOAD, 128)
        with self.assertRaises(ValueError): O.resource_profile(O.workload_path(128), 64)

    def test_native_profile_mismatch_and_legacy_capacity(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(H.NativeVerifier._libraries, {}, clear=True):
            for capacity in (None, 0, 64, 128):
                library = Path(directory) / str(capacity)
                library.write_bytes(b'explicit-noncryptographic-test-library')
                exports = dict(lattica_v2_research_host_initialize_v1=Mock(),
                               lattica_v2_research_host_replay_v1=Mock())
                if capacity is not None:
                    exports['lattica_v2_research_host_capacity_v1'] = Mock(return_value=capacity)
                args = (library, b'LBV2RG01', bytes(32), bytes(32),
                        b'LBV2GN01'+bytes(60), H.IssuancePolicy({}))
                with patch.object(H.ctypes, 'CDLL', return_value=SimpleNamespace(**exports)):
                    if capacity == 0:
                        with self.assertRaises(H.HostStoreError): H.NativeVerifier(*args)
                        continue
                    verifier = H.NativeVerifier(*args)
                    self.assertEqual(verifier.capacity, capacity or 64)
                    self.assertEqual('block_capacity' in verifier.configuration, capacity == 128)
                    if verifier.capacity == 64:
                        candidate = H.Candidate(1, b'LBV2BD01'+struct.pack('<I',65), b'proof')
                        with self.assertRaises(H.RejectedBlock): verifier._history_inputs([candidate])


if __name__ == '__main__':
    unittest.main()
