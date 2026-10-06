#!/usr/bin/env python3
"""Controller checks use synthetic records, never measured qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('query_compare', Path(__file__).with_name('block-v2-query-compare.py'))
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


class QueryComparison(unittest.TestCase):
    def profiles(self):
        p = Q.T.resource_profile(Path(__file__).with_name('block-v2-multi-gpu-direct-readback-workload.json'), 'paired', 'compact')
        profiles = {'rows': p, 'gather': copy.deepcopy(p)}
        profiles['gather']['geometry']['query_readback_layout'] = 'gather'
        return profiles

    def test_only_query_layout_may_differ(self):
        profiles = self.profiles()
        original = copy.deepcopy(profiles)
        Q.validate_profiles(profiles)
        self.assertEqual(profiles, original)
        profiles['gather']['geometry']['main_columns'] += 1
        with self.assertRaisesRegex(ValueError, 'differ only'):
            Q.validate_profiles(profiles)
        profiles = self.profiles()
        profiles['gather']['phases'][0]['name'] = 'different'
        with self.assertRaises(ValueError): Q.validate_profiles(profiles)

    def test_profiles_must_match_both_arm_names(self):
        profiles = self.profiles()
        profiles['gather']['geometry']['query_readback_layout'] = 'rows'
        with self.assertRaises(ValueError): Q.validate_profiles(profiles)
        with self.assertRaises(ValueError): Q.validate_profiles({'rows': profiles['rows']})

    def checkpoints(self, layout='gather', **changes):
        values = dict(gather=str(layout == 'gather').lower(), counters='cumulative', calls=3,
                      tiles=4, readbacks=4 if layout == 'gather' else 400,
                      downloaded_bytes=1024, gather_device_ns=300 if layout == 'gather' else 0, wall_ns=1000)
        values.update(changes)
        return 'bounded_gpu_query_checkpoint label="after proof" ' + ' '.join(f'{k}={v}' for k,v in values.items()) + ' timings=nonadditive\n'

    def test_query_work_is_observed_and_gather_reads_once_per_tile(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'prove.log'
            for layout in Q.LAYOUTS:
                path.write_text(self.checkpoints(layout))
                self.assertEqual(Q.query_checkpoints(path, layout)[0]['label'], 'after proof')
            for changes in ({'gather':'false'}, {'readbacks':5}, {'tiles':0},
                            {'downloaded_bytes':0}, {'calls':0}, {'wall_ns':-1}):
                path.write_text(self.checkpoints(**changes))
                with self.assertRaises(ValueError): Q.query_checkpoints(path, 'gather')
            path.write_text('no query reconstruction\n')
            with self.assertRaises(ValueError): Q.query_checkpoints(path, 'gather')

    def test_worker_boundary_and_alternating_order_drive_pair_arithmetic(self):
        pairs = []
        for number in range(1, 6):
            trials = [{'query_readback_layout': layout, 'worker_seconds': 20 if layout == 'rows' else 15}
                      for layout in Q.C.trial_order(number, *Q.LAYOUTS)]
            pairs.append(Q.pair_measurement(number, trials))
            with self.assertRaises(ValueError): Q.pair_measurement(number, trials[::-1])
            trials[0]['worker_seconds'] = float('nan')
            with self.assertRaises(ValueError): Q.pair_measurement(number, trials)
        a = Q.aggregate(pairs)
        self.assertEqual(a['median_within_pair_reduction_percent'], 25)
        self.assertEqual(a['gather_faster_pairs'], 5)
        self.assertEqual(a['median_worker_seconds'], {'rows':20, 'gather':15})

    def test_profile_and_auditor_must_match_the_checked_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); worker = root/'001-typed'; worker.mkdir()
            cpu = root/'cpu'; cpu.write_text('synthetic CPU binary')
            profile = self.profiles()['gather']
            config = {'workload':profile, 'cpu_binary':str(cpu), 'pins':{str(cpu):Q.T.G.digest(cpu)}}
            result = {'profile_sha256':Q.T.G.profile_digest(config), 'budget':{'query_readback_layout':'gather'}}
            (worker/'prove.log').write_text(self.checkpoints())
            (root/'config.json').write_text(json.dumps(config))
            (worker/'result.json').write_text(json.dumps(result))
            args = (root, 'paired', 4, {}, 'assignment', 'gpu', Q.T.G.digest(cpu), profile, 'gather')
            with patch.object(Q.C, 'checked_trial', return_value={}):
                self.assertEqual(Q.checked_trial(*args)['query_readback_layout'], 'gather')
                result['budget']['query_readback_layout'] = 'rows'
                (worker/'result.json').write_text(json.dumps(result))
                with self.assertRaises(ValueError): Q.checked_trial(*args)
                result['budget']['query_readback_layout'] = 'gather'
                result['profile_sha256'] = 'wrong'
                (worker/'result.json').write_text(json.dumps(result))
                with self.assertRaises(ValueError): Q.checked_trial(*args)
                cpu.write_text('changed auditor')
                with self.assertRaises(ValueError): Q.checked_trial(*args)


if __name__ == '__main__':
    unittest.main()
