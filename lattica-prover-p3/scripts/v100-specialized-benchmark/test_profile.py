import tempfile
import unittest
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location('gpu_profile', Path(__file__).with_name('profile.py'))
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class ProfileTests(unittest.TestCase):
    def test_overlapping_commands_are_not_added_to_busy_time(self):
        self.assertEqual(profile.union_ns([(10, 20), (15, 25), (30, 35)]), 20)
        with self.assertRaises(ValueError):
            profile.union_ns([(20, 10)])

    def test_submission_order_and_dropped_events_reject_incomplete_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'profile.log'
            valid = ('gpu_timeline_interval kind=test queued_ns=1 submitted_ns=2 start_ns=3 end_ns=4\n'
                     'host_timeline_interval thread=0 name="work" start_ns=1 end_ns=3\n'
                     'performance_span name="work" total_ns=2\n')
            log.write_text(valid)
            result = profile.summarize(log)
            self.assertEqual(result['events'], 1)
            self.assertEqual(result['submit_to_start']['p50_us'], .001)
            for invalid in [valid + 'gpu_timeline_checkpoint dropped=1\n',
                            valid + 'performance_checkpoint spans_dropped=1\n',
                            valid.replace('submitted_ns=2', 'submitted_ns=5'),
                            valid.splitlines()[0] + '\n']:
                log.write_text(invalid)
                with self.assertRaises(ValueError):
                    profile.summarize(log)


if __name__ == '__main__':
    unittest.main()
