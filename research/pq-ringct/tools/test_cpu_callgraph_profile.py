import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

import cpu_callgraph_profile as p


class CallgraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'recording'
        self.path.write_bytes(b'PERFILE2payload')
        self.selected = {'kind': 'native', 'workers': 16, 'callgraph': True}
        self.decoder = patch.object(p.subprocess, 'run', return_value=CompletedProcess([], 0, '123\n' * 23, ''))
        self.decode = self.decoder.start()
        self.addCleanup(self.decoder.stop)
        self.row = {'kind': 'native', 'workers': 16, 'cases': 159, 'elapsed_ns': 1,
                    'counts_equal': True, 'gpu_used': False, 'original_host_bytes': 1,
                    'phase_host_bytes_peak': 1, 'ledger_all_claims_released': True,
                    'cache': {'threads_spawned': 0, 'jobs_started': 0, 'admitted_host_bytes_peak': 1}}

    def log(self):
        return 'CPU_SCALING_RESULT ' + json.dumps(self.row) + '\n[ perf record: Captured (23 samples) ]\n'

    def test_command_is_bounded_and_does_not_write_buildid_cache(self):
        argv = p.command(['binary', 'exact-test'], self.path)
        self.assertEqual(argv[argv.index('--max-size') + 1], '512M')
        self.assertEqual(argv[argv.index('--call-graph') + 1], 'dwarf,8192')
        self.assertIn('--no-buildid-cache', argv)
        self.assertIn('--all-user', argv)
        self.assertIn('--user-callchains', argv)
        self.assertEqual(argv[-3:], ['--', 'binary', 'exact-test'])

    def test_records_hash_and_preserves_correctness_checks(self):
        accepted, artifact = p.validate(self.log(), self.selected, self.path)
        self.assertEqual(artifact['samples'], 23)
        self.assertEqual(len(artifact['sha256']), 64)
        self.assertFalse(accepted['counters'])
        for field in ['counts_equal', 'ledger_all_claims_released']:
            self.row[field] = False
            with self.assertRaises(ValueError):
                p.validate(self.log(), self.selected, self.path)
            self.row[field] = True

    def test_rejects_missing_lost_or_duplicate_samples_and_wrong_scope(self):
        for log in [self.log().replace('perf record: Captured', ''), self.log() * 2,
                    self.log() + 'lost 2 samples']:
            with self.assertRaises(ValueError):
                p.validate(log, self.selected, self.path)
        with self.assertRaises(ValueError):
            p.validate(self.log(), {**self.selected, 'kind': 'registered'}, self.path)
        for output in ['', 'PERF_RECORD_LOST 4\n', '123\ninvalid\n']:
            self.decode.return_value = CompletedProcess([], 0, output, '')
            with self.assertRaises(ValueError):
                p.validate(self.log(), self.selected, self.path)

    def test_rejects_missing_invalid_symlink_and_size_cap(self):
        self.path.write_bytes(b'BADFILE2payload')
        with self.assertRaises(ValueError):
            p.validate(self.log(), self.selected, self.path)
        with self.path.open('wb') as output:
            output.write(b'PERFILE2')
            output.truncate(p.MAX_BYTES)
        with self.assertRaises(ValueError):
            p.validate(self.log(), self.selected, self.path)
        self.path.unlink()
        with self.assertRaises(ValueError):
            p.validate(self.log(), self.selected, self.path)
        self.path.symlink_to(Path(__file__))
        with self.assertRaises(ValueError):
            p.validate(self.log(), self.selected, self.path)


if __name__ == '__main__':
    unittest.main()
