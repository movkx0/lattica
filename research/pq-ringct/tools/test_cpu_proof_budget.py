import json
from pathlib import Path
import sys
import tempfile
import unittest
from cpu_proof_budget import Budget, LIMIT_SECONDS


class TestingBudget(unittest.TestCase):
    def test_failed_and_timed_out_attempts_are_charged_and_cannot_be_repeated(self):
        with tempfile.TemporaryDirectory() as path:
            budget = Budget(Path(path) / 'budget.json')
            failed = budget.run('failure', [sys.executable, '-c', 'raise SystemExit(2)'])
            self.assertEqual(failed['status'], 'failed')
            stopped = budget.run('timeout', [sys.executable, '-c', 'import time; time.sleep(10)'], seconds=1)
            self.assertEqual(stopped['status'], 'timed_out')
            self.assertLess(budget.remaining(), LIMIT_SECONDS - 1)
            with self.assertRaises(RuntimeError):
                budget.run('failure', [sys.executable, '-c', 'pass'])

    def test_exhausted_or_unfinished_ledgers_cannot_reset(self):
        with tempfile.TemporaryDirectory() as path:
            budget = Budget(Path(path) / 'budget.json')
            value = budget.read()
            value['attempts'] = [dict(label='spent', status='failed', wall_seconds=LIMIT_SECONDS - 29)]
            budget.save(value)
            with self.assertRaises(RuntimeError):
                budget.run('next', [sys.executable, '-c', 'pass'])
            value['attempts'][0]['status'] = 'running'
            budget.save(value)
            with self.assertRaises(RuntimeError):
                budget.remaining()


if __name__ == '__main__':
    unittest.main()
