#!/usr/bin/env python3
"""Recovery runners must work from their archive and preserve JSON receipts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'native_host_qualifier', Path(__file__).with_name('qualify-block-v2-native-host.py'))
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


class NativeHostTools(unittest.TestCase):
    def test_frozen_runner_imports_without_the_source_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory / 'tools'
            pins = Q.freeze_tools(archive)
            Q.unchanged(pins)
            command = [sys.executable, '-E', str(archive / 'qualify-block-v2-native-host.py'), '--help']
            environment = {key: value for key, value in os.environ.items() if not key.startswith('PYTHON')}
            result = subprocess.run(command, cwd=directory, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--alternate-proof', result.stdout)
            # A missing archived dependency must not be supplied by the checkout.
            (archive / 'block_v2_capacity.py').unlink()
            result = subprocess.run(command, cwd=directory, env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('block_v2_capacity', result.stderr)

    def test_native_diagnostics_do_not_corrupt_restart_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            runner = directory / 'child.py'
            runner.write_text("import sys\nprint('native verification diagnostic', file=sys.stderr)\n"
                              "print('{\"status\": \"passed\"}')\n")
            output = directory / 'restart.log'
            code = Q.invoke_child(str(runner), directory / 'inputs.json', directory,
                                  'restart', '-', '-', output)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text()), {'status': 'passed'})
            self.assertEqual(output.with_suffix('.stderr.log').read_text(),
                             'native verification diagnostic\n')


if __name__ == '__main__':
    unittest.main()
