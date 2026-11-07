"""Persistent, exclusive 60-minute testing budget. Builds run separately.

Every invocation, including refusal, failure and timeout, is charged. An
interrupted controller cannot silently reset/refund an unfinished attempt.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

LIMIT_SECONDS = 3600
JOB_SECONDS = 300
CLEANUP_SECONDS = 30


class Budget:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self):
        if not self.path.exists():
            return dict(schema='cpu-proof-test-budget-v1', limit_seconds=LIMIT_SECONDS, attempts=[])
        value = json.loads(self.path.read_text())
        if value.get('schema') != 'cpu-proof-test-budget-v1' or value.get('limit_seconds') != LIMIT_SECONDS:
            raise RuntimeError('invalid testing budget ledger')
        return value

    def remaining(self):
        value = self.read()
        if any(a['status'] == 'running' for a in value['attempts']):
            raise RuntimeError('unfinished test attempt requires receipt reconciliation; budget cannot reset')
        return LIMIT_SECONDS - sum(a['wall_seconds'] for a in value['attempts'])

    def save(self, value):
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(value, indent=2) + '\n')
        temp.replace(self.path)

    def run(self, label, command, seconds=JOB_SECONDS, guard_unit=None, cwd=None):
        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,55}', label) is None or seconds < 1:
            raise RuntimeError('invalid testing label or timeout')
        with self.path.with_suffix('.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            remaining = self.remaining()
            timeout = min(seconds, JOB_SECONDS, int(remaining - CLEANUP_SECONDS))
            if timeout < 1:
                raise RuntimeError('one-hour cumulative testing budget exhausted')
            data = self.read()
            if any(a['label'] == label for a in data['attempts']):
                raise RuntimeError('test attempt labels cannot be reused')
            # A callable receives the actual remaining-budget timeout, so the
            # hardware guard and its cgroup are also bounded by that deadline.
            argv = command(timeout) if callable(command) else list(command)
            attempt = dict(label=label, command=argv, status='running', timeout_seconds=timeout,
                started_unix_ns=time.time_ns(), controller_pid=os.getpid(),
                reserved_seconds=timeout + CLEANUP_SECONDS)
            data['attempts'].append(attempt)
            self.save(data)
            start = time.monotonic()
            process = None
            log = self.path.parent / (label + '.controller.log')
            try:
                with log.open('w') as output:
                    process = subprocess.Popen(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                        start_new_session=True)
                    code = process.wait(timeout=timeout + (10 if guard_unit else 0))
                attempt.update(status='passed' if code == 0 else 'failed', returncode=code)
            except subprocess.TimeoutExpired:
                attempt.update(status='timed_out', returncode=None)
            except BaseException:
                attempt.update(status='interrupted', returncode=None)
                raise
            finally:
                try:
                    if process is not None and process.poll() is None:
                        if guard_unit:
                            # Guard descendants live in their own systemd cgroup.
                            # Retire that group before killing the controller group.
                            try:
                                subprocess.run(['/usr/bin/systemctl', '--user', 'stop', guard_unit],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                            finally:
                                if process.poll() is None:
                                    os.killpg(process.pid, signal.SIGKILL)
                        elif process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                finally:
                    attempt['wall_seconds'] = time.monotonic() - start
                    attempt['finished_unix_ns'] = time.time_ns()
                    attempt['log'] = str(log)
                    self.save(data)
            return attempt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', type=int, default=JOB_SECONDS)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('test command required')
    result = Budget(args.ledger).run(args.label, command, args.seconds)
    print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
