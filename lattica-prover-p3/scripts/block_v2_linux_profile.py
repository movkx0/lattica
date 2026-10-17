"""Scoped Nsight capture with explicit environment and monotonic clock anchors."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SAFE_ENV = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL',
            'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS'}


def command(config, budget, directory, prover_command, environment):
    profile = config.get('linux_profile')
    if profile is None:
        return prover_command, environment
    if set(profile) != {'nsys', 'gpu_index', 'clock_library', 'clock_runner'}:
        raise ValueError('invalid Linux profiling assignment')
    if type(profile['gpu_index']) is not int or profile['gpu_index'] < 0:
        raise ValueError('invalid profiling device index')
    for key in ('nsys', 'clock_library', 'clock_runner'):
        path = Path(profile[key])
        if not path.is_absolute() or str(path) not in config['pins']:
            raise ValueError('profiler and clock helpers must be pinned absolute paths')
    # Nsight records its target environment. Keep credentials and unrelated
    # desktop/application variables out of both the target and report.
    env = {k: v for k, v in environment.items()
           if k in SAFE_ENV or k.startswith(('LATTICA_', 'RAYON_'))}
    env['LATTICA_PROFILE_TIMELINE'] = '1'
    argv = [profile['nsys'], 'profile', '--trace=nvtx,osrt', '--sample=process-tree',
            '--sampling-period=22660288',
            '--backtrace=dwarf', '--cpuctxsw=process-tree',
            '--gpu-metrics-devices=' + str(profile['gpu_index']),
            '--gpu-metrics-set=gb20x', '--gpu-metrics-frequency=1000',
            '--kill=none', '--output=' + str(directory / 'nsight'),
            sys.executable, profile['clock_runner'], '--clock-library',
            profile['clock_library'], '--clock-output', str(directory / 'profile-clock.jsonl'),
            '--', *map(str, prover_command)]
    return argv, env


def process_samples(root_pid, proc=Path('/proc')):
    """Process CPU counters include every thread, without reading argv or env."""
    pending, seen, result = [root_pid], set(), []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        root = proc / str(pid)
        try:
            text = (root / 'stat').read_text()
            fields = text[text.rindex(')') + 2:].split()
            result.append(dict(pid=pid, state=fields[0], user_ticks=int(fields[11]),
                               system_ticks=int(fields[12]), threads=int(fields[17]),
                               start_ticks=int(fields[19]), rss_pages=int(fields[21])))
            # The coordinator spawns its worker from its main thread.
            pending.extend(map(int, (root / 'task' / str(pid) / 'children').read_text().split()))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--clock-library', type=Path, required=True)
    ap.add_argument('--clock-output', type=Path, required=True)
    ap.add_argument('prover', nargs=argparse.REMAINDER)
    args = ap.parse_args()
    argv = args.prover[1:] if args.prover[:1] == ['--'] else args.prover
    if not argv:
        ap.error('missing prover command')
    library = ctypes.CDLL(str(args.clock_library.resolve(strict=True)))
    mark = library.lattica_profile_mark
    mark.argtypes, mark.restype = [ctypes.c_char_p], None
    os.umask(0o077)
    child = None
    def interrupted(signum, _frame):
        if child is not None and child.poll() is None:
            child.send_signal(signum)
        raise InterruptedError(f'profiling wrapper interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with args.clock_output.open('x') as stream:
        stream.write(json.dumps(dict(type='metadata', schema='lattica-linux-profile-clock-v1',
                                      pid=os.getpid(), ticks_per_second=os.sysconf('SC_CLK_TCK'),
                                      page_bytes=os.sysconf('SC_PAGE_SIZE'),
                                      clock='CLOCK_MONOTONIC', samples='process_cpu_ticks')) + '\n')
        sequence = 0
        def anchor():
            nonlocal sequence
            label = f'lattica_clock:{sequence}'.encode()
            before = time.monotonic_ns()
            mark(label)
            after = time.monotonic_ns()
            stream.write(json.dumps(dict(type='clock', sequence=sequence,
                                          before_ns=before, after_ns=after,
                                          processes=process_samples(child.pid) if child else [])) + '\n')
            stream.flush()
            sequence += 1
        try:
            anchor()
            started = time.monotonic_ns()
            child = subprocess.Popen(argv)
            stream.write(json.dumps(dict(type='prover_start', pid=child.pid, before_ns=started,
                                          after_ns=time.monotonic_ns())) + '\n')
            while True:
                anchor()
                try:
                    code = child.wait(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    pass
            ended = time.monotonic_ns()
            anchor()
            stream.write(json.dumps(dict(type='prover_end', pid=child.pid, returncode=code,
                                          clock_ns=ended, elapsed_ns=ended-started)) + '\n')
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
