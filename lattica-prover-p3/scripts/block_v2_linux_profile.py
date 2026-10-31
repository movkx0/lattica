"""Scoped Nsight capture with explicit environment and monotonic clock anchors."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SAFE_ENV = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL',
            'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS'}


def validate(profile, pins):
    """Only bounded, explicit diagnostic options; never accept an argv prefix."""
    common = {'tool', 'executable', 'nvtx_library'}
    tool = profile.get('tool')
    if tool == 'nsys':
        if not common <= set(profile) <= common | {'cpu_sampling', 'cpu_backtrace'}:
            raise ValueError('invalid CUDA timeline assignment')
        if 'cpu_sampling' in profile and type(profile['cpu_sampling']) is not bool:
            raise ValueError('CPU sampling must be an explicit boolean')
        if 'cpu_backtrace' in profile and (
                not profile.get('cpu_sampling', False)
                or profile['cpu_backtrace'] not in ('fp', 'dwarf')):
            raise ValueError('CPU backtrace requires sampling and an explicit fp or dwarf method')
    elif tool == 'ncu':
        if set(profile) != common | {'kernel', 'launch_skip', 'launch_count', 'metrics'}:
            raise ValueError('invalid CUDA kernel profiling assignment')
        if (not isinstance(profile['kernel'], str) or not profile['kernel']
                or len(profile['kernel']) > 256 or '\0' in profile['kernel']):
            raise ValueError('invalid profiling kernel filter')
        for key, lower, upper in (('launch_skip', 0, 1000000), ('launch_count', 1, 8)):
            if type(profile[key]) is not int or not lower <= profile[key] <= upper:
                raise ValueError('invalid profiling launch bound')
        metrics = profile['metrics']
        if (not isinstance(metrics, list) or not 1 <= len(metrics) <= 16
                or any(not isinstance(m, str) or not m or len(m) > 160
                       or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.' for c in m)
                       for m in metrics)):
            raise ValueError('invalid profiling metrics')
    else:
        raise ValueError('unknown CUDA profiler')
    for key in ('executable', 'nvtx_library'):
        path = Path(profile[key])
        if not path.is_absolute() or str(path) not in pins:
            raise ValueError('profiler and NVTX library must be pinned absolute paths')


def load(path):
    path = Path(path).resolve(strict=True)
    profile = json.loads(path.read_text())
    if not isinstance(profile, dict):
        raise ValueError('profiling assignment must be an object')
    pins = {}
    for artifact in (path, *(Path(profile[k]) for k in ('executable', 'nvtx_library'))):
        if not artifact.is_absolute():
            raise ValueError('profiling paths must be absolute')
        with artifact.open('rb') as stream:
            pins[str(artifact)] = hashlib.file_digest(stream, 'sha256').hexdigest()
    validate(profile, pins)
    return profile, pins


def cuda_command(profile, pins, directory, prover_command, environment, shared_worker=False):
    validate(profile, pins)
    # CUDA paths come from the launcher's pinned runtime, not the desktop shell.
    env = {k: v for k, v in environment.items()
           if k in SAFE_ENV | {'LD_LIBRARY_PATH', 'CUDA_PATH'}
           or k.startswith(('LATTICA_', 'RAYON_'))}
    env['LATTICA_CUDA_PROFILE_LIBRARY'] = profile['nvtx_library']
    if profile['tool'] == 'nsys':
        sampling = 'process-tree' if profile.get('cpu_sampling', False) else 'none'
        argv = [profile['executable'], 'profile', '--trace=cuda,nvtx,osrt',
                '--sample=' + sampling, '--cpuctxsw=' + sampling, '--gpu-metrics-devices=none',
                '--cuda-memory-usage=true', '--kill=none',
                '--output=' + str(directory / 'nsight')]
        if profile.get('cpu_sampling', False):
            argv += ['--backtrace=' + profile.get('cpu_backtrace', 'dwarf'),
                     '--sampling-period=22660288']
    else:
        # The managed identity helper execs the prover. Nsight Compute must
        # follow that handoff; all targets remain in this worker's cgroup.
        argv = [profile['executable'], '--target-processes', 'all' if shared_worker else 'application-only',
                '--clock-control', 'none', '--cache-control', 'none',
                '--kernel-name', profile['kernel'],
                '--launch-skip', str(profile['launch_skip']),
                '--launch-count', str(profile['launch_count']),
                '--metrics', ','.join(profile['metrics']),
                '--export', str(directory / 'kernel-profile')]
    target = list(map(str, prover_command))
    if shared_worker:
        if str(Path(__file__).resolve()) not in pins:
            raise ValueError('shared profiling helper must be pinned')
        target = [sys.executable, str(Path(__file__).resolve()), '--worker-exec', '--', *target]
    return argv + target, env


def completed_capture(profile, directory):
    """Accept either Nsight Compute report format, without accepting stale duplicates."""
    if profile['tool'] == 'nsys':
        names = ('nsight.nsys-rep',)
    elif profile['tool'] == 'ncu':
        # Nsight Compute 2026.3 defaults to the compressed .ncu-repz format.
        names = ('kernel-profile.ncu-rep', 'kernel-profile.ncu-repz')
    else:
        raise ValueError('unknown CUDA profiler')
    captures = [directory / name for name in names if (directory / name).exists()]
    if (len(captures) != 1 or not captures[0].is_file()
            or captures[0].stat().st_size == 0):
        raise ValueError('profiler exited without a single complete capture')
    return captures[0]


def command(config, budget, directory, prover_command, environment):
    profile = config.get('linux_profile')
    if profile is None:
        return prover_command, environment
    if 'tool' in profile:
        return cuda_command(profile, config['pins'], directory, prover_command, environment,
                            config.get('profile_shared_worker', False))
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
            '--gpu-metrics-frequency=1000',
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


def worker_entry(mode, argv):
    """Keep the original worker executable/argv as systemd's authenticated PID.

    The profiler stays in the same bounded cgroup until export completes.
    No pipe replaces the worker's duplex stdin and no identity check is skipped.
    """
    if not argv or argv[0] != '--' or len(argv) < 2:
        raise ValueError('missing profiling worker command')
    argv = argv[1:]
    if not os.environ.get('NOTIFY_SOCKET'):
        raise ValueError('shared profiling requires its managed notification socket')
    if mode == '--worker-env':
        keep = SAFE_ENV | {'LD_LIBRARY_PATH', 'CUDA_PATH', 'NOTIFY_SOCKET'}
        env = {k: v for k, v in os.environ.items()
               if k in keep or k.startswith(('LATTICA_', 'RAYON_'))}
    elif mode == '--worker-exec':
        # systemd-notify waits for manager acknowledgement before returning.
        subprocess.run(['/usr/bin/systemd-notify', '--pid=' + str(os.getpid())],
                       stdin=subprocess.DEVNULL, check=True, timeout=10)
        env = dict(os.environ)
    else:
        raise ValueError('unknown profiling worker entry')
    os.execvpe(argv[0], argv, env)


def main():
    if sys.argv[1:2] in (['--worker-env'], ['--worker-exec']):
        return worker_entry(sys.argv[1], sys.argv[2:])
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
