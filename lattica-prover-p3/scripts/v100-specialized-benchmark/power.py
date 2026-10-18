#!/usr/bin/env python3
"""Repeat the pinned four-input GPU benchmark with read-only NVML energy metering.

The energy window starts immediately before worker launch and ends when wait()
returns. It includes context initialization and shutdown; the separate CPU audit
and idle baselines are excluded. All existing proving receipts remain required.
"""
import argparse
import csv
import ctypes as ct
import ctypes.util
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('benchmark', ROOT / 'run.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
C, E = B.C, B.E
GIB = 1 << 30


class Meter:
    def __init__(self, directory):
        self.lib = ct.CDLL(ctypes.util.find_library('nvidia-ml'))
        self.lib.nvmlErrorString.restype = ct.c_char_p
        self.lib.nvmlErrorString.argtypes = [ct.c_int]
        self.check(self.lib.nvmlInit_v2())
        self.handle = ct.c_void_p()
        handle_fn = self.lib.nvmlDeviceGetHandleByUUID
        handle_fn.argtypes = [ct.c_char_p, ct.POINTER(ct.c_void_p)]
        self.check(handle_fn(B.UUID.encode(), ct.byref(self.handle)))
        for name, typ in (
            ('nvmlDeviceGetPowerUsage', ct.c_uint),
            ('nvmlDeviceGetPowerManagementLimit', ct.c_uint),
            ('nvmlDeviceGetEnforcedPowerLimit', ct.c_uint),
            ('nvmlDeviceGetTotalEnergyConsumption', ct.c_ulonglong),
        ):
            getattr(self.lib, name).argtypes = [ct.c_void_p, ct.POINTER(typ)]
        self.power_limit_w = self.get('nvmlDeviceGetPowerManagementLimit') / 1000
        self.enforced_limit_w = self.get('nvmlDeviceGetEnforcedPowerLimit') / 1000
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.rows, self.errors = [], []
        self.output = (directory / 'power.jsonl').open('w', buffering=1)
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def check(self, code):
        if code:
            raise RuntimeError(self.lib.nvmlErrorString(code).decode())

    def get(self, name, typ=ct.c_uint):
        value = typ()
        self.check(getattr(self.lib, name)(self.handle, ct.byref(value)))
        return value.value

    def read(self, marker='sample'):
        with self.lock:
            start = time.monotonic_ns()
            power = self.get('nvmlDeviceGetPowerUsage')
            energy_start = time.monotonic_ns()
            energy = self.get('nvmlDeviceGetTotalEnergyConsumption', ct.c_ulonglong)
            end = time.monotonic_ns()
            row = dict(marker=marker, monotonic_seconds=(energy_start + end) / 2e9,
                       utc=datetime.now(timezone.utc).isoformat(), power_w=power / 1000,
                       energy_mj=energy, read_duration_ms=(end - start) / 1e6)
            self.rows.append(row)
            self.output.write(json.dumps(row) + '\n')
            return row

    def loop(self):
        deadline = time.monotonic()
        try:
            while not self.stop_event.is_set():
                self.read()
                deadline += .1
                self.stop_event.wait(max(0, deadline - time.monotonic()))
        except BaseException as error:
            self.errors.append(f'{type(error).__name__}: {error}')
            self.stop_event.set()

    def close(self):
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError('power sampler failed to stop')
        self.output.close()
        self.check(self.lib.nvmlShutdown())
        if self.errors:
            raise RuntimeError('; '.join(self.errors))

    def window(self, start, end):
        a, b = start['monotonic_seconds'], end['monotonic_seconds']
        rows = sorted((r for r in self.rows if a <= r['monotonic_seconds'] <= b),
                      key=lambda r: r['monotonic_seconds'])
        gaps = [y['monotonic_seconds'] - x['monotonic_seconds']
                for x, y in zip(rows, rows[1:])]
        integrated = sum(dt * (x['power_w'] + y['power_w']) / 2
                         for dt, x, y in zip(gaps, rows, rows[1:]))
        joules = (end['energy_mj'] - start['energy_mj']) / 1000
        if b <= a or joules <= 0 or len(rows) < 2:
            raise RuntimeError('invalid power window')
        if any(y['energy_mj'] < x['energy_mj'] for x, y in zip(rows, rows[1:])):
            raise RuntimeError('GPU energy counter decreased during measurement')
        return dict(start=start, end=end, seconds=b-a, samples=len(rows),
                    energy_j=joules, energy_wh=joules/3600,
                    average_power_w=joules/(b-a), sampled_peak_power_w=max(r['power_w'] for r in rows),
                    sampled_min_power_w=min(r['power_w'] for r in rows),
                    integrated_power_j=integrated, integrated_average_power_w=integrated/(b-a),
                    integral_vs_counter_percent=100*(integrated/joules-1),
                    median_sample_gap_seconds=statistics.median(gaps),
                    max_sample_gap_seconds=max(gaps),
                    max_read_duration_ms=max(r['read_duration_ms'] for r in rows))


def measured_stage(argv, name, meter, windows):
    """Existing resource watchdog plus launch/exit energy boundaries."""
    directory = B.OUT / name
    directory.mkdir()
    before = C.cgroup()
    if C.gpu(B.UUID)['compute_processes']:
        raise RuntimeError('GPU must be idle before the power measurement')
    environment = B.environment(True, '')
    C.write_json(directory / 'command.json', dict(argv=list(map(str, argv)),
                 overrides={k: v for k, v in environment.items() if k.startswith(('LATTICA_', 'RAYON_'))},
                 cgroup_before=before))
    peak = gpu_peak = charge_peak = 0
    gpu_pid = attribution = None
    next_gpu = last_status = 0
    process = waiter = None
    finished = threading.Event()
    completion = {}
    result = {'status': 'running'}
    stage_start = time.monotonic()

    def wait_for_exit():
        try:
            completion['exit_code'] = process.wait()
            completion['end'] = meter.read('gpu_worker_end')
        except BaseException as error:
            completion['error'] = f'{type(error).__name__}: {error}'
        finally:
            finished.set()

    try:
        with (directory / 'benchmark.log').open('w') as log, (directory / 'telemetry.jsonl').open('w', buffering=1) as telemetry:
            start = meter.read('gpu_worker_start')
            process = subprocess.Popen(list(map(str, argv)), cwd=ROOT, env=environment,
                        stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                        start_new_session=True)
            waiter = threading.Thread(target=wait_for_exit, daemon=True)
            waiter.start()
            while not finished.is_set():
                now = time.monotonic()
                members = C.group_rss(process.pid)
                rss = sum(members.values())
                peak = max(peak, rss)
                charge = int((Path(before['path']) / 'memory.current').read_text())
                charge_peak = max(charge_peak, charge)
                row = dict(seconds=now-stage_start, rss_bytes=rss, cgroup_bytes=charge)
                if now >= next_gpu:
                    row.update(C.gpu(B.UUID))
                    gpu_pid, observed = C.check_gpu_processes(row['compute_processes'], members, gpu_pid)
                    attribution = observed or attribution
                    gpu_peak = max(gpu_peak, float(row['gpu']['memory.used']))
                    if gpu_peak > 20*1024:
                        raise RuntimeError('GPU usage exceeded the 20 GiB watchdog')
                    next_gpu = now+1
                telemetry.write(json.dumps(row)+'\n')
                if rss > E.RSS_LIMIT or charge > int(before['memory.max'])-2*GIB:
                    raise RuntimeError('RAM watchdog stopped worker before container limit')
                if now-stage_start > 3600:
                    raise RuntimeError('one-hour worker watchdog expired')
                if meter.errors:
                    raise RuntimeError('; '.join(meter.errors))
                if now-last_status >= 20:
                    latest = meter.rows[-1]
                    print(f'{name}: {now-stage_start:.1f}s; GPU {latest["power_w"]:.1f} W; peak RSS {peak/GIB:.2f} GiB', flush=True)
                    last_status = now
                finished.wait(.1)
            waiter.join()
        if completion.get('error'):
            raise RuntimeError(completion['error'])
        if completion['exit_code']:
            raise RuntimeError(f'GPU worker exited {completion["exit_code"]}; see {directory / "benchmark.log"}')
        windows['gpu_worker'] = meter.window(start, completion['end'])
        if C.gpu(B.UUID)['compute_processes']:
            raise RuntimeError('GPU compute process remains after worker exit')
        after = C.cgroup()
        first, last = E.events(before['memory.events']), E.events(after['memory.events'])
        deltas = {k: last[k]-first[k] for k in first}
        if any(deltas.values()):
            raise RuntimeError('container memory-limit event invalidates sample')
        result.update(status='passed', seconds=time.monotonic()-stage_start,
                      peak_rss_bytes=peak, peak_cgroup_bytes=charge_peak, peak_gpu_mib=gpu_peak,
                      nvml_pid=gpu_pid, gpu_pid_attribution=attribution, memory_event_deltas=deltas)
        print('GPU worker complete; recording ten seconds after exit.', flush=True)
        post_start = meter.read('post_idle_start')
        time.sleep(10)
        post_end = meter.read('post_idle_end')
        windows['post_exit'] = meter.window(post_start, post_end)
        return result
    except BaseException as error:
        if process is not None:
            C.terminate_group(process)
        if waiter is not None:
            waiter.join(timeout=5)
        result.update(status='failed', error=f'{type(error).__name__}: {error}',
                      seconds=time.monotonic()-stage_start, peak_rss_bytes=peak,
                      peak_cgroup_bytes=charge_peak, peak_gpu_mib=gpu_peak)
        raise
    finally:
        C.write_json(directory / 'result.json', result)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    B.add_arguments(parser)
    B.configure(parser.parse_args())
    B.verify_pins()
    B.admit()
    name = 'power-baseline-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    directory = B.OUT / (name + '-power')
    directory.mkdir()
    original_stage = B.stage
    windows = {}
    state = {'status': 'running', 'name': name, 'timestamp_utc': datetime.now(timezone.utc).isoformat()}
    meter = None
    try:
        manifest = B.verify_pins()
        gpu_before = C.gpu(B.UUID)
        if gpu_before['compute_processes']:
            raise RuntimeError('GPU is occupied')
        meter = Meter(directory)
        state.update(git_commit=manifest['git_commit'], gpu_before=gpu_before,
                     binaries=manifest['binaries'], tuning='', sampler_period_seconds=.1,
                     controller_git_commit=C.capture(['git', 'rev-parse', 'HEAD'], cwd=B.CRATE),
                     power_limit_w=meter.power_limit_w, enforced_power_limit_w=meter.enforced_limit_w,
                     controller_sha256=C.digest(Path(__file__)),
                     energy_source='NVML hardware total-energy counter delta, millijoules converted to joules',
                     power_source='NVML board power (GPU and associated circuitry, including memory)',
                     measurement_window='Immediately before GPU worker launch through wait() completion; includes GPU initialization, aggregation, verification, serialization and shutdown. Excludes idle windows and separate CPU audit.',
                     scope=manifest['scope'])
        meter.thread.start()
        print('Recording ten-second idle baseline.', flush=True)
        idle_start = meter.read('pre_idle_start')
        time.sleep(10)
        idle_end = meter.read('pre_idle_end')
        windows['idle_before'] = meter.window(idle_start, idle_end)

        def stage(argv, stage_name, gpu=False, tuning=''):
            if gpu:
                if tuning:
                    raise RuntimeError('this measurement pins the faster baseline configuration')
                return measured_stage(argv, stage_name, meter, windows)
            return original_stage(argv, stage_name, gpu, tuning)

        B.stage = stage
        B.sample(name, '')
        sample = json.loads((B.OUT / name / 'verified-sample.json').read_text())
        power_after = meter.get('nvmlDeviceGetEnforcedPowerLimit') / 1000
        if power_after != meter.enforced_limit_w:
            raise RuntimeError('power limit changed during benchmark')
        state.update(status='passed', sample=sample, windows=windows, gpu_after=C.gpu(B.UUID),
                     energy_wh_per_aggregated_input=windows['gpu_worker']['energy_wh']/4,
                     transactions_per_kwh_aggregation_only=4000/windows['gpu_worker']['energy_wh'],
                     average_increment_above_idle_w=windows['gpu_worker']['average_power_w']-windows['idle_before']['average_power_w'])
        meter.close()
        rows = meter.rows
        meter = None
        with (directory / 'power.csv').open('w', newline='') as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        window, idle = windows['gpu_worker'], windows['idle_before']
        text = (
            'V100 four-input specialized recursive aggregation: power measurement\n'
            f'Run: {name}\nRevision: {manifest["git_commit"]}\n'
            f'Aggregation time: {sample["seconds"]:.6f} s\n'
            f'Metered GPU worker duration: {window["seconds"]:.6f} s (includes GPU initialization and shutdown)\n'
            f'Average board power: {window["average_power_w"]:.3f} W (hardware energy / worker duration)\n'
            f'Peak sampled board power: {window["sampled_peak_power_w"]:.3f} W\n'
            f'GPU energy: {window["energy_j"]:.3f} J = {window["energy_wh"]:.6f} Wh\n'
            f'GPU energy per aggregated input: {window["energy_wh"]/4:.6f} Wh\n'
            f'Idle average: {idle["average_power_w"]:.3f} W over {idle["seconds"]:.3f} s\n'
            f'Power limit: {state["power_limit_w"]:.1f} W; enforced limit unchanged\n'
            f'Sampling: {window["samples"]} readings; median interval {window["median_sample_gap_seconds"]:.6f} s; maximum interval {window["max_sample_gap_seconds"]:.6f} s\n'
            f'Integrated sampled power vs hardware energy: {window["integral_vs_counter_percent"]:+.4f}%\n'
            f'Validation: all 16 proving stages on GPU, {sample["specialized_executions"]} specialized quotient executions, independent CPU root audit passed\n'
            f'Aggregation throughput for this run: {sample["aggregation_user_transactions_per_hour"]:.3f} existing transaction proofs/hour\n'
            'Scope: four existing JoinSplit wallet proofs, two pair wrappers, one level-two merge root.\n'
            'Power and energy are GPU board readings; CPU and other system power are excluded.\n'
            'Wallet proving and full-block finalization are outside this workload.\n'
        )
        (directory / 'results.txt').write_text(text)
        print(text, flush=True)
    except BaseException as error:
        state.update(status='failed', error=f'{type(error).__name__}: {error}', windows=windows)
        raise
    finally:
        B.stage = original_stage
        if meter is not None:
            try:
                meter.close()
            except BaseException as error:
                state.update(status='failed', sampler_error=f'{type(error).__name__}: {error}')
        C.write_json(directory / 'summary.json', state)
        (B.OUT / 'latest-power-run.txt').write_text(str(directory)+'\n')


if __name__ == '__main__':
    main()
