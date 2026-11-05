"""Best-effort external utilization samples; never proof acceptance authority."""
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

GPU_FIELDS = ('uuid', 'utilization.gpu', 'utilization.memory', 'memory.used',
              'clocks.current.sm', 'clocks.current.memory', 'temperature.gpu', 'power.draw')


class Sampler:
    def __init__(self, path, gpu_uuid):
        self.path = Path(path)
        self.gpu_uuid = gpu_uuid
        self.started = time.monotonic_ns()
        self.samples = 0
        self.errors = 0
        self.previous = None
        self.write_error = None
        self.output = self.path.open('x')

    def sample(self, state):
        if self.write_error is not None:
            return
        now = time.monotonic_ns()
        row = dict(schema='ringct-workflow-telemetry-v1', since_start_ns=now - self.started,
                   gpu_uuid=self.gpu_uuid, errors=[])
        try:
            group = state.get('ControlGroup', '')
            if not group.startswith('/') or '..' in Path(group).parts:
                raise ValueError('no live cgroup')
            root = Path('/sys/fs/cgroup') / group.lstrip('/')
            counters = dict(line.split() for line in (root / 'cpu.stat').read_text().splitlines())
            usage = int(counters['usage_usec'])
            row.update(cpu_usage_usec=usage, cpu_user_usec=int(counters['user_usec']),
                       cpu_system_usec=int(counters['system_usec']),
                       memory_current_bytes=int((root / 'memory.current').read_text()),
                       memory_peak_bytes=int((root / 'memory.peak').read_text()))
            if self.previous is not None:
                previous_ns, previous_usage = self.previous
                row['cpu_percent_one_core'] = 100_000 * (usage - previous_usage) / (now - previous_ns)
            self.previous = now, usage
        except (OSError, ValueError, KeyError) as error:
            row['errors'].append('cgroup: ' + str(error))
        try:
            result = subprocess.run(['/usr/bin/nvidia-smi', '--id=' + self.gpu_uuid,
                '--query-gpu=' + ','.join(GPU_FIELDS), '--format=csv,noheader,nounits'],
                capture_output=True, text=True, timeout=2, check=True)
            values = [value.strip() for value in result.stdout.strip().split(',')]
            if len(values) != len(GPU_FIELDS) or values[0] != self.gpu_uuid:
                raise ValueError('unexpected GPU inventory')
            row['gpu'] = {name: float(value) if value not in ('N/A', '[N/A]', '[Not Supported]') else None
                          for name, value in zip(GPU_FIELDS[1:], values[1:])}
            if not all(value is None or math.isfinite(value) for value in row['gpu'].values()):
                raise ValueError('nonfinite GPU sample')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row.pop('gpu', None)
            row['errors'].append('gpu: ' + str(error))
        self.samples += 1
        self.errors += bool(row['errors'])
        try:
            self.output.write(json.dumps(row, allow_nan=False) + '\n')
            self.output.flush()
        except OSError as error:
            self.write_error = str(error)

    def finish(self):
        self.output.close()
        return dict(schema='ringct-workflow-telemetry-v1', path=str(self.path),
                    sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(), samples=self.samples,
                    samples_with_errors=self.errors, write_error=self.write_error, requested_interval_seconds=1,
                    scope='External cgroup CPU/RAM and whole-device GPU samples; not process-isolated GPU busy time.')
