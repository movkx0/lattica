"""Read-only Linux worker observations, never a lifetime/RSS admission bound.

Arm before launching the coordinator. Discover its worker inside the unique fleet
cgroup before READY, then reconcile with the protocol's service identity. A pidfd
distinguishes leader exit from ordinary thread churn. Sampling is non-atomic and
can miss transient peaks; cgroup, RSS, PSS and virtual sizes are different metrics.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import threading
import time
import uuid


MAX_SMAPS_BYTES = 16 << 20
MAX_MAPPING_GROUPS = 4096
MAPPING_FIELDS = ('Size', 'Rss', 'Pss', 'Private_Clean', 'Private_Dirty',
                  'Shared_Clean', 'Shared_Dirty', 'Anonymous', 'Swap')


def mapping_category(name):
    # A pathname hint, not proof of ownership (including the anonymous group).
    if name == '[heap]':
        return 'heap'
    if name.startswith('[stack'):
        return 'labeled_stack'
    if any(s in name.lower() for s in
           ('libnvidia', 'libcuda', 'libopencl', '/dev/nvidia', 'libamd', 'libhsa')):
        return 'driver_backed'
    if name.startswith(('/dev/shm/', '/SYSV', '/memfd:', 'memfd:')):
        return 'shared_backing'
    if name.startswith('/'):
        return 'other_file'
    if not name or name.startswith('[anon'):
        return 'anonymous_unattributed'
    return 'kernel_special'


def read_smaps(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_SMAPS_BYTES + 1)
    if len(data) > MAX_SMAPS_BYTES:
        raise ValueError('smaps exceeds observation limit')
    # Linux pathnames need not be UTF-8. Preserve their bytes in JSON via escaped
    # surrogate characters instead of conflating distinct replacement strings.
    return data.decode('utf-8', errors='surrogateescape')


def mapping_details(text):
    """Aggregate one smaps read by backing identity, permissions and VM flags.

    Device/inode/path are observations, not stable identities across time or
    authenticated ownership. Private/shared RSS describe page accounting, not
    mapping permissions. These samples do not establish RLIMIT_DATA coverage,
    complete driver/pinned ownership, cgroup charges or lifetime admission.
    """
    groups = {}
    current = None
    fields = (*MAPPING_FIELDS, 'Locked')
    header = re.compile(r'^([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) '
                        r'([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) ([0-9]+)(?:\s+(.*))?$')

    def finish():
        if current is None:
            return
        if set(current['kib']) != set(fields) or 'vm_flags' not in current:
            raise ValueError('incomplete smaps mapping')
        key = (current['path'], current['device'], current['inode'],
               current['permissions'], tuple(current['vm_flags']))
        if key not in groups:
            if len(groups) >= MAX_MAPPING_GROUPS:
                raise ValueError('smaps backing groups exceed observation limit')
            groups[key] = dict(current, mappings=0, kib={field: 0 for field in fields})
        row = groups[key]
        row['mappings'] += 1
        for field in fields:
            row['kib'][field] += current['kib'][field]

    for line in text.splitlines():
        match = header.fullmatch(line)
        if match:
            finish()
            start, end, permissions, _, device, inode, name = match.groups()
            if int(start, 16) >= int(end, 16):
                raise ValueError('invalid smaps mapping extent')
            name = name or ''
            current = dict(path=name, device=device, inode=int(inode),
                           permissions=permissions, category=mapping_category(name), kib={})
        else:
            key, sep, value = line.partition(':')
            if current is None or not sep or not re.fullmatch(r'[A-Za-z_]+', key):
                raise ValueError('invalid smaps mapping record')
            if key == 'VmFlags':
                if 'vm_flags' in current:
                    raise ValueError('duplicate smaps VM flags')
                current['vm_flags'] = sorted(value.split())
                if len(set(current['vm_flags'])) != len(current['vm_flags']):
                    raise ValueError('duplicate smaps VM flag')
            elif key in fields:
                if key in current['kib'] or not re.fullmatch(r'\s*[0-9]+ kB', value):
                    raise ValueError('invalid smaps residency field')
                current['kib'][key] = int(value.split()[0])
    finish()
    return [groups[key] for key in sorted(groups)]


def start_ticks(stat):
    # comm may itself contain spaces and closing parentheses.
    return int(stat.rsplit(')', 1)[1].split()[19])


def numeric_status(text):
    wanted = {'VmPeak', 'VmSize', 'VmHWM', 'VmRSS', 'RssAnon', 'RssFile',
              'RssShmem', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmPTE',
              'VmSwap', 'Threads'}
    return {key: int(value.split()[0]) for key, value in
            (line.split(':', 1) for line in text.splitlines()) if key in wanted}


def mapping_residency(text):
    """Group smaps by backing, without pretending anonymous maps are all stacks."""
    totals = {}
    category = None
    fields = MAPPING_FIELDS
    for line in text.splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line):
            parts = line.split(None, 5)
            name = parts[5] if len(parts) == 6 else ''
            category = mapping_category(name)
            totals.setdefault(category, {key: 0 for key in fields})
        elif category is not None:
            key, sep, value = line.partition(':')
            if sep and key in fields:
                totals[category][key] += int(value.split()[0])
    return totals


def task_snapshot(root):
    tasks, vanished = {}, []
    for task in sorted((root / 'task').iterdir()):
        try:
            before = start_ticks((task / 'stat').read_text())
            name = (task / 'comm').read_text().strip()
            if start_ticks((task / 'stat').read_text()) != before:
                vanished.append(int(task.name))
            else:
                tasks[task.name] = {'name': name, 'start_ticks': before}
        except (FileNotFoundError, ProcessLookupError):
            vanished.append(int(task.name))
    return tasks, vanished


def check_identity(observed, reported):
    for key in ('pid', 'start_ticks', 'group', 'device', 'inode', 'boot'):
        if observed[key] != reported[key]:
            raise ValueError(f'worker identity changed: {key}')


class RuntimeObserver:
    def __init__(self, directory, fleet_group, executable, *, interval=0.25, duration=185,
                 include_mapping_details=False):
        if not 0.05 <= interval <= 1 or not 1 <= duration <= 190:
            raise ValueError('bounded sampling interval/duration required')
        self.directory = Path(directory)
        self.fleet = Path(fleet_group)
        if not self.fleet.is_absolute() or '..' in self.fleet.parts:
            raise ValueError('absolute fleet cgroup required')
        if (self.directory / 'service-identity.json').exists():
            raise ValueError('observer must be armed before this worker starts')
        stat = Path(executable).stat()
        self.executable = (stat.st_dev, stat.st_ino)
        self.interval, self.duration = interval, duration
        self.include_mapping_details = include_mapping_details
        self.stop_event, self.armed = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self._run, name='worker-observer', daemon=True)
        self.pidfd = None
        self.group = None
        self.observed = None
        self.result = {'schema': 'lattica-worker-runtime-observation-v1',
                       'observation_only': True, 'establishes_rss_bound': False,
                       'interval_seconds': interval, 'samples': [], 'errors': [],
                       'interrupted_samples': 0, 'pidfd_exit_observed': False,
                       'pre_attach_permission_retries': 0,
                       'protocol_identity_verified': False,
                       'non_atomic_samples': True,
                       'boot': list(uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip()).bytes)}
        if include_mapping_details:
            self.result['mapping_detail_schema'] = 'lattica-smaps-backing-v1'
            self.result['mapping_details_are_ownership_bounds'] = False

    def start(self):
        self.thread.start()
        if not self.armed.wait(5):
            raise RuntimeError('observer did not arm')

    def finish(self, output):
        self.stop_event.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError('observer did not stop')
        with Path(output).open('x') as stream:
            json.dump(self.result, stream, indent=2)
            stream.write('\n')
        return self.result

    def _identity(self, pid):
        root = Path('/proc') / str(pid)
        group = (root / 'cgroup').read_text().splitlines()
        expected = '/' + str(self.group.relative_to('/sys/fs/cgroup'))
        if group != ['0::' + expected]:
            raise ValueError('worker left assigned cgroup')
        stat = self.group.stat()
        exe = (root / 'exe').stat()
        if (exe.st_dev, exe.st_ino) != self.executable:
            raise ValueError('worker executable changed')
        return {'pid': pid, 'start_ticks': start_ticks((root / 'stat').read_text()),
                'group': expected, 'device': stat.st_dev, 'inode': stat.st_ino,
                'boot': self.result['boot']}

    def _discover(self):
        if self.group is None:
            path = self.directory / 'budget.json'
            try:
                with path.open('rb') as stream:
                    data = stream.read((1 << 20) + 1)
            except FileNotFoundError:
                return
            if len(data) > 1 << 20:
                raise ValueError('oversized assignment')
            try:
                budget = json.loads(data)
            except json.JSONDecodeError:
                return  # The coordinator may still be writing its assignment.
            unit = budget['unit']
            if (not re.fullmatch(r'lattica-v2-multi-persistent-[0-9a-f]{64}\.service', unit)
                    or budget['slice'] != self.fleet.name):
                raise ValueError('unexpected worker unit/fleet')
            self.group = Path('/sys/fs/cgroup') / str(self.fleet).lstrip('/') / unit
            self.result['assignment_sha256'] = hashlib.sha256(data).hexdigest()
        try:
            candidates = [int(pid) for pid in (self.group / 'cgroup.procs').read_text().split()]
        except FileNotFoundError:
            return
        for pid in candidates:
            try:
                stat = (Path('/proc') / str(pid) / 'exe').stat()
            except PermissionError:
                # systemd's executor can be non-dumpable before exec. Retry only
                # discovery; a denied read after attachment is an observation error.
                self.result['pre_attach_permission_retries'] += 1
                continue
            except (FileNotFoundError, ProcessLookupError):
                continue
            try:
                if (stat.st_dev, stat.st_ino) != self.executable:
                    continue  # systemd may not have exec'd the service yet.
                observed = self._identity(pid)
                fd = os.pidfd_open(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            try:
                check_identity(observed, self._identity(pid))
            except BaseException:
                os.close(fd)
                raise
            self.pidfd, self.observed = fd, observed
            self.result['observed_identity'] = observed
            self.result['attached_monotonic_ns'] = time.monotonic_ns()
            self.result['first_observed_process_age_seconds'] = (
                time.clock_gettime(time.CLOCK_BOOTTIME) - observed['start_ticks'] / os.sysconf('SC_CLK_TCK'))
            self.result['process_limits'] = (Path('/proc') / str(pid) / 'limits').read_text()
            return

    def _exited(self, timeout=0):
        if self.pidfd is None:
            return False
        if select.select([self.pidfd], [], [], timeout)[0]:
            self.result['pidfd_exit_observed'] = True
            self.result.setdefault('exit_observed_monotonic_ns', time.monotonic_ns())
            return True
        return False

    def _protocol_identity(self):
        if self.observed is None or self.result['protocol_identity_verified']:
            return
        try:
            reported = json.loads((self.directory / 'service-identity.json').read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return
        check_identity(self.observed, reported)
        self.result['protocol_identity_verified'] = True
        self.result['protocol_identity'] = reported
        self.result['ready_identity_observed_monotonic_ns'] = time.monotonic_ns()

    def _sample(self):
        started = time.monotonic_ns()
        pid = self.observed['pid']
        root = Path('/proc') / str(pid)
        check_identity(self.observed, self._identity(pid))
        self._protocol_identity()
        smaps = read_smaps(root / 'smaps')
        sample = {'monotonic_ns': started, 'time_ns': time.time_ns(),
                  'protocol_ready_observed': self.result['protocol_identity_verified'],
                  'status_kib_except_threads': numeric_status((root / 'status').read_text()),
                  'mapping_kib': mapping_residency(smaps),
                  'smaps_rollup': (root / 'smaps_rollup').read_text(),
                  'process_limits': (root / 'limits').read_text(),
                  'cgroup': {name: (self.group / name).read_text().strip() for name in
                             ('memory.current', 'memory.peak', 'memory.stat', 'memory.events',
                              'memory.swap.current', 'memory.swap.peak', 'memory.max',
                              'memory.swap.max', 'cpu.max', 'pids.current')}}
        if self.include_mapping_details:
            sample['mapping_details'] = mapping_details(smaps)
        sample['tasks'], sample['vanished_tasks'] = task_snapshot(root)
        check_identity(self.observed, self._identity(pid))
        sample['sample_duration_ns'] = time.monotonic_ns() - started
        self.result['samples'].append(sample)

    def _run(self):
        self.result['armed_monotonic_ns'] = time.monotonic_ns()
        self.armed.set()
        deadline = time.monotonic() + self.duration
        try:
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                if self.observed is None:
                    self._discover()
                if self.observed is not None:
                    self._protocol_identity()
                    if self._exited():
                        break
                    try:
                        self._sample()
                    except (FileNotFoundError, ProcessLookupError):
                        self.result['interrupted_samples'] += 1
                        # /proc/exe and mappings can disappear while the kernel
                        # is still finishing exit, before the pidfd is readable.
                        # Accept only that authoritative exit event, with a
                        # short grace period inside the observation deadline.
                        if not self._exited(timeout=min(0.25, max(0, deadline - time.monotonic()))):
                            raise  # A missing thread is handled separately in task_snapshot.
                        break
                self.stop_event.wait(self.interval if self.observed else 0.01)
            self._protocol_identity()
            self._exited()
            self.result['ended'] = ('pidfd_exit' if self.result['pidfd_exit_observed'] else
                                    'stopped' if self.stop_event.is_set() else 'deadline')
        except Exception as error:
            self.result['errors'].append(f'{type(error).__name__}: {error}')
            self.result['ended'] = 'error'
        finally:
            self.result['finished_monotonic_ns'] = time.monotonic_ns()
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
