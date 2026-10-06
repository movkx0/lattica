"""Durable admission for one coordinator service, including incomplete bootstrap.

The guard conveys no proof-validity authority. An unfinished *new* journal can
be abandoned only before the Rust initialization marker and before any worker
reservation or accepted node. Recovery of an existing journal stays explicit.
"""
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys

G = importlib.import_module('block-v2-multi-gpu-run')
MAX_RECORD = 4 * 1024**2
_lifetime_fds = []


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD:
            raise ValueError('invalid coordinator bootstrap record')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(MAX_RECORD + 1)
        if len(data) > MAX_RECORD:
            raise ValueError('coordinator bootstrap record exceeds bound')
        return json.loads(data)
    finally:
        os.close(fd)


def unit_name(unit):
    if not re.fullmatch(r'lattica-v2-multi-owner-[0-9a-f]{64}\.service', unit):
        raise ValueError('invalid coordinator bootstrap service')


def gate_path(config):
    path = Path(config['coordinator_bootstrap_guard'])
    if not path.is_absolute() or path != Path(config['owner_directory']) / 'coordinator-startup':
        raise ValueError('coordinator bootstrap guard differs from owner directory')
    if path.is_symlink():
        raise ValueError('coordinator bootstrap directory is a symlink')
    return path


def lock(path):
    fd = os.open(path / 'lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size:
            raise ValueError('invalid coordinator bootstrap lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def observation(unit):
    unit_name(unit)
    output = G.systemctl('show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ControlGroup')
    state = dict(line.split('=', 1) for line in output.splitlines())
    for key in ('MainPID', 'ControlPID'):
        state[key] = int(state[key])
    return state


def birth(pid):
    return int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])


def boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def group_path(group, unit):
    path = Path(group)
    if not path.is_absolute() or '..' in path.parts or path.name != unit:
        raise ValueError('coordinator bootstrap cgroup differs from service')
    return Path('/sys/fs/cgroup') / str(path).lstrip('/')


def intent(config_path, config, path):
    value = read(path / 'intent.json')
    unit_name(value['unit'])
    if (value['schema_version'] != 1 or value['unit'] != config['owner_unit']
            or value['config_path'] != str(config_path)
            or value['config_sha256'] != G.digest(config_path)
            or value['plan_path'] != config['fleet_plan']
            or value['plan_sha256'] != G.digest(Path(config['fleet_plan']))
            or value['plan_text'] != Path(config['fleet_plan']).read_text()
            or value['proofs'] != str(Path(config['owner_directory']) / 'proofs')):
        raise ValueError('coordinator bootstrap intent or pinned inputs changed')
    return value


def create(config_path, controller_path):
    config_path = Path(config_path).resolve(strict=True)
    config = read(config_path)
    path = gate_path(config)
    unit_name(config['owner_unit'])
    path.mkdir(mode=0o700)
    fd = os.open(path / 'lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    value = dict(schema_version=1, unit=config['owner_unit'], config_path=str(config_path),
        config_sha256=G.digest(config_path), plan_path=config['fleet_plan'],
        plan_sha256=G.digest(Path(config['fleet_plan'])), plan_text=Path(config['fleet_plan']).read_text(),
        proofs=str(Path(config['owner_directory']) / 'proofs'),
        executable_sha256=G.digest(Path(sys.executable)),
        command=[sys.executable, str(controller_path), '--owner', str(config_path)])
    G.durable(path / 'intent.json', value, True)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def enter(config_path):
    config_path = Path(config_path).resolve(strict=True)
    config = read(config_path)
    importlib.import_module('block_v2_controller_bootstrap').require_owner_authorized(config_path, config)
    if not config.get('coordinator_bootstrap_guard'):
        return None  # Retained legacy plans use the existing full-journal path.
    path = gate_path(config)
    value = intent(config_path, config, path)
    fd = lock(path)
    try:
        if (path / 'revoked.json').exists() or (path / 'started.json').exists():
            raise ValueError('coordinator bootstrap was revoked or already consumed')
        command = Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if ([os.fsdecode(arg) for arg in command] != value['command']
                or G.digest(Path('/proc/self/exe')) != value['executable_sha256']):
            raise ValueError('coordinator bootstrap executable or arguments differ')
        state = observation(value['unit'])
        if (state['ActiveState'] != 'active' or state['SubState'] != 'running'
                or state['MainPID'] != os.getpid() or not state['InvocationID']
                or os.environ.get('INVOCATION_ID') != state['InvocationID']
                or Path('/proc/self/cgroup').read_text().strip() != '0::' + state['ControlGroup']):
            raise ValueError('coordinator bootstrap requires its exact owner service')
        group = group_path(state['ControlGroup'], value['unit'])
        info = group.stat()
        started = dict(pid=os.getpid(), start_ticks=birth(os.getpid()), boot=boot(),
            invocation=state['InvocationID'], group=state['ControlGroup'],
            device=info.st_dev, inode=info.st_ino, unit=value['unit'])
        G.durable(path / 'started.json', started, True)
        # Raw fd intentionally survives local cleanup until OS process exit.
        _lifetime_fds.append(fd)
        return started
    except BaseException:
        os.close(fd)
        raise


def quiescent(state, unit, started):
    if (state['ActiveState'] not in ('inactive', 'failed') or state['MainPID']
            or state['ControlPID'] or state['Job']):
        raise ValueError('old coordinator bootstrap service is not quiescent')
    groups = set()
    if state['ControlGroup']:
        groups.add(state['ControlGroup'])
    if started is not None:
        if started['unit'] != unit or type(started['pid']) is not int or started['pid'] <= 0:
            raise ValueError('invalid retained coordinator bootstrap identity')
        if boot() == started['boot']:
            try:
                same_process = birth(started['pid']) == started['start_ticks']
            except FileNotFoundError:
                same_process = False
            if same_process:
                raise ValueError('old coordinator bootstrap process is still alive')
            if state['InvocationID'] and state['InvocationID'] != started['invocation']:
                raise ValueError('coordinator bootstrap service invocation changed')
            group = group_path(started['group'], unit)
            if group.exists():
                info = group.stat()
                if (info.st_dev, info.st_ino) != (started['device'], started['inode']):
                    raise ValueError('coordinator bootstrap cgroup identity changed')
                groups.add(started['group'])
    for value in groups:
        group = group_path(value, unit)
        if group.exists() and any(p.read_text().strip() for p in group.rglob('cgroup.procs')):
            raise ValueError('coordinator bootstrap cgroup still contains processes')


def incomplete_new_candidate(config, plan):
    if (config.get('recover_from') or plan.get('recover_from') or config.get('recover_cached_only')
            or plan.get('recover_cached_only') or config.get('preseal_only') or plan.get('preseal_only')
            or config.get('reuse_preseal') or plan.get('reuse_preseal')):
        raise ValueError('incomplete bootstrap of an existing journal requires journal recovery')
    proofs = Path(config['owner_directory']) / 'proofs'
    runtime = proofs / 'execution'
    if any(path.is_symlink() for path in (proofs, runtime, runtime / 'artifacts', runtime / 'launches')):
        raise ValueError('incomplete coordinator bootstrap contains a substituted directory')
    prohibited = [*proofs.glob('node.*'), *runtime.glob('worker-*.session'),
        *runtime.glob('worker-*-start.json'), *runtime.glob('worker-*-startup/authorization.json'),
        *runtime.glob('worker-*-startup/started.json'), *runtime.glob('artifacts/n-*.proof')]
    prohibited += [p for p in (runtime / 'launches').glob('*') if p.name != '.owner.lock']
    if prohibited or (proofs / 'result.json').exists():
        raise ValueError('incomplete coordinator bootstrap contains admitted or accepted work')


def incomplete_existing_recovery(config, plan):
    """Keep the original journal, including accepted proofs, across bootstrap."""
    source = plan.get('recover_from')
    if (not source or not Path(source).is_absolute() or config.get('recover_from') != source
            or not plan.get('startup_fenced') or config.get('preseal_only') or plan.get('preseal_only')
            or config.get('reuse_preseal') or plan.get('reuse_preseal')):
        raise ValueError('interrupted recovery lacks its original journal admission')
    proofs = Path(config['owner_directory']) / 'proofs'
    runtime = proofs / 'execution'
    if any(path.is_symlink() for path in (proofs, runtime)):
        raise ValueError('interrupted recovery contains substituted directory')
    prohibited = [*runtime.glob('worker-*.session'), *runtime.glob('worker-*-start.json'),
                  *runtime.glob('worker-*-startup/authorization.json'), *runtime.glob('worker-*-startup/started.json')]
    if prohibited or (proofs / 'result.json').exists():
        raise ValueError('interrupted recovery contains work admitted before initialization')
    admission_path = proofs / 'recovery-admission.json'
    admission = read(admission_path) if admission_path.exists() else None
    if admission is not None:
        state = read(proofs / 'recovery-state.json')
        if (admission.get('schema_version') != 1 or admission.get('source') != source
                or admission.get('state') != state or state.get('schema_version') != 1
                or type(state.get('epoch')) is not int or state['epoch'] < 2
                or not Path(state['durable_runtime']).is_absolute()
                or read(proofs / 'fleet-plan.json') != plan):
            raise ValueError('interrupted recovery metadata differs from durable admission')
        for name in ('coordinator.json', 'expected.json'):
            read(proofs / name)
    return dict(interrupted_existing_journal=True, recovery_admission=admission,
                retry_source=str(proofs) if admission is not None else source)


def reconcile(config_path):
    config_path = Path(config_path).resolve(strict=True)
    config = read(config_path)
    if not config.get('coordinator_bootstrap_guard'):
        return None
    path = gate_path(config)
    value = intent(config_path, config, path)
    before = observation(value['unit'])
    # Do not interrupt an active run merely because recovery was requested.
    quiescent(before, value['unit'], None)
    revocation = dict(schema_version=1, intent_sha256=G.digest(path / 'intent.json'))
    if (path / 'revoked.json').exists():
        if read(path / 'revoked.json') != revocation:
            raise ValueError('coordinator bootstrap revocation changed')
    else:
        G.durable(path / 'revoked.json', revocation, True)
    fd = lock(path)
    try:
        value = intent(config_path, config, path)
        started = read(path / 'started.json') if (path / 'started.json').exists() else None
        after = observation(value['unit'])
        quiescent(after, value['unit'], started)
        if before != after:
            raise ValueError('coordinator bootstrap service changed during reconciliation')
        initialized = read(path / 'initialized.json') if (path / 'initialized.json').exists() else None
        if initialized is not None:
            if (started is None or initialized.get('schema_version') != 1
                    or initialized.get('plan_sha256') != value['plan_sha256']
                    or initialized.get('proofs') != value['proofs']
                    or initialized.get('owner_pid') != started['pid']
                    or type(initialized.get('coordinator_pid')) is not int):
                raise ValueError('coordinator initialization marker differs from admission')
        recovery = {}
        if initialized is None:
            plan = read(config['fleet_plan'])
            if plan.get('recover_from'):
                recovery = incomplete_existing_recovery(config, plan)
            else:
                incomplete_new_candidate(config, plan)
        return dict(schema_version=1, guard=str(path), unit=value['unit'],
            intent_sha256=G.digest(path / 'intent.json'), started=started, initialized=initialized,
            future_entry_fenced=True, process_and_service_quiescent=True,
                    abandoned_incomplete_new_candidate=initialized is None and not recovery,
                    **recovery,
            accepted_proofs_discarded=0, gpu_workers_started_before_initialization=0)
    finally:
        os.close(fd)
