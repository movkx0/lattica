"""Controller admission before native preparation or GPU resource planning.

The foreground launcher and controller each retain a lifetime lock. Owner
services require a durable handoff and are bound to the controller service.
All interrupted directories are retained; a new invocation gets a new directory.
"""

import fcntl
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

B = importlib.import_module('block_v2_coordinator_bootstrap')
G = B.G
_lifetime_fds = []
MODES = {'owner', 'launch_worker', 'controller_request', 'recover_controller',
         'supervise', 'supervisor_request', 'supervisor_accounting'}
ARGUMENT_OMISSIONS = MODES | {'supervisor_max_restarts', 'supervisor_restart_delay'}


def read(path):
    return B.read(path)


def publish(path, value):
    """A partial write is never interpreted as an admission or revocation."""
    path = Path(path)
    temporary = path.parent / ('.' + path.name + '-' + secrets.token_hex(16) + '.partial')
    G.durable(temporary, value, True)
    os.link(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
        temporary.unlink()
        os.fsync(fd)
    finally:
        os.close(fd)


def unit_name(unit):
    if not isinstance(unit, str) or not re.fullmatch(r'lattica-v2-controller-[0-9a-f]{64}\.service', unit):
        raise ValueError('invalid controller admission service')


def observation(unit):
    unit_name(unit)
    output = G.systemctl('show', unit,
        '--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID,ControlGroup')
    state = dict(line.split('=', 1) for line in output.splitlines())
    for name in ('MainPID', 'ControlPID'):
        state[name] = int(state[name])
    return state


def lock(gate, name):
    fd = os.open(gate / name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size:
            raise ValueError('unsafe controller lifetime lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def guard(directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise ValueError('controller recovery requires its canonical absolute directory')
    gate = directory / 'controller-startup'
    for path in (directory, gate):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('unsafe controller admission directory')
    return gate


def check_pins(pins):
    if not isinstance(pins, dict) or not pins:
        raise ValueError('controller admission lacks input pins')
    for name, digest in pins.items():
        path = Path(name)
        if not path.is_absolute() or G.digest(path) != digest:
            raise ValueError('controller admission input changed: ' + name)


def arguments(args):
    result = []
    for name, value in sorted(vars(args).items()):
        if name in ARGUMENT_OMISSIONS or name.startswith('_') or value is None or value is False:
            continue
        flag = '--' + name.replace('_', '-')
        values = value if isinstance(value, list) else [value]
        for item in values:
            result.append(flag)
            if item is not True:
                result.append(str(item.resolve() if isinstance(item, Path) else item))
    return result


def intent(path):
    path = Path(path)
    gate = guard(path.parent.parent)
    value = read(path)
    unit_name(value.get('unit'))
    if (path != gate / 'intent.json' or value.get('schema_version') != 1
            or value.get('evidence') != str(gate.parent)
            or value.get('command') != [value.get('executable'), value.get('script'), '--controller-request', str(path)]
            or not Path(value['cwd']).is_absolute()
            or G.digest(Path(value['executable'])) != value.get('executable_sha256')
            or not isinstance(value.get('arguments'), list)
            or not all(isinstance(arg, str) for arg in value['arguments'])):
        raise ValueError('controller admission differs from its immutable request')
    check_pins(value['pins'])
    return gate, value


def create(args, script, pins, recovered=None):
    directory = args.evidence.resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    gate = directory / 'controller-startup'
    gate.mkdir(mode=0o700)
    for name in ('launcher.lock', 'lock'):
        fd = os.open(gate / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    launcher = lock(gate, 'launcher.lock')
    # An integer fd intentionally survives Python teardown until OS process exit.
    _lifetime_fds.append(launcher)
    if (gate / 'revoked.json').exists():
        raise ValueError('controller launcher has been revoked')
    publish(gate / 'launcher-started.json', dict(schema_version=1, pid=os.getpid(),
        start_ticks=B.birth(os.getpid()), boot=B.boot()))
    path = gate / 'intent.json'
    executable = str(Path(sys.executable).resolve(strict=True))
    script = str(Path(script).resolve(strict=True))
    value = dict(schema_version=1, unit='lattica-v2-controller-' + secrets.token_hex(32) + '.service',
        evidence=str(directory), cwd=str(Path.cwd().resolve()), executable=executable,
        executable_sha256=G.digest(Path(executable)), script=script, arguments=arguments(args),
        command=[executable, script, '--controller-request', str(path)], pins=pins,
        recovered_controller=recovered)
    check_pins(pins)
    if pins.get(script) != G.digest(Path(script)) or (gate / 'revoked.json').exists():
        raise ValueError('controller launcher code changed or was revoked')
    publish(path, value)
    return path, value


def enter(path, parser, script):
    gate, value = intent(path)
    fd = lock(gate, 'lock')
    try:
        if (gate / 'revoked.json').exists() or (gate / 'started.json').exists():
            raise ValueError('controller admission revoked or already consumed')
        command = [os.fsdecode(arg) for arg in Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').split(b'\0')]
        state = observation(value['unit'])
        if (command != value['command'] or str(Path(script).resolve()) != value['script']
                or G.digest(Path('/proc/self/exe')) != value['executable_sha256']
                or state['ActiveState'] != 'active' or state['SubState'] != 'running'
                or state['MainPID'] != os.getpid() or not state['InvocationID']
                or os.environ.get('INVOCATION_ID') != state['InvocationID']
                or str(Path.cwd().resolve()) != value['cwd']
                or Path('/proc/self/cgroup').read_text().strip() != '0::' + state['ControlGroup']):
            raise ValueError('controller admission requires its exact executable and service')
        group = B.group_path(state['ControlGroup'], value['unit'])
        info = group.stat()
        started = dict(pid=os.getpid(), start_ticks=B.birth(os.getpid()), boot=B.boot(),
            invocation=state['InvocationID'], group=state['ControlGroup'],
            device=info.st_dev, inode=info.st_ino, unit=value['unit'])
        args = parser.parse_args(value['arguments'])
        if (any(getattr(args, name, None) is not None and getattr(args, name) is not False for name in MODES)
                or args.evidence.resolve() != gate.parent):
            raise ValueError('controller request contains another entry mode or output directory')
        publish(gate / 'started.json', started)
        _lifetime_fds.append(fd)
        return args, dict(gate=str(gate), unit=value['unit'], intent_sha256=G.digest(gate / 'intent.json'))
    except BaseException:
        os.close(fd)
        raise


def authorize(control, config_path):
    gate, value = intent(Path(control['gate']) / 'intent.json')
    config_path = Path(config_path).resolve(strict=True)
    config = read(config_path)
    started = read(gate / 'started.json')
    if (config_path != gate.parent / 'config.json' or config.get('controller_admission') != control
            or control['unit'] != value['unit'] or control['intent_sha256'] != G.digest(gate / 'intent.json')
            or started['pid'] != os.getpid() or started['start_ticks'] != B.birth(os.getpid())
            or started['boot'] != B.boot() or (gate / 'revoked.json').exists()):
        raise ValueError('controller owner handoff differs from the admitted process')
    owner_gate = B.gate_path(config)
    owner_intent = B.intent(config_path, config, owner_gate)
    publish(gate / 'owner-admission.json', dict(schema_version=1,
        controller_intent_sha256=control['intent_sha256'], config=str(config_path),
        config_sha256=G.digest(config_path), owner_unit=owner_intent['unit'],
        owner_intent_sha256=G.digest(owner_gate / 'intent.json')))


def require_owner_authorized(config_path, config):
    control = config.get('controller_admission')
    if control is None:
        return  # Retained legacy owners still use their existing admission gate.
    gate, value = intent(Path(control['gate']) / 'intent.json')
    admission = read(gate / 'owner-admission.json')
    if ((gate / 'revoked.json').exists() or control['unit'] != value['unit']
            or control['intent_sha256'] != G.digest(gate / 'intent.json')
            or admission.get('schema_version') != 1
            or admission.get('controller_intent_sha256') != control['intent_sha256']
            or admission.get('config') != str(config_path)
            or admission.get('config_sha256') != G.digest(config_path)
            or admission.get('owner_unit') != config['owner_unit']
            or admission.get('owner_intent_sha256') != G.digest(B.gate_path(config) / 'intent.json')):
        raise ValueError('owner lacks the exact controller handoff')
    state = observation(value['unit'])
    started = read(gate / 'started.json')
    if (state['ActiveState'] != 'active' or state['SubState'] != 'running'
            or state['MainPID'] != started['pid'] or state['InvocationID'] != started['invocation']
            or started['boot'] != B.boot() or B.birth(started['pid']) != started['start_ticks']):
        raise ValueError('owner controller is no longer the admitted live process')


def reconcile(directory):
    gate = guard(Path(directory).resolve(strict=True))
    # Never revoke a live foreground launch or an active/pending controller.
    launcher = lock(gate, 'launcher.lock')
    controller = None
    try:
        path = gate / 'intent.json'
        value = intent(path)[1] if path.exists() else None
        before = observation(value['unit']) if value else None
        if value:
            B.quiescent(before, value['unit'], None)
        revoked = dict(schema_version=1, intent_sha256=G.digest(path) if value else None)
        if (gate / 'revoked.json').exists():
            if read(gate / 'revoked.json') != revoked:
                raise ValueError('controller admission revocation changed')
        else:
            publish(gate / 'revoked.json', revoked)
        controller = lock(gate, 'lock')
        if value:
            started = read(gate / 'started.json') if (gate / 'started.json').exists() else None
            after = observation(value['unit'])
            B.quiescent(after, value['unit'], started)
            if before != after:
                raise ValueError('controller service changed during reconciliation')
        elif (gate / 'started.json').exists() or (gate / 'owner-admission.json').exists():
            raise ValueError('controller startup exists without a durable request')
        admission_path = gate / 'owner-admission.json'
        admission = read(admission_path) if admission_path.exists() else None
        owner = None
        if admission is not None:
            config_path = gate.parent / 'config.json'
            config = read(config_path)
            if (admission.get('schema_version') != 1
                    or admission.get('controller_intent_sha256') != G.digest(path)
                    or admission.get('config') != str(config_path)
                    or admission.get('config_sha256') != G.digest(config_path)
                    or admission.get('owner_unit') != config['owner_unit']
                    or config.get('controller_admission', {}).get('gate') != str(gate)
                    or admission.get('owner_intent_sha256') != G.digest(B.gate_path(config) / 'intent.json')):
                raise ValueError('retained owner handoff differs from controller admission')
            owner = B.reconcile(config_path)
        return dict(schema_version=1, source=str(gate.parent), intent=value,
            request_published=value is not None, controller_service_quiescent=True,
            future_controller_entry_fenced=True, future_owner_entry_fenced=True,
            owner_admission=admission, owner_bootstrap=owner,
            recovery_owner=str(gate.parent / 'owner') if admission else None,
            partial_files_retained=True, accepted_proofs_discarded=0)
    finally:
        if controller is not None:
            os.close(controller)
        os.close(launcher)


def recover(args, parser):
    receipt = reconcile(args.recover_controller)
    if receipt['intent'] is None:
        raise ValueError('controller stopped before its request was published; reuse the original command with a fresh evidence directory')
    recovered = parser.parse_args(receipt['intent']['arguments'])
    recovered.evidence = args.evidence
    if receipt['recovery_owner'] is not None:
        recovered.recover_owner = Path(receipt['recovery_owner'])
    recovered.recover_cached_only = recovered.recover_cached_only or args.recover_cached_only
    return recovered, receipt


def launch(args, script, pins, accounting, recovered=None):
    path, value = create(args, script, pins, recovered)
    gate = path.parent
    command = ['systemd-run', '--user', '--quiet', '--expand-environment=no', '--service-type=exec',
        '--wait', '--pipe', '--unit=' + value['unit'], '--working-directory=' + value['cwd'],
        '--property=MemoryMax=4G', '--property=MemorySwapMax=0', '--property=CPUQuota=100%',
        '--property=TasksMax=256', '--property=KillMode=control-group', '--property=OOMPolicy=kill',
        '--property=TimeoutStopSec=30', '--property=LimitCORE=0', '--property=UMask=0077',
        '--setenv=RAYON_NUM_THREADS=1',
        accounting(gate.parent), *value['command']]
    started = time.monotonic()
    if (gate / 'revoked.json').exists():
        raise ValueError('controller admission revoked before service launch')
    result = subprocess.run(command)
    state = observation(value['unit'])
    B.quiescent(state, value['unit'], read(gate / 'started.json') if (gate / 'started.json').exists() else None)
    publish(gate / 'launcher-result.json', dict(schema_version=1, returncode=result.returncode,
        elapsed_seconds=time.monotonic()-started, state=state, command=command))
    if result.returncode:
        raise SystemExit(result.returncode)
