#!/usr/bin/env python3
"""Run a wallet-owned native application in one bounded Linux GPU service.

The assignment holds public resource metadata only. The native application
initializes the prover and handles its witnesses locally; this launcher does
not add a private-input queue, transport, or artifact store to the public pool.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import uuid


def launch(args):
    if sys.platform != 'linux':
        raise ValueError('wallet GPU workers require Linux cgroup v2')
    backend = getattr(args, 'gpu_backend', 'opencl')
    library_path = getattr(args, 'cuda_library_path', None)
    if backend not in ('opencl', 'cuda'):
        raise ValueError('wallet GPU backend must be opencl or cuda')
    if backend == 'cuda':
        if library_path is None:
            raise ValueError('CUDA requires --cuda-library-path for the NVRTC runtime')
        if args.storage != 'full':
            raise ValueError('--storage compact is an OpenCL setting')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lattica-prover-p3/scripts'))
        import block_v2_cuda_cli as Cuda
        cuda_runtime = Cuda.runtime(library_path)
    elif library_path is not None:
        raise ValueError('--cuda-library-path requires --gpu-backend cuda')
    if 'LATTICA_V2_WORKER_BUDGET' in os.environ or 'LATTICA_WALLET_WORKER_BUDGET' in os.environ:
        raise ValueError('launch from the wallet owner, outside an existing worker assignment')
    if not re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', args.gpu_uuid):
        raise ValueError('an explicit GPU UUID is required')
    if type(args.managed_gpu_gib) is not int or not 1 <= args.managed_gpu_gib <= 7:
        raise ValueError('managed GPU allowance must be between 1 and 7 GiB')
    if type(args.host_output_gib) is not int or not 1 <= args.host_output_gib <= 2:
        raise ValueError('host-output allowance must be between 1 and 2 GiB, leaving room for stacks, staging and retained heap')
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        raise ValueError('provide a native wallet application after --')
    binary = Path(command[0]).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('the wallet application must be an executable file')
    workdir = args.workdir.resolve(strict=True)
    if not workdir.is_dir():
        raise ValueError('the working directory must be a directory')
    state = args.state_dir.resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = state.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError('the assignment directory must be owned by this user with mode 0700')
    service = 'lattica-wallet-' + uuid.uuid4().hex + '.service'
    assignment = state / (service + '.json')
    budget = dict(schema='lattica-wallet-local-cuda-v1' if backend == 'cuda' else 'lattica-wallet-local-gpu-v1',
                  service=service, gpu_uuid=args.gpu_uuid,
                  host_bytes=3 << 30, threads=4, managed_gpu_bytes=args.managed_gpu_gib << 30,
                  context_gpu_bytes=4 << 30, host_output_bytes=args.host_output_gib << 30)
    if backend == 'cuda':
        budget['cuda'] = {'max_allocation_bytes': 1 << 30, 'headroom_bytes': 1 << 30}
    with os.fdopen(os.open(assignment, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as stream:
        json.dump(budget, stream, indent=2)
        stream.write('\n')
    environment = {
        'LATTICA_WALLET_WORKER_BUDGET': str(assignment),
        'LATTICA_PROVING_POLICY': 'gpu-required',
        'LATTICA_PROVING_REPORT': '1',
        'LATTICA_GPU_DEVICE_UUID': args.gpu_uuid,
        'LATTICA_GPU_BACKEND': backend,
        'LATTICA_V2_GPU_MANAGED_BYTES': str(budget['managed_gpu_bytes']),
        'LATTICA_V2_GPU_CONTEXT_BYTES': str(budget['context_gpu_bytes']),
        'LATTICA_V2_HOST_OUTPUT_BYTES': str(budget['host_output_bytes']),
        'RAYON_NUM_THREADS': '4',
        'CARGO_BUILD_JOBS': '4',
    }
    if backend == 'cuda':
        environment['LD_LIBRARY_PATH'] = cuda_runtime['library_directory']
    else:
        for suffix in ['HASH', 'RETAIN_TREES', 'RESIDENT_LDE', 'OPENINGS', 'QUOTIENT_LDE',
                       'QUOTIENT_EVAL', 'QUOTIENT_RESIDENT', 'LOOKUP', 'OPENING_EVAL',
                       'FRI_RESIDENT', 'PCS_DEVICE_ONLY', 'WITNESS', 'RANDOMNESS', 'TRANSCRIPT']:
            environment['LATTICA_V2_GPU_' + suffix] = '1'
        environment['LATTICA_V2_QUOTIENT_FUSION'] = '1'
        for suffix in ['DIRECT_READBACK', 'LDE_WORKSPACE_BYTES', 'FRI_FOLD', 'QUERY_GATHER',
                       'OPENING_DENOMINATOR_CACHE', 'OPENING_COMPACT', 'PIPELINE']:
            environment['LATTICA_V2_GPU_' + suffix] = '0'
        for suffix in ['COMPACT_PROVER_DATA', 'DIRECT_READBACK', 'OPENING_COMPACT', 'PARALLEL_READBACK']:
            environment['LATTICA_V2_GPU_' + suffix] = '1' if args.storage == 'compact' else '0'
    limits = ['MemoryMax=3G', 'MemorySwapMax=0', 'CPUQuota=400%', 'RuntimeMaxSec=180',
              'KillMode=control-group', 'LimitCORE=0', 'LimitSTACK=8M', 'TasksMax=96', 'TimeoutStopSec=10']
    invocation = ['systemd-run', '--user', '--wait', '--pipe', '--collect', '--service-type=exec',
                  '--unit=' + service, '--working-directory=' + str(workdir),
                  *['--property=' + p for p in limits],
                  *['--setenv=' + k + '=' + v for k, v in environment.items()],
                  str(binary), *command[1:]]

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    old_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        return subprocess.run(invocation, check=False).returncode
    except KeyboardInterrupt:
        # Stop the service, including descendants; retain its public assignment
        # even if the manager is unavailable. RuntimeMaxSec remains in force.
        subprocess.run(['systemctl', '--user', 'stop', service], check=False, timeout=15)
        return 130
    finally:
        signal.signal(signal.SIGTERM, old_handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gpu-backend', choices=['opencl', 'cuda'], default='opencl',
                        help='native backend matching the application library (default: opencl)')
    parser.add_argument('--cuda-library-path', type=Path,
                        help='CUDA 12.9 NVRTC library directory; required for CUDA')
    parser.add_argument('--gpu-uuid', required=True)
    parser.add_argument('--state-dir', type=Path, required=True,
                        help='owner-only directory retaining public resource assignments')
    parser.add_argument('--workdir', type=Path, default=Path.cwd())
    parser.add_argument('--storage', choices=['full', 'compact'], default='full')
    parser.add_argument('--managed-gpu-gib', type=int, choices=range(1, 8), default=1,
                        help='managed GPU allowance in GiB; context allowance remains 4 GiB')
    parser.add_argument('--host-output-gib', type=int, choices=range(1, 3), default=1,
                        help='host-output GiB, leaving room for stacks, staging and retained heap inside the 3 GiB process cap')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        return launch(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    sys.exit(main())
