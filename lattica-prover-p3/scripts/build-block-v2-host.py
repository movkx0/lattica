#!/usr/bin/env python3
"""Link the opt-in native replay/fixture bridge to a supplied Rust library.

Run only between timed campaigns. Build the Rust static library first with
--no-default-features --features block-v2-host,stream. For Linux GPU wallet
callers, add gpu and pass --gpu-backend opencl, or add gpu-cuda and pass
--gpu-backend cuda. The existing --gpu flag still selects OpenCL. GPU startup
and resource admission remain explicit responsibilities of the wallet caller.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]


def pin(path):
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'bytes': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-staticlib', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--block-capacity', type=int, choices=(64, 128), default=64, help='must match the Rust block profile; 128 needs block-v2-capacity-128')
    parser.add_argument('--gpu', action='store_true', help='link the Linux OpenCL wallet bridge')
    parser.add_argument('--gpu-backend', choices=('opencl', 'cuda'),
                        help='explicit Linux GPU backend; must match the supplied Rust library')
    args = parser.parse_args()
    gpu_backend = args.gpu_backend or ('opencl' if args.gpu else None)
    system = platform.system()
    if system not in ('Linux', 'Darwin'):
        parser.error('this research bridge currently targets Linux and macOS')
    if gpu_backend and system != 'Linux':
        parser.error('GPU wallet bridges currently require Linux')
    library = args.rust_staticlib.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    obj = out / 'host-bridge.o'
    linked = out / ('liblattica_host_bridge.dylib' if system == 'Darwin' else 'liblattica_host_bridge.so')
    commands = [
        ['zig', 'build-obj', str(ROOT / ('src/block_v2_host_bridge_128.zig' if args.block_capacity == 128 else 'src/block_v2_host_bridge.zig')), '-O', 'ReleaseSafe',
         '-fPIC', '-fcompiler-rt', '-femit-bin=' + str(obj)],
        (['cc', '-dynamiclib', '-Wl,-undefined,error', '-o', str(linked), str(obj), str(library), '-lpthread', '-lm']
         if system == 'Darwin' else
         ['cc', '-shared', '-Wl,-z,defs', '-o', str(linked), str(obj), str(library),
          '-lpthread', '-ldl', '-lm', '-lrt', '-lutil', '-lgcc_s']),
    ]
    if gpu_backend == 'opencl':
        commands[-1].append('-lOpenCL')
    report = {'schema_version': 1, 'status': 'running', 'platform': system,
              'gpu_linked': gpu_backend is not None, 'gpu_backend': gpu_backend,
              'block_capacity': args.block_capacity,
              'rust_staticlib': pin(library), 'commands': [], 'production_ready': False,
              'sources': [pin(p) for p in sorted((ROOT / 'src').glob('*.zig'))] + [pin(Path(__file__))]}
    started = time.monotonic()
    for index, command in enumerate(commands, 1):
        log = out / f'build-{index}.log'
        with log.open('x') as handle:
            result = subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT)
        report['commands'].append({'command': command, 'exit_code': result.returncode, 'log': pin(log)})
        if result.returncode:
            report['status'] = 'failed'
            break
    else:
        report['status'] = 'succeeded'
        report['library'] = pin(linked)
    if report['status'] == 'succeeded':
        host = ctypes.CDLL(str(linked))
        capacity = host.lattica_v2_research_host_capacity_v1
        capacity.argtypes = []
        capacity.restype = ctypes.c_uint32
        report['observed_block_capacity'] = capacity()
        if report['observed_block_capacity'] != args.block_capacity:
            report.update(status='failed', error='native/Rust block capacity mismatch')
    report['elapsed_seconds'] = time.monotonic() - started
    (out / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'manifest': str(out / 'manifest.json'),
                      'library': report.get('library')}))
    return int(report['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
