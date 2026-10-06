#!/usr/bin/env python3
"""Link the opt-in native replay/fixture bridge to a supplied CPU Rust library.

Run only between timed campaigns. Build the Rust static library first with
--no-default-features --features block-v2-host,stream. No GPU library is needed.
"""
import argparse
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
    args = parser.parse_args()
    system = platform.system()
    if system not in ('Linux', 'Darwin'):
        parser.error('this research bridge currently targets Linux and macOS')
    library = args.rust_staticlib.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    obj = out / 'host-bridge.o'
    linked = out / ('liblattica_host_bridge.dylib' if system == 'Darwin' else 'liblattica_host_bridge.so')
    commands = [
        ['zig', 'build-obj', str(ROOT / 'src/block_v2_host_bridge.zig'), '-O', 'ReleaseSafe',
         '-fPIC', '-fcompiler-rt', '-femit-bin=' + str(obj)],
        (['cc', '-dynamiclib', '-Wl,-undefined,error', '-o', str(linked), str(obj), str(library), '-lpthread', '-lm']
         if system == 'Darwin' else
         ['cc', '-shared', '-Wl,-z,defs', '-o', str(linked), str(obj), str(library),
          '-lpthread', '-ldl', '-lm', '-lrt', '-lutil', '-lgcc_s']),
    ]
    report = {'schema_version': 1, 'status': 'running', 'platform': system,
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
    report['elapsed_seconds'] = time.monotonic() - started
    (out / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'manifest': str(out / 'manifest.json'),
                      'library': report.get('library')}))
    return int(report['status'] != 'succeeded')


if __name__ == '__main__':
    raise SystemExit(main())
