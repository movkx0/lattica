#!/usr/bin/env python3
"""Prepare a fresh two-worker experiment from its validated source/binary snapshot.

Add --run to execute the copied bounded controller. This reuses inputs and
binaries, never proof outputs. The complete original evidence must be present.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text())


def prepare(source, out):
    if read(source / 'summary.json')['status'] != 'passed' or read(source / 'completion.json')['status'] != 'completed':
        raise ValueError('source experiment must have completed and passed its reporter')
    if out.exists() or out.parent != source.parent:
        raise ValueError('output must be a new sibling of the source experiment')
    for name, directory in [('source-manifest.json', source), ('control-manifest.json', source / 'control'),
                            ('fixture-manifest.json', source / 'fixture'), ('support-pins.json', Path('/')),
                            ('binary-manifest.json', Path('/'))]:
        for filename, digest in read(source / name).items():
            if sha(directory / filename) != digest:
                raise ValueError('pinned source changed: ' + filename)
    if sha(source / 'bin-gpu/capacity-128-benchmark') != read(source / 'binary-manifest.json')[str(source / 'bin-gpu/capacity-128-benchmark')]:
        raise ValueError('source GPU binary differs')
    out.mkdir(mode=0o700)
    for directory in ['source', 'control', 'bin-gpu', 'fixture', 'driver-cache']:
        subprocess.run(['cp', '-a', '--reflink=auto', str(source / directory), str(out / directory)], check=True)
    for name in ['source-manifest.json', 'control-manifest.json', 'fixture-manifest.json',
                 'expected.json', 'proof-plan.json', 'source.patch']:
        shutil.copy2(source / name, out / name)
    for name in ['scope.json', 'patch-reconstruction.json']:
        if (source / name).exists():
            shutil.copy2(source / name, out / name)
    # These are validation receipts for unchanged copied source, not new tests.
    if (source / 'tests').is_dir():
        (out / 'tests').mkdir()
        for path in (source / 'tests').iterdir():
            if path.is_file() and path.suffix in ('.json', '.log'):
                shutil.copy2(path, out / 'tests' / path.name)
    pins = {}
    for filename, digest in read(source / 'support-pins.json').items():
        path = Path(filename)
        if path.is_relative_to(source):
            path = out / path.relative_to(source)
        if sha(path) != digest:
            raise ValueError('copied support changed: ' + str(path))
        pins[str(path)] = digest
    (out / 'support-pins.json').write_text(json.dumps(pins, indent=2) + '\n')
    (out / 'repeat-origin.json').write_text(json.dumps(dict(source_run=str(source),
        summary_sha256=sha(source / 'summary.json'), binary_manifest_sha256=sha(source / 'binary-manifest.json'),
        proofs_reused=False), indent=2) + '\n')
    return out / 'control/benchmark.py'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_run', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    controller = prepare(args.source_run.resolve(), args.output.resolve())
    print('Prepared:', controller, flush=True)
    if args.run:
        subprocess.run([sys.executable, str(controller)], check=True)
