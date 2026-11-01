"""Bounded call-stack collection for the exact CPU-only native catalogue."""
import hashlib
import os
from pathlib import Path
import re
import subprocess

from cpu_scaling_profile import require, validate as validate_scaling

MAX_BYTES = 512 << 20
FREQUENCY = 99
STACK_BYTES = 8192


def command(argv, destination):
    return ['/usr/bin/perf', 'record', '--no-buildid-cache', '--all-user', '--user-callchains',
            '--event', 'cycles:u',
            '--freq', str(FREQUENCY), '--strict-freq', '--call-graph', f'dwarf,{STACK_BYTES}',
            '--mmap-pages', '128', '--max-size', f'{MAX_BYTES >> 20}M', '--output', str(destination),
            '--', *argv]


def validate(content, selected, destination):
    require(selected.get('kind') == 'native' and selected.get('callgraph') is True,
            'call-stack collection requires the native catalogue')
    accepted = validate_scaling(content, selected, counters_required=False)
    path = Path(destination)
    require(path.is_file() and not path.is_symlink(), 'missing regular perf recording')
    size = path.stat().st_size
    require(8 < size < MAX_BYTES, 'empty or truncated perf recording')
    with path.open('rb') as stream:
        require(stream.read(8) == b'PERFILE2', 'invalid perf recording header')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(content.count('perf record: Captured') == 1, 'missing recording completion')
    decoded = subprocess.run(['/usr/bin/perf', 'script', '--input', str(path), '-G',
                              '--fields', 'period', '--show-lost-events'],
                             capture_output=True, text=True, timeout=30,
                             env=dict(os.environ, DEBUGINFOD_URLS=''))
    samples = decoded.stdout.splitlines()
    require(decoded.returncode == 0 and samples and all(s.strip().isdecimal() for s in samples),
            'missing, lost or undecodable call-stack samples')
    require(not re.search(r'PERF_RECORD_LOST|lost \d+ (?:chunks|samples)', content, re.I),
            'call-stack collection lost samples')
    require(not re.search(r'PERF_RECORD_LOST|lost [1-9]\d* (?:chunks|samples)', decoded.stderr, re.I),
            'call-stack decoder reported lost samples')
    artifact = {'path': str(path), 'sha256': digest, 'bytes': size, 'samples': len(samples),
                'event': 'cycles:u', 'frequency_hz': FREQUENCY, 'stack_bytes': STACK_BYTES,
                'maximum_bytes': MAX_BYTES, 'gpu_used': False, 'transactions_or_proofs': False}
    accepted['counter_scope'] = 'sampled user-space cycles with DWARF call stacks; not a timing comparison'
    return accepted, artifact
