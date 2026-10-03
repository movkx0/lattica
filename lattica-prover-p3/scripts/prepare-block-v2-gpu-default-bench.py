#!/usr/bin/env python3
"""Derive a frozen RAM 8/16/24 benchmark with the preserved GPU binary as control.

Preparation and command-policy checks do not start a prover. The original
qualified scratch launcher and completed evidence remain untouched.
"""
import ast
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'lattica-prover-p3/target'
SOURCE = ROOT / 'lattica-prover-p3/scripts/block-v2-scratch-bench.py'
SOURCE_SHA = '4ad9d60de7a33d2fbce0d0ff4d2ac05eda860aa68481702378907687466f1117'
PREVIOUS = TARGET / 'block-v2-scratch-bench-20261002'
CANDIDATE = TARGET / 'block-v2-gpu-default-20261002-a'
OUT = TARGET / 'block-v2-gpu-default-bench-20261002-a'
LAUNCHER = TARGET / 'block-v2-gpu-default-bench-20261002-a-launcher.py'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    if sha(SOURCE) != SOURCE_SHA:
        raise ValueError('completed-suite launcher changed; review before deriving')
    if OUT.exists() or LAUNCHER.exists():
        raise ValueError('already prepared; inspect rather than overwrite')
    build = json.loads((CANDIDATE / 'build-result.json').read_text())
    if build['status'] != 'BUILD_AND_ENTRYPOINT_CHECKS_PASS' or not build['effective_features_equal_except_default_alias']:
        raise ValueError('candidate build validation incomplete')
    for name, expected in build['pins'].items():
        if sha(Path(name)) != expected:
            raise ValueError('build pin changed: ' + name)
    if json.loads((PREVIOUS / 'run-state.json').read_text())['status'] != 'COMPLETE_RESEARCH_ONLY':
        raise ValueError('previous suite incomplete')
    original = SOURCE.read_text()
    source = original
    changes = []

    def change(before, after):
        nonlocal source
        if source.count(before) != 1:
            raise ValueError('launcher template drift: ' + before[:100])
        source = source.replace(before, after, 1)
        changes.append({'before': before, 'after': after})

    change('ROOT = Path(__file__).resolve().parents[2]', f'ROOT = Path({str(ROOT)!r})')
    change('DEFAULT_PLAN = TARGET / "block-v2-scratch-bench-20261002"',
           f'DEFAULT_PLAN = Path({str(OUT)!r})\nPREVIOUS = Path({str(PREVIOUS)!r})\n'
           f'CANDIDATE = Path({str(CANDIDATE)!r})')
    change('ARMS = ("disk8", "ram8", "ram16", "disk16")',
           'ARMS = ("ram16-control", "ram16", "ram8", "ram24")')
    change('SCHEMA = "post-reboot-scratch-bench-v1"', 'SCHEMA = "gpu-default-ram-control-bench-v1"')
    change('require(threads in (8, 16), "unsupported thread count")',
           'require(threads in (8, 16, 24), "unsupported thread count")')
    change('require(1 <= repeats <= 3, "choose one to three repeats per arm")',
           'require(repeats == 3, "this experiment requires three repeats per arm")')
    change('threads = 16 if arm.endswith("16") else 8',
           'threads = {"ram8": 8, "ram16": 16, "ram24": 24, "ram16-control": 16}[arm]')
    change('"scratch": str(scratch), "controller": str(controller)}',
           '"scratch": str(scratch), "controller": str(controller),\n'
           '                     "config_overrides": {} if arm == "ram16-control" else {\n'
           '                         "gpu_runner": str(CANDIDATE / "block-v2-gpu-grouped-probe"),\n'
           '                         "source_archive": str(CANDIDATE / "source.tar.gz")}}')
    change('    cfg = plan["config"]\n    argv = ',
           '    cfg = {**plan["config"], **plan["arms"][arm]["config_overrides"]}\n    argv = ')
    change('"baseline_manifest": str(BASELINE), "source_artifacts": baseline["source_artifacts"],',
           '"baseline_manifest": str(BASELINE), "source_artifacts": baseline["source_artifacts"],\n'
           '            "previous_suite": str(PREVIOUS), "candidate": str(CANDIDATE),\n'
           '            "comparison": "default GPU vs preserved explicitly GPU-enabled executable",')
    change('pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir()]',
           f'pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir(),\n'
           '              PREVIOUS / "plan.json", PREVIOUS / "run-state.json", PREVIOUS / "summary.json",\n'
           f'              Path({str(SOURCE)!r}), Path({str(Path(__file__).resolve())!r}),\n'
           '              CANDIDATE / "block-v2-gpu-grouped-probe", CANDIDATE / "source.tar.gz",\n'
           '              CANDIDATE / "build-result.json", CANDIDATE / "source-comparison.json"]')
    change('"measured_runs": repeats * 4,', '"measured_runs": repeats * len(ARMS),')
    change('"proofs_started": 0, "requires_new_boot": True',
           '"proofs_started": 0, "requires_new_boot": False')
    change('require(boot_id() != plan["prepared_boot_id"], "reboot has not happened; preparation never starts proving")',
           'require(os.cpu_count() == 24 and len(os.sched_getaffinity(0)) == 24,\n'
           '            "all 24 hardware threads must be available")\n'
           '    require(json.loads((PREVIOUS / "run-state.json").read_text())["status"] == "COMPLETE_RESEARCH_ONLY",\n'
           '            "previous benchmark suite must be complete")')
    ast.parse(source)
    with LAUNCHER.open('x') as stream:
        stream.write(source)
    spec = importlib.util.spec_from_file_location('gpu_default_bench', LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Validate both actual controller command construction and per-arm overrides.
    for threads in (8, 16, 24):
        derived = module.derive_controller(module.TEMPLATE.read_text(), threads, Path(f'/tmp/validate-ram{threads}'))
        controller = types.ModuleType(f'ram{threads}_controller')
        controller.__file__ = str(module.TEMPLATE)
        exec(compile(derived, str(module.TEMPLATE), 'exec'), controller.__dict__)
        cfg = json.loads((PREVIOUS / 'plan.json').read_text())['config']
        cfg.update(job='/tmp/validate-job', evidence='/tmp/validate-evidence', scratch_dir=f'/tmp/validate-ram{threads}')
        argv = controller.stage_command(cfg, 'lattica-v2-validation.service', 'worker.service', 'pairs', ['wrap-all'])
        for expected in (f'--setenv=RAYON_NUM_THREADS={threads}', '--property=MemoryMax=44G',
                         '--property=MemorySwapMax=0', f'--setenv=LATTICA_SPILL_MAX_BYTES={34 * (1 << 30)}',
                         '--setenv=LATTICA_V2_GPU_OPENING_COMPACT=1',
                         f'--setenv=LATTICA_SPILL_DIR=/tmp/validate-ram{threads}'):
            if expected not in argv:
                raise ValueError('derived worker command missing ' + expected)
    with patch.object(module.os, 'sched_getaffinity', return_value=set(range(23))):
        try:
            module.preflight(OUT, {}, None)
        except ValueError as error:
            if '24 hardware threads' not in str(error):
                raise
        else:
            raise ValueError('reduced CPU availability accepted')
    subprocess.run([sys.executable, '-B', str(LAUNCHER), 'prepare'], check=True)
    plan, _ = module.read_plan(OUT)
    sequence = module.steps(plan)
    if len(sequence) != 16 or sum(not item[2] for item in sequence) != 12:
        raise ValueError('expected four registrations and twelve measured runs')
    for arm in module.ARMS:
        for register in (True, False):
            argv = module.invocation(OUT, plan, arm, 'validation-only', register)
            expected_runner = plan['config']['gpu_runner'] if arm == 'ram16-control' else str(CANDIDATE / 'block-v2-gpu-grouped-probe')
            expected_source = plan['config']['source_archive'] if arm == 'ram16-control' else str(CANDIDATE / 'source.tar.gz')
            if argv[argv.index('--gpu-runner') + 1] != expected_runner or argv[argv.index('--source-archive') + 1] != expected_source:
                raise ValueError('per-arm build identity lost')
            if not register and argv[argv.index('--registration') + 1] != str(OUT / 'evidence' / f'register-{arm}' / 'manifest.json'):
                raise ValueError('incorrect registration binding')
    # Preserve interrupted-stage refusal in the derived experiment.
    bad = {'attempts': [{'label': 'register-ram16-control', 'arm': 'ram16-control', 'status': 'attempted'}]}
    try:
        module.validate_progress(bad, plan)
    except ValueError:
        pass
    else:
        raise ValueError('attempted stage accepted for automatic retry')
    (OUT / 'launcher.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile=str(SOURCE), tofile=str(LAUNCHER))))
    (OUT / 'derivation.json').write_text(json.dumps({
        'source': str(SOURCE), 'source_sha256': SOURCE_SHA, 'launcher': str(LAUNCHER),
        'launcher_sha256': sha(LAUNCHER), 'changes': changes,
        'validation': ['8/16/24 thread worker flags, memory limits and RAM scratch',
                       'per-arm runner/archive pins and registration binding',
                       'four registrations and twelve runs; alternating control/new16 order',
                       'reject reduced CPU affinity', 'reject automatic retry of attempted stage'],
        'proofs_started': 0}, indent=2) + '\n')
    print(json.dumps({'prepared': str(OUT), 'validation': 'PASS', 'proofs_started': 0}))


if __name__ == '__main__':
    main()
