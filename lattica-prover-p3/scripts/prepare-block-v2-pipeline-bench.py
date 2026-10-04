#!/usr/bin/env python3
"""Freeze a bounded, alternating pipeline comparison using qualified controllers.

Preparation never launches proofs. Both arms use the same preserved executable,
public fixture and CPU auditor. The previous suites and controllers are read-only.
"""
import argparse
import ast
import csv
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import types

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "lattica-prover-p3/scripts/block-v2-scratch-bench.py"
SOURCE_SHA = "4ad9d60de7a33d2fbce0d0ff4d2ac05eda860aa68481702378907687466f1117"
ARMS = ("ram-reference", "ram-candidate")


def require(value, message):
    if not value:
        raise ValueError(message)


def replace_once(source, before, after):
    require(source.count(before) == 1, "qualified source changed: " + before[:100])
    return source.replace(before, after, 1)


def load_module(path):
    module = types.ModuleType("pipeline_qualification_helper")
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def configure_controller(source, parallel, gpu_quotient=0):
    require(type(parallel) is int and parallel in (0, 1), "readback must be integer 0 or 1")
    require(type(gpu_quotient) is int and gpu_quotient in (0, 1), "GPU quotient must be integer 0 or 1")
    source = replace_once(source, 'SCHEMA = "gpu-scratch-eight-v1"',
                          'SCHEMA = "gpu-pipeline-eight-v1"')
    source = replace_once(source, '"--setenv=RAYON_NUM_THREADS=16"',
                          '"--setenv=RAYON_NUM_THREADS=24"')
    source = replace_once(source, 'config["rayon_threads"] = 16',
                          'config["rayon_threads"] = 24')
    source = replace_once(source, '"--setenv=LATTICA_V2_GPU_OPENING_PINNED=0",',
                          '"--setenv=LATTICA_V2_GPU_OPENING_PINNED=0",\n'
                          f'        f"--setenv=LATTICA_V2_GPU_PARALLEL_READBACK={{{parallel} if gpu else 0}}",\n'
                          f'        f"--setenv=LATTICA_V2_GPU_QUOTIENT_LDE={{{gpu_quotient} if gpu else 0}}",')
    source = replace_once(source, 'def run(config, resume):\n',
                          f'def run(config, resume):\n    config["parallel_readback"] = {parallel}\n    config["gpu_quotient"] = {gpu_quotient}\n')
    source = replace_once(source,
        'for key in ("external", "backend", "gpu_index", "gpu_uuid", "quotient_fusion", "gpu_openings", "gpu_compact"):',
        'for key in ("external", "backend", "gpu_index", "gpu_uuid", "quotient_fusion", "gpu_openings", "gpu_compact", "parallel_readback", "gpu_quotient"):')
    source = replace_once(source, 'def validate_gpu_log(', 'def validate_original_gpu_log(')
    validation = '''
def validate_gpu_log(path, *args):
    result = validate_original_gpu_log(path, *args)
    text = path.read_text()
    policies = [line for line in text.splitlines() if line.startswith("gpu_readback_research ")]
    require(policies == ["gpu_readback_research parallel=POLICY production_ready=false"],
            "missing or contradictory readback policy")
    records = []
    for line in text.splitlines():
        if line.startswith("bounded_gpu_readback_checkpoint "):
            records.append(dict(item.split("=", 1) for item in shlex.split(line)[1:]))
    require(records and records[-1]["label"] == "GPU grouped process remainder",
            "final readback accounting missing")
    last = records[-1]
    values = {key: H.natural(last[key]) for key in ("parallel_decode_bytes", "parallel_decode_chunks")}
    require(all((value > 0) == ENABLED for value in values.values()),
            "readback work differs from requested policy")
    result["readback"] = values
    policies = [line for line in text.splitlines() if line.startswith("gpu_quotient_research ")]
    require(policies == ["gpu_quotient_research enabled=QPOLICY production_ready=false"], "GPU quotient policy missing")
    records = [dict(item.split("=", 1) for item in shlex.split(line)[1:])
               for line in text.splitlines() if line.startswith("bounded_gpu_quotient_checkpoint ")]
    require(records and records[-1]["label"] == "GPU grouped process remainder", "final GPU quotient accounting missing")
    commits = H.natural(records[-1]["commits"])
    name = args[1] if len(args) > 1 else "pairs"
    expected = {"pairs": 4, "merges": 3}.get(name, 0) if QENABLED else 0
    require(commits == expected, "GPU quotient work differs from requested policy")
    result["gpu_quotient_commits"] = commits
    return result

'''.replace("QPOLICY", str(bool(gpu_quotient)).lower()).replace("QENABLED", repr(bool(gpu_quotient))).replace("POLICY", str(bool(parallel)).lower()).replace("ENABLED", repr(bool(parallel)))
    source = replace_once(source, 'if __name__ == "__main__":',
                          validation + 'if __name__ == "__main__":')
    ast.parse(source)
    return source


def desktop_gpu_processes(output, gpu_uuid):
    """Record known desktop renderers; reject other GPU compute clients.

    No process is stopped. A renderer must be owned by this user, have its actual
    executable and --type=gpu-process checked, and fit the reserved headroom.
    """
    observed = []
    for row in csv.reader(io.StringIO(output)):
        require(len(row) == 4, "unexpected GPU process columns")
        uuid, pid, name, memory = [value.strip() for value in row]
        require(uuid == gpu_uuid and pid.isdecimal() and memory.isdecimal(), "GPU process identity")
        process = Path("/proc") / pid
        require(process.stat().st_uid == os.getuid(), "GPU client belongs to another user")
        require(int(memory) <= 512, "desktop GPU client exceeds reserved headroom")
        group = (process / "cgroup").read_text().strip()
        if name == "/usr/bin/kwin_wayland":
            require(group.endswith("/plasma-kwin_wayland.service"), "unexpected compositor cgroup")
            executable = name
        else:
            executable = os.readlink(process / "exe")
            allowed = executable == "/opt/brave-bin/brave" or (
                executable.startswith(str(Path.home() / ".config/discord/app-"))
                and executable.endswith("/Discord"))
            require(allowed, "unqualified GPU compute process: " + executable)
            require(b"--type=gpu-process" in (process / "cmdline").read_bytes().split(b"\0"),
                    "expected a desktop GPU renderer")
        observed.append({"pid": int(pid), "executable": executable,
                         "gpu_memory_mib": int(memory), "cgroup": group})
    require(sum(row["gpu_memory_mib"] for row in observed) <= 1024, "desktop GPU headroom exceeded")
    return observed


def launcher_source(candidate, out, pairs, reference_readback, candidate_readback, candidate_fusion, reference_fusion=0, candidate_quotient=0):
    original = SOURCE.read_text()
    require(hashlib.sha256(original.encode()).hexdigest() == SOURCE_SHA, "qualified scratch launcher changed")
    source = original
    helper = str(Path(__file__).resolve())
    replacements = [
        ('ROOT = Path(__file__).resolve().parents[2]', f'ROOT = Path({str(ROOT)!r})'),
        ('DEFAULT_PLAN = TARGET / "block-v2-scratch-bench-20261002"',
         f'DEFAULT_PLAN = Path({str(out)!r})\nCANDIDATE = Path({str(candidate)!r})'),
        ('ARMS = ("disk8", "ram8", "ram16", "disk16")', f'ARMS = {ARMS!r}'),
        ('SCHEMA = "post-reboot-scratch-bench-v1"', 'SCHEMA = "gpu-pipeline-paired-bench-v1"'),
        ('require(1 <= repeats <= 3, "choose one to three repeats per arm")',
         'require(repeats in (1, 5), "choose one qualification pair or five comparison pairs")'),
        ('threads = 16 if arm.endswith("16") else 8', 'threads = 24'),
        ('controller.write_text(derive_controller(source, threads, scratch))',
         f'controller.write_text(P.configure_controller(derive_controller(source, 16, scratch), '
         f'{reference_readback} if arm == "ram-reference" else {candidate_readback}, 0 if arm == "ram-reference" else {candidate_quotient}))'),
        ('"scratch": str(scratch), "controller": str(controller)}',
         '"scratch": str(scratch), "controller": str(controller), "config_overrides": {\n'
         '            "gpu_runner": str(CANDIDATE / "block-v2-gpu-grouped-probe"),\n'
         '            "source_archive": str(CANDIDATE / "source.tar.gz"),\n'
         f'            "quotient_fusion": {reference_fusion} if arm == "ram-reference" else {candidate_fusion}}}}}'),
        ('    cfg = plan["config"]\n    argv = ',
         '    cfg = {**plan["config"], **plan["arms"][arm]["config_overrides"]}\n    argv = '),
        ('pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir()]',
         f'pinned = [Path(__file__).resolve(), BASELINE, *support.iterdir(), Path({helper!r}),\n'
         '              CANDIDATE / "block-v2-gpu-grouped-probe", CANDIDATE / "source.tar.gz"]'),
        ('"measured_runs": repeats * 4,', '"measured_runs": repeats * len(ARMS),'),
        ('"proofs_started": 0, "requires_new_boot": True', '"proofs_started": 0, "requires_new_boot": False'),
        ('require(boot_id() != plan["prepared_boot_id"], "reboot has not happened; preparation never starts proving")',
         'require(os.cpu_count() == 24 and len(os.sched_getaffinity(0)) == 24, "24 hardware threads required")'),
        ('def prepare(out, repeats):',
         f'P = load_module(Path({helper!r}))\n\n\ndef prepare(out, repeats):'),
        ('desktop = desktop_gpu_processes(compute, plan["config"]["gpu_uuid"])',
         'desktop = P.desktop_gpu_processes(compute, plan["config"]["gpu_uuid"])'),
        ('parser.add_argument("--repeats", type=int, default=3)',
         f'parser.add_argument("--repeats", type=int, default={pairs})'),
    ]
    for before, after in replacements:
        source = replace_once(source, before, after)
    ast.parse(source)
    return original, source


def prepare(candidate, out, pairs, reference_readback, candidate_readback, candidate_fusion, reference_fusion=0, candidate_quotient=0):
    require(pairs in (1, 5), "one qualification pair or five comparison pairs required")
    require(all(type(n) is int and n in (0, 1)
                for n in (reference_readback, candidate_readback, candidate_fusion, reference_fusion, candidate_quotient)), "invalid pipeline policy")
    require(reference_readback != candidate_readback or candidate_fusion != reference_fusion or candidate_quotient, "comparison changes nothing")
    require(not candidate_quotient or candidate_fusion, "GPU quotient requires fusion")
    candidate, out = candidate.resolve(), out.resolve()
    require(all((candidate / name).is_file() for name in ("block-v2-gpu-grouped-probe", "source.tar.gz")),
            "preserved candidate binary and source archive required")
    launcher = out.with_name(out.name + "-launcher.py")
    require(not out.exists() and not launcher.exists(), "preserve previous attempts; choose a new directory")
    original, source = launcher_source(candidate, out, pairs, reference_readback, candidate_readback, candidate_fusion, reference_fusion, candidate_quotient)
    with launcher.open("x") as stream:
        stream.write(source)
    module = load_module(launcher)
    module.prepare(out, pairs)
    plan, _ = module.read_plan(out)
    require(len(module.steps(plan)) == 2 + 2 * pairs, "unexpected comparison schedule")
    (out / "launcher.diff").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), source.splitlines(keepends=True),
        fromfile=str(SOURCE), tofile=str(launcher))))
    (out / "experiment.json").write_text(json.dumps({
        "schema": "gpu-pipeline-experiment-v1", "pairs": pairs,
        "reference_readback": reference_readback, "candidate_readback": candidate_readback,
        "candidate_fusion": candidate_fusion, "reference_fusion": reference_fusion, "candidate_quotient": candidate_quotient, "same_binary": True,
        "production_ready": False, "started_provers": 0,
    }, indent=2) + "\n")
    print(json.dumps({"launcher": str(launcher), "plan": str(out), "started_provers": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--pairs", type=int, choices=(1, 5), default=5)
    parser.add_argument("--reference-readback", type=int, choices=(0, 1), default=0)
    parser.add_argument("--candidate-readback", type=int, choices=(0, 1), default=1)
    parser.add_argument("--candidate-fusion", type=int, choices=(0, 1), default=0)
    parser.add_argument("--reference-fusion", type=int, choices=(0, 1), default=0)
    parser.add_argument("--candidate-quotient", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    os.umask(0o077)
    prepare(args.candidate, args.plan, args.pairs, args.reference_readback,
            args.candidate_readback, args.candidate_fusion, args.reference_fusion, args.candidate_quotient)


if __name__ == "__main__":
    main()
