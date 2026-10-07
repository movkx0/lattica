#!/usr/bin/env python3
"""Check that the pending Mac research source is complete in the Git index.

Run from the repository root before its next Mac source commit. --stage stages
changed source/configuration files only; it never commits, pushes, pulls, or
changes branches. Benchmark outputs and binaries are outside its source scope.
"""
import argparse
from pathlib import Path
import subprocess


CRATE = 'lattica-prover-p3'
REQUIRED = tuple(f'{CRATE}/src/{name}' for name in (
    'block_v2/gpu_hash/prefix_storage.rs',
    'block_v2/gpu_quotient_prover/metal.rs',
    'metal_compute/backing.rs', 'metal_compute/diagnostics.rs',
    'metal_compute/quotient.metal', 'metal_compute/resident.rs',
))
ROOTS = ('src', f'{CRATE}/src', f'{CRATE}/scripts', f'{CRATE}/tests', 'scripts', '.cargo')
CONFIGS = ('build.zig', 'build.zig.zon', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
           f'{CRATE}/Cargo.toml', f'{CRATE}/Cargo.lock', f'{CRATE}/build.rs',
           f'{CRATE}/rust-toolchain.toml', f'{CRATE}/.cargo/config.toml')
SUFFIXES = {'.rs', '.metal', '.zig', '.py', '.js', '.mjs', '.sh', '.c', '.h',
            '.cpp', '.hpp', '.s', '.json', '.toml', '.lock'}
EXCLUDED_PARTS = {'target', '.git', '.venv', 'venv', '__pycache__', 'node_modules', 'benchmark-results'}


class IncompleteSource(ValueError):
    pass


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def source_path(name):
    path = Path(name)
    if EXCLUDED_PARTS.intersection(path.parts):
        return False
    return name in CONFIGS or (path.suffix.lower() in SUFFIXES and
        any(name.startswith(root + '/') for root in ROOTS))


def names(repo, *args):
    return {name for name in git(repo, *args).decode().split('\0') if name and source_path(name)}


def source_changes(repo):
    unstaged = names(repo, 'diff', '--no-renames', '--name-only', '-z')
    new = names(repo, 'ls-files', '--others', '--exclude-standard', '-z')
    ignored = names(repo, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z', '--', *ROOTS, *CONFIGS)
    return unstaged, new, ignored


def check(repo, stage=False):
    repo = Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip())
    conflicts = git(repo, 'ls-files', '--unmerged', '-z')
    if conflicts:
        raise IncompleteSource('Resolve merge conflicts before checking the source checkpoint.')
    unstaged, new, ignored = source_changes(repo)
    if ignored:
        raise IncompleteSource('Ignored source files need explicit review; nothing was force-added:\n' +
                               '\n'.join(sorted(ignored)))
    if stage and (unstaged or new):
        subprocess.run(['git', '-C', str(repo), 'add', '-A', '--',
                        *(':(literal)' + name for name in sorted(unstaged | new))], check=True)
        unstaged, new, ignored = source_changes(repo)
    problems = []
    if unstaged:
        problems.append('Source edits omitted from the index:\n' + '\n'.join(sorted(unstaged)))
    if new:
        problems.append('New source files omitted from the index:\n' + '\n'.join(sorted(new)))
    indexed = names(repo, 'ls-files', '-z')
    missing = set(REQUIRED) - indexed
    if missing:
        problems.append('Pending Mac modules missing from the index:\n' + '\n'.join(sorted(missing)))
    if problems:
        raise IncompleteSource('\n\n'.join(problems))
    git(repo, 'diff', '--cached', '--check')
    changed = names(repo, 'diff', '--cached', '--no-renames', '--name-only', '-z')
    return sorted(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--stage', action='store_true', help='stage all changed source files in the declared scope before checking')
    args = parser.parse_args()
    try:
        changed = check(args.repo, args.stage)
    except (IncompleteSource, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')
    print(f'PASS: all {len(REQUIRED)} pending Mac modules are indexed; {len(changed)} source changes staged.')
    print('Review git diff --cached before committing. This checks source completeness, not proof correctness.')
    for name in changed:
        print(name)


if __name__ == '__main__':
    main()
