"""Explicit CPU ISA controls for recorded builds, never a runtime quota switch."""
from pathlib import Path
import platform

TARGET = 'x86-64-v3'
REQUIRED = frozenset('avx avx2 bmi1 bmi2 f16c fma movbe xsave cx16 lahf_lm popcnt pni sse4_1 sse4_2 ssse3'.split())


def check(target, machine=None, cpuinfo=None):
    if target is None:
        return
    if target != TARGET:
        raise ValueError('unsupported recorded CPU build target')
    if (platform.machine() if machine is None else machine) != 'x86_64':
        raise ValueError('x86-64-v3 build artifact requires an x86_64 host')
    content = Path('/proc/cpuinfo').read_text() if cpuinfo is None else cpuinfo
    processors = [set(line.split(':', 1)[1].split()) for line in content.splitlines()
                  if line.split(':', 1)[0].strip() == 'flags' and ':' in line]
    if not processors or any(not REQUIRED <= flags or not {'abm', 'lzcnt'} & flags
                             for flags in processors):
        raise ValueError('x86-64-v3 build artifact requires AVX2/BMI2 and the complete v3 ISA on every CPU')


def configure(target, profile, command, environment):
    if target is None:
        return
    if (profile != 'build' or not command or Path(command[0]).name != 'cargo'
            or not (command[1:2] == ['build'] or command[1:2] == ['test'] and '--no-run' in command)):
        raise ValueError('CPU build target requires a recorded Cargo build or test --no-run')
    check(target)
    environment['RUSTFLAGS'] = '-C target-cpu=' + target
