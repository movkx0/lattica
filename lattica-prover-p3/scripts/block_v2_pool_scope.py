"""Select a bounded fleet's systemd hierarchy without changing other fleets."""
import re

DEFAULT = 'lattica-v2-multi.slice'


def validate(name):
    if name == DEFAULT:
        return name
    if (not isinstance(name, str) or len(name) > 100
            or not re.fullmatch(r'lattica-v2-multi-[a-z0-9]+(?:-[a-z0-9]+)*\.slice', name)
            or name.endswith('-coordinator.slice')):
        raise ValueError('invalid dedicated Lattica fleet slice')
    return name


def configure(name, gpu, timing):
    gpu.SLICE = validate(DEFAULT if name is None else name)
    timing.COORDINATOR_SLICE = gpu.SLICE.removesuffix('.slice') + '-coordinator.slice'


def select(args, gpu, timing):
    name = getattr(args, 'fleet_slice', None)
    if name is not None and not (getattr(args, 'owned_public_gpu', False)
            and (getattr(args, 'pool_calibration', None) or getattr(args, 'pool_timing_approval', []))):
        raise ValueError('dedicated fleet selection requires bounded owned admission')
    configure(name, gpu, timing)
