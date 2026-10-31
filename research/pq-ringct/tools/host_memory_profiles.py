"""Explicit complete-workflow host envelopes; never enlarge operation budgets."""
GIB = 1 << 30
# worker, MemoryMax, MemoryHigh, required MemAvailable (GiB)
HOST_PROFILES = {
    'standard': (32, 47, 45, 49),
    'expanded-36': (36, 51, 49, 53),
    'expanded-40': (40, 55, 53, 57),
}


def selected_host_profile(name):
    if name not in HOST_PROFILES:
        raise ValueError('unrecognized host-memory profile')
    worker, maximum, high, available = HOST_PROFILES[name]
    return {
        'name': name, 'worker_host_bytes': worker * GIB,
        'memory_max_bytes': maximum * GIB,
        'memory_high_bytes': high * GIB,
        'fresh_memavailable_required_bytes': available * GIB,
    }
