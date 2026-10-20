"""Retire page-cache hints for consumed public artifacts, retaining all bytes.

Tree retirement requires reconciliation of every service owning the directory.
Pinned retirement is for immutable published outputs after their reader exits;
the publisher may remain alive, but must not write those outputs again. Advice
never touches driver/shader caches or system cache controls. DONTNEED is a kernel
hint, not proof of a physical byte release or proof validity.
"""
import hashlib
import os
from pathlib import Path
import stat
import time

import block_v2_capacity as Capacity

MAX_ENTRIES = 4096
MAX_PINNED_ENTRIES = Capacity.MAX_TRANSACTIONS - 1
MAX_DEPTH = 12
MAX_BYTES = 512 << 20


def release_pinned(directory, pins, deadline_ms):
    """Retire only named, bounded files authenticated across a completed read.

    The caller pins outputs before their independent consumer starts, waits for
    that consumer to exit, and checks its result. This does not retire a live
    journal, working directory, or any unlisted file, and grants no proof rights.
    """
    if type(deadline_ms) is not int or deadline_ms <= 0:
        raise ValueError('pinned cache retirement needs an absolute deadline')
    root = Path(directory)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError('pinned artifact directory must be canonical and nonsymlink')
    if (type(pins) is not dict or not 1 <= len(pins) <= MAX_PINNED_ENTRIES
            or any(type(name) is not str or name in ('', '.', '..') or '/' in name
                   or type(pin) is not dict or set(pin) != {'bytes', 'sha256'}
                   or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= 2 << 20
                   or type(pin['sha256']) is not str or len(pin['sha256']) != 64
                   or any(c not in '0123456789abcdef' for c in pin['sha256'])
                   for name, pin in pins.items())):
        raise ValueError('invalid bounded pinned artifact inventory')
    if not hasattr(os, 'posix_fadvise') or not hasattr(os, 'POSIX_FADV_DONTNEED'):
        raise ValueError('pinned artifact retirement requires file-scoped advice')
    started = time.monotonic_ns()
    def within():
        if time.monotonic_ns() // 1_000_000 >= deadline_ms:
            raise TimeoutError('pinned artifact retirement deadline')
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    within()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    opened = []
    try:
        parent = os.fstat(fd)
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError('pinned artifact directory must be private to its owner')
        # Authenticate every file before any advice. Keep the bounded descriptor
        # set open so replacement cannot redirect advice to another inode.
        for name, pin in pins.items():
            within()
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size != pin['bytes']:
                raise ValueError('pinned artifact type, owner or size changed')
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            opened.append((name, child, info))
            if identity(os.fstat(child)) != identity(info):
                raise ValueError('pinned artifact changed while opening')
            digest = hashlib.sha256()
            remaining = pin['bytes']
            while remaining:
                within()
                block = os.read(child, min(remaining, 64 << 10))
                if not block:
                    raise ValueError('pinned artifact bytes changed')
                digest.update(block); remaining -= len(block)
            if (os.read(child, 1) or digest.hexdigest() != pin['sha256']
                    or identity(os.fstat(child)) != identity(info)):
                raise ValueError('pinned artifact bytes changed')
        for name, child, info in opened:
            within()
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(info):
                raise ValueError('pinned artifact path changed before advice')
            os.fsync(child)
            within()
            os.posix_fadvise(child, 0, 0, os.POSIX_FADV_DONTNEED)
            if (identity(os.fstat(child)) != identity(info)
                    or identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(info)):
                raise ValueError('pinned artifact changed during advice')
    finally:
        for _, child, _ in opened: os.close(child)
        os.close(fd)
    within()
    return {'schema_version': 1, 'directory': str(root), 'files': len(pins),
            'requested_bytes': sum(pin['bytes'] for pin in pins.values()), 'pins': pins,
            'advice': 'POSIX_FADV_DONTNEED', 'artifact_bytes_preserved': True,
            'physical_release_measured': False, 'proof_authority_granted': False,
            'elapsed_ms': (time.monotonic_ns() - started) // 1_000_000}


def release(directory, deadline_ms):
    if type(deadline_ms) is not int or deadline_ms <= 0:
        raise ValueError('public artifact cache retirement needs an absolute deadline')
    root = Path(directory)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError('public artifact directory must be canonical and nonsymlink')
    if not hasattr(os, 'posix_fadvise') or not hasattr(os, 'POSIX_FADV_DONTNEED'):
        raise ValueError('public artifact cache retirement requires file-scoped advice')
    started = time.monotonic_ns()
    result = {'schema_version': 1, 'directory': str(root), 'files': 0, 'entries': 0,
              'requested_bytes': 0, 'advice': 'POSIX_FADV_DONTNEED',
              'artifact_bytes_preserved': True, 'physical_release_measured': False}

    def within():
        if time.monotonic_ns() // 1_000_000 >= deadline_ms:
            raise TimeoutError('public artifact cache retirement deadline')

    def visit(fd, depth):
        within()
        if depth > MAX_DEPTH:
            raise ValueError('public artifact directory depth bound')
        with os.scandir(fd) as entries:
            for entry in entries:
                within()
                result['entries'] += 1
                if result['entries'] > MAX_ENTRIES:
                    raise ValueError('public artifact inventory entry bound')
                info = entry.stat(follow_symlinks=False)
                if info.st_uid != os.getuid():
                    raise ValueError('public artifact owner changed')
                directory_entry = stat.S_ISDIR(info.st_mode)
                if not directory_entry and not stat.S_ISREG(info.st_mode):
                    raise ValueError('public artifact must be a regular nonsymlink file or directory')
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                if directory_entry:
                    flags |= os.O_DIRECTORY
                child = os.open(entry.name, flags, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (
                            info.st_dev, info.st_ino, info.st_mode, info.st_size):
                        raise ValueError('public artifact changed while opening it')
                    if directory_entry:
                        visit(child, depth + 1)
                    else:
                        result['requested_bytes'] += opened.st_size
                        if result['requested_bytes'] > MAX_BYTES:
                            raise ValueError('public artifact inventory byte bound')
                        # All proof/journal producers already sync their writes.
                        # Sync the descriptor again before asking to discard only
                        # its clean cache pages, including final diagnostic logs.
                        os.fsync(child)
                        within()
                        os.posix_fadvise(child, 0, 0, os.POSIX_FADV_DONTNEED)
                        result['files'] += 1
                        after = os.fstat(child)
                        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                            raise ValueError('public artifact changed during cache retirement')
                finally:
                    os.close(child)
    within()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('public artifact directory must be private to its owner')
        visit(fd, 0)
    finally:
        os.close(fd)
    within()
    result['elapsed_ms'] = (time.monotonic_ns() - started) // 1_000_000
    return result
