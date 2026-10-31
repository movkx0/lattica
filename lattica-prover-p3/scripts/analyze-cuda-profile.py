#!/usr/bin/env python3
"""Read an exported Nsight SQLite trace; distinguish overlapping time scopes."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def union_ns(intervals):
    total, previous = 0, None
    for start, end in intervals:
        if end < start:
            raise ValueError('invalid GPU interval')
        if previous is None:
            previous = (start, end)
        elif start <= previous[1]:
            previous = (previous[0], max(previous[1], end))
        else:
            total += previous[1] - previous[0]
            previous = (start, end)
    return total + (previous[1] - previous[0] if previous else 0)


def analyze(path):
    with sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'CUPTI_ACTIVITY_KIND_KERNEL', 'StringIds'} <= tables:
            raise ValueError('trace has no CUDA kernels or string dictionary')
        kernel = 'CUPTI_ACTIVITY_KIND_KERNEL'
        devices = [r[0] for r in db.execute(f'SELECT DISTINCT deviceId FROM {kernel}')]
        timelines = []
        for device in devices:
            first, last, total, calls = db.execute(
                f'SELECT min(start),max(end),sum(end-start),count(*) FROM {kernel} WHERE deviceId=?',
                (device,)).fetchone()
            active = union_ns(db.execute(f'SELECT start,end FROM {kernel} WHERE deviceId=? ORDER BY start,end', (device,)))
            timelines.append(dict(device_id=device, kernel_calls=calls, kernel_sum_seconds=total/1e9,
                                  kernel_active_seconds=active/1e9, first_to_last_kernel_seconds=(last-first)/1e9))
        kernels = [dict(r) for r in db.execute(f'''
            SELECT s.value AS name,count(*) AS calls,sum(k.end-k.start)/1e9 AS seconds,
                   k.gridX AS grid_x,k.blockX AS block_x,k.registersPerThread AS registers_per_thread,
                   k.dynamicSharedMemory AS dynamic_shared_bytes,k.localMemoryPerThread AS local_bytes_per_thread
            FROM {kernel} k JOIN StringIds s ON s.id=k.shortName
            GROUP BY k.shortName,k.gridX,k.blockX,k.registersPerThread,k.dynamicSharedMemory,k.localMemoryPerThread
            ORDER BY sum(k.end-k.start) DESC LIMIT 64''')]
        apis = []
        for table in ('CUPTI_ACTIVITY_KIND_DRIVER', 'CUPTI_ACTIVITY_KIND_RUNTIME'):
            if table in tables:
                apis.extend(dict(r) | {'table': table} for r in db.execute(f'''
                    SELECT s.value AS name,count(*) AS calls,sum(a.end-a.start)/1e9 AS inclusive_seconds
                    FROM {table} a JOIN StringIds s ON s.id=a.nameId
                    GROUP BY a.nameId ORDER BY sum(a.end-a.start) DESC LIMIT 24'''))
        ranges = []
        if 'NVTX_EVENTS' in tables:
            ranges = [dict(r) for r in db.execute('''
                SELECT coalesce(n.text,s.value) AS name,count(*) AS calls,
                       sum(n.end-n.start)/1e9 AS inclusive_host_seconds
                FROM NVTX_EVENTS n LEFT JOIN StringIds s ON s.id=n.textId
                WHERE n.end IS NOT NULL AND coalesce(n.text,s.value) LIKE 'cuda.%'
                GROUP BY coalesce(n.text,s.value) ORDER BY sum(n.end-n.start) DESC''')]
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(schema='lattica-cuda-profile-v1', sqlite=str(path.resolve()), sha256=digest,
                device_timelines=timelines, kernel_geometry=kernels, api_times=apis, host_ranges=ranges,
                interpretation='Instrumented diagnostics only. API waits overlap GPU work; host ranges nest. '
                               'Neither may be added to kernel time or treated as removable overhead. '
                               'Kernel-active time excludes transfers and memory initialization.')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('sqlite', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    result = json.dumps(analyze(args.sqlite), indent=2) + '\n'
    if args.output:
        with args.output.open('x') as stream:
            stream.write(result)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
