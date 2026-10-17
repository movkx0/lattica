#!/usr/bin/env python3
"""Join a scoped Nsight capture to prover phases using measured NVTX clock anchors.

OpenCL event times and host-relative tracing spans are deliberately not aligned:
neither clock has a synchronization anchor in the frozen paired prover.
"""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3

import numpy as np


METRICS = {
    'gr': 'GR Active [Throughput %]',
    'sm': 'SMs Active [Throughput %]',
    'issue': 'SM Issue [Throughput %]',
    'dram_read': 'DRAM Read Bandwidth [Throughput %]',
    'dram_write': 'DRAM Write Bandwidth [Throughput %]',
    'pcie_rx': 'PCIe RX Throughput [Throughput %]',
    'pcie_tx': 'PCIe TX Throughput [Throughput %]',
    'copy': 'Sync Copy Engine Active [Throughput %]',
}


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def align_clock(db, records):
    clocks = {r['sequence']: r for r in records if r['type'] == 'clock'}
    markers = db.execute("""select start, coalesce(text, s.value) from NVTX_EVENTS n
        left join StringIds s on s.id=n.textId
        where coalesce(text, s.value) like 'lattica_clock:%'""").fetchall()
    offsets, uncertainty, lower, upper = [], [], [], []
    if len(markers) != len(clocks):
        raise ValueError('NVTX clock marker loss or duplication')
    seen = set()
    for timestamp, label in markers:
        sequence = int(label.split(':')[1])
        if sequence in seen:
            raise ValueError('duplicate clock marker')
        seen.add(sequence)
        r = clocks[sequence]
        lo, hi = r['before_ns'] - timestamp, r['after_ns'] - timestamp
        lower.append(lo)
        upper.append(hi)
        offsets.append((lo + hi) / 2)
        uncertainty.append(hi - lo)
    # Nsight timestamp conversion can jitter across CPU cores. Preserve the
    # entire observed envelope, including marker-call duration, and refuse a
    # capture whose alignment is poorer than one GPU sample period. This is an
    # empirical alignment bound, not a claim of a shared hardware clock.
    lo, hi = min(lower), max(upper)
    if hi-lo > 1_000_000:
        raise ValueError(f'clock offset envelope exceeds 1 ms ({hi-lo} ns)')
    return (lo + hi) // 2, dict(markers=len(markers), offset_ns=(lo+hi)//2,
        observed_offset_envelope_ns=[lo, hi], uncertainty_ns=hi-lo,
        maximum_observed_alignment_error_ns=(hi-lo)/2,
        constant_offset_brackets_intersect=max(lower)<=min(upper),
        maximum_marker_call_ns=max(uncertainty),
        midpoint_offset_spread_ns=max(offsets)-min(offsets))


def cpu_intervals(records):
    hz = next(r['ticks_per_second'] for r in records if r['type'] == 'metadata')
    clocks = sorted((r for r in records if r['type'] == 'clock'), key=lambda r:r['before_ns'])
    intervals, pids, vanished = [], set(), 0
    for before, after in zip(clocks, clocks[1:]):
        old = {(p['pid'], p['start_ticks']):p for p in before['processes']}
        new = {(p['pid'], p['start_ticks']):p for p in after['processes']}
        ticks = 0
        for key, p in new.items():
            pids.add(p['pid'])
            now = p['user_ticks'] + p['system_ticks']
            if key in old:
                prev = old[key]['user_ticks'] + old[key]['system_ticks']
                ticks += max(0, now-prev)
            elif p['start_ticks'] / hz >= before['before_ns'] / 1e9 - 1/hz:
                ticks += now
        vanished += len(old.keys() - new.keys())
        start, end = before['before_ns'], after['before_ns']
        intervals.append(dict(start_ns=start, end_ns=end,
            cores=(ticks/hz)/((end-start)/1e9)))
    return intervals, sorted(pids), vanished


def phases(log):
    active, result, nodes, timeline_counts = {}, [], [], defaultdict(int)
    for line in log.read_text().splitlines():
        if line.startswith('{'):
            record = json.loads(line)
            if record.get('event') == 'fresh_typed_node':
                nodes.append(record)
        tag = line.split(' ', 1)[0]
        if tag in ('gpu_timeline_interval', 'host_timeline_interval', 'performance_span'):
            timeline_counts[tag] += 1
        if tag not in ('linux_memory_admit', 'linux_memory_release'):
            continue
        values = dict(item.split('=', 1) for item in shlex.split(line)[1:])
        key = (int(values['pid']), values['phase'], values['pool'], int(values['slot']))
        timestamp = int(values['clock_ns'])
        if tag == 'linux_memory_admit':
            if key in active:
                raise ValueError('duplicate phase admission')
            active[key] = (timestamp, int(values['waited_ms']) / 1000)
        else:
            start, wait = active.pop(key)
            result.append(dict(pid=key[0], name=key[1], pool=key[2],
                start_ns=start, end_ns=timestamp, duration_seconds=(timestamp-start)/1e9,
                waited_seconds=wait))
    if active:
        raise ValueError('unreleased phase at end of successful proof')
    return result, nodes, dict(timeline_counts)


def operation_timings(log):
    checkpoints, spans, gpu, host = {}, [], [], []
    device_intervals = defaultdict(list)
    pattern = re.compile(r'kind=(\S+) start_ns=(\d+) end_ns=(\d+) clock=(\S+)')
    for line in log.read_text().splitlines():
        tag = line.split(' ',1)[0]
        if tag == 'gpu_timeline_interval':
            match = pattern.search(line)
            if not match or match[4] != 'opencl_device':
                raise ValueError('unknown GPU event clock')
            start, end = int(match[2]), int(match[3])
            if end < start:
                raise ValueError('negative GPU interval')
            device_intervals[match[1]].append((start,end))
            continue
        if (tag.startswith('bounded_gpu_') and tag.endswith('checkpoint')) or tag in (
                'performance_span','performance_checkpoint','gpu_timeline_checkpoint','host_timeline_checkpoint'):
            fields = dict(item.split('=',1) for item in shlex.split(line)[1:])
            values = {key:int(value) if value.isdecimal() else value for key,value in fields.items()}
            if tag == 'performance_span':
                spans.append(values)
            elif tag == 'gpu_timeline_checkpoint':
                gpu.append(values)
            elif tag == 'host_timeline_checkpoint':
                host.append(values)
            else:
                if tag in checkpoints:
                    raise ValueError('multiple timing checkpoints need explicit cumulative differencing')
                checkpoints[tag] = values
    all_intervals = sorted(interval for rows in device_intervals.values() for interval in rows)
    union, last = 0, None
    for start,end in all_intervals:
        union += end-max(start,last if last is not None else start) if last is None or end>last else 0
        last = max(end,last if last is not None else end)
    return dict(checkpoints=checkpoints, inclusive_cpu_spans=spans,
        gpu_timeline_checkpoints=gpu,host_timeline_checkpoints=host,
        recorded_gpu_events={kind:dict(events=len(rows),device_seconds=sum(b-a for a,b in rows)/1e9)
            for kind,rows in device_intervals.items()},
        recorded_gpu_union_seconds=union/1e9,
        note='Cumulative timing counters and CPU spans cover the full run. Event buffers can drop intervals; their unions are partial. CPU spans overlap and must not be added.')


def load_metrics(db, uuid, gpu_index, offset):
    db.row_factory = sqlite3.Row
    gpus = [dict(r) for r in db.execute('select id,name,uuid,memoryBandwidth from TARGET_INFO_GPU')]
    matches = [r for r in gpus if r['uuid'].removeprefix('GPU-').lower() == uuid.removeprefix('GPU-').lower()]
    if len(matches) != 1 or matches[0]['id'] != gpu_index:
        raise ValueError('capture GPU identity differs from runner assignment')
    types = list(db.execute('select distinct typeId from TARGET_INFO_GPU_METRICS'))
    if len(types) != 1:
        raise ValueError('expected exactly one GPU metric source in this scoped capture')
    type_id = types[0][0]
    names = {r[1]:r[0] for r in db.execute('select metricId,metricName from TARGET_INFO_GPU_METRICS where typeId=?',(type_id,))}
    timestamps, values = None, {}
    for key, name in METRICS.items():
        if name not in names:
            raise ValueError('missing hardware metric: ' + name)
        rows = np.fromiter((tuple(r) for r in db.execute('select timestamp,value from GPU_METRICS where typeId=? and metricId=? order by timestamp',
                           (type_id,names[name]))), dtype=[('timestamp',np.int64),('value',np.float64)])
        if timestamps is None:
            timestamps = rows['timestamp'].copy() + offset
        elif not np.array_equal(rows['timestamp']+offset, timestamps):
            raise ValueError('GPU metrics do not share sampling instants')
        values[key] = rows['value'].copy()
        if not np.isfinite(values[key]).all() or np.any(values[key] < 0) or np.any(values[key] > 100.01):
            raise ValueError('invalid GPU throughput percentage')
    delta = np.diff(timestamps)
    if np.any(delta <= 0):
        raise ValueError('nonincreasing metric clock')
    period = int(np.median(delta))
    # Counters describe the preceding sample period. Avoid crediting gaps as
    # measured time when the recorder has dropped samples.
    starts = timestamps - np.minimum(np.r_[period, delta], period*2)
    return starts, timestamps, values, dict(gpu=matches[0], type_id=type_id,
        mapping='single requested UUID and index, single collected metric source',
        samples=len(timestamps), median_period_ns=period,
        gaps_over_two_periods=int(np.count_nonzero(delta > period*2)))


def weights(starts, ends, windows):
    result = np.zeros(len(ends))
    # Callers supply disjoint intervals of one phase or the whole proof.
    ordered = sorted(windows)
    if any(a[1] > b[0] for a,b in zip(ordered,ordered[1:])):
        raise ValueError('overlapping aggregation intervals')
    for start, end in ordered:
        result += np.maximum(0, np.minimum(ends,end)-np.maximum(starts,start)) / 1e9
    return result


def describe(values, w):
    selected = w > 0
    if not selected.any():
        return None
    x, wt = values[selected], w[selected]
    order = np.argsort(x)
    cumulative = np.cumsum(wt[order])
    return dict(mean=float(np.average(x, weights=wt)),
        p50=float(x[order[np.searchsorted(cumulative,cumulative[-1]*0.5)]]),
        p95=float(x[order[np.searchsorted(cumulative,cumulative[-1]*0.95)]]),
        maximum=float(x.max()))


def summarize(values, w, cpu):
    active = values['gr'] > 10
    idle = values['gr'] <= 2
    sm_busy = values['sm'] > 50
    return dict(covered_seconds=float(w.sum()),
        active_seconds=float(w[active].sum()),
        largely_idle_seconds=float(w[idle].sum()),
        idle_with_cpu_active_seconds=float(w[idle & (cpu >= 0.5)].sum()),
        idle_with_four_cpu_cores_seconds=float(w[idle & (cpu >= 4)].sum()),
        dram_read_over_80_seconds=float(w[values['dram_read'] >= 80].sum()),
        dram_write_over_80_seconds=float(w[values['dram_write'] >= 80].sum()),
        sm_over_50_seconds=float(w[sm_busy].sum()),
        metrics={key:describe(x,w) for key,x in values.items()},
        gpu_active_metrics={key:describe(x,w*active) for key,x in values.items()},
        sm_busy_metrics={key:describe(x,w*sm_busy) for key,x in values.items()},
        cpu_cores=describe(cpu,w))


def cpu_stacks(db, pids, start, end, offset):
    placeholders = ','.join('?' for _ in pids)
    where = f'''from COMPOSITE_EVENTS e join PROCESSES p on p.globalPid=(e.globalTid & -16777216)
        where p.pid in ({placeholders}) and e.start>=? and e.start<? and e.threadState=1'''
    parameters = [*pids,start-offset,end-offset]
    total = db.execute('select count(*) ' + where,parameters).fetchone()[0]
    top = db.execute(f'''select s.value as symbol,m.value as module,count(*) as samples
        from SAMPLING_CALLCHAINS c join StringIds s on s.id=c.symbol
        join StringIds m on m.id=c.module
        where c.stackDepth=0 and c.id in (select e.id {where})
        group by c.symbol,c.module order by samples desc limit 30''',parameters).fetchall()
    return dict(running_samples=total, leaf_symbols=[dict(r) for r in top],
        note='User-mode reference-cycle samples; kernel call stacks unavailable at perf_event_paranoid=2.')


def analyze(run, sqlite):
    summary = json.loads((run/'summary.json').read_text())
    if summary['status'] != 'succeeded' or len(summary['workers']) != 1:
        raise ValueError('requires one successful, fully CPU-audited worker')
    worker = summary['workers'][0]
    if not worker['result']['cpu_audited'] or worker['result']['fresh_proofs'] != 8:
        raise ValueError('missing CPU root audit or eight fresh proofs')
    directory = Path(worker['directory'])
    records = jsonl(directory/'profile-clock.jsonl')
    begin = next(r for r in records if r['type']=='prover_start')
    finish = next(r for r in records if r['type']=='prover_end')
    if finish['returncode']:
        raise ValueError('profiled prover failed')
    start, end = begin['before_ns'], finish['clock_ns']
    db = sqlite3.connect(f'file:{sqlite}?mode=ro',uri=True)
    offset, calibration = align_clock(db,records)
    starts, ends, metrics, capture = load_metrics(db,worker['uuid'],summary['linux_profile']['gpu_index'],offset)
    cpu, pids, vanished = cpu_intervals(records)
    cpu_ends = np.array([r['end_ns'] for r in cpu],dtype=np.int64)
    idx = np.clip(np.searchsorted(cpu_ends,ends),0,len(cpu)-1)
    cores = np.array([r['cores'] for r in cpu])[idx]
    admitted, nodes, counts = phases(directory/'prove.log')
    whole = summarize(metrics,weights(starts,ends,[(start,end)]),cores)
    groups = {}
    for name in sorted({p['name'] for p in admitted}):
        rows = [p for p in admitted if p['name']==name]
        groups[name] = dict(intervals=len(rows), duration_seconds=sum(p['duration_seconds'] for p in rows),
            waited_seconds=sum(p['waited_seconds'] for p in rows),
            counters=summarize(metrics,weights(starts,ends,[(p['start_ns'],p['end_ns']) for p in rows]),cores))
    rows = []
    for left in np.arange(start,end,500_000_000,dtype=np.int64):
        right = min(int(left)+500_000_000,end)
        w = weights(starts,ends,[(int(left),right)])
        if w.sum():
            rows.append(dict(seconds=(int(left)-start)/1e9,
                cpu_cores=float(np.average(cores,weights=w)),
                **{key:float(np.average(x,weights=w)) for key,x in metrics.items()}))
    diagnostics = [r[0] for r in db.execute('select text from DIAGNOSTIC_EVENT')]
    diagnostics = [s for s in diagnostics if any(word in s.lower() for word in ('lost','overflow','drop','unable','backtrace','ip samples','buffer'))]
    report = dict(schema='lattica-linux-gpu-profile-v1',run=str(run),
        binary_sha256=summary['binary_sha256'],clock=calibration,capture=capture,
        fresh_proofs=8,cpu_audited=True,proof_seconds=(end-start)/1e9,
        fleet_seconds=summary['elapsed_seconds'],
        fleet_peak_bytes=summary['fleet_sampled_peak_bytes'],
        fleet_events=summary['fleet_events_after'],cleanup_errors=summary['cleanup_errors'],
        fleet_limits_restored=summary['fleet_limits_restored'],
        cpu=dict(pids=pids, approximate_cpu_seconds=sum(r['cores']*(min(r['end_ns'],end)-max(r['start_ns'],start))/1e9
            for r in cpu if r['end_ns']>start and r['start_ns']<end),
            exited_between_samples=vanished,sample_interval_seconds=0.5,
            note='CPU ticks summed across prover process tree; last partial interval of exited processes is not recovered.'),
        whole=whole,phases=groups,phase_intervals=[{**p,'start_seconds':(p['start_ns']-start)/1e9,
            'end_seconds':(p['end_ns']-start)/1e9} for p in admitted],
        nodes=nodes,timeline_records=counts,operation_timings=operation_timings(directory/'prove.log'),
        cpu_stacks=cpu_stacks(db,pids,start,end,offset),
        diagnostics=diagnostics,half_second_bins=rows,
        interpretation=dict(active='GR Active >10%; largely idle means GR Active <=2%.',
            metrics='Device-wide metrics, including desktop graphics. Throughput percentages are peak-relative, not nvidia-smi memory utilization.',
            cpu='CPU busy during GPU-idle windows is evidence of host-side work, not proof of a specific dependency or kernel stall.',
            clocks='NVTX aligns Nsight with CLOCK_MONOTONIC only; raw OpenCL event clocks are not assumed synchronized.',
            phases='Query reconstruction nests within the late phase; phase totals are not additive.',
            per_kernel='OpenCL events are recorded on a separate, unaligned device clock, and event buffers report drops. Operation totals are usable; per-kernel roofline or stall-reason attribution is unavailable.'),
        sources={str(p):digest(p) for p in [run/'summary.json',directory/'profile-clock.jsonl',directory/'prove.log']})
    db.close()
    return report


def plot(report, path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    rows = report['half_second_bins']
    x = [r['seconds'] for r in rows]
    fig, axes = plt.subplots(4,1,figsize=(13,9),sharex=True,
        gridspec_kw={'height_ratios':[2,2,1.4,0.9]},layout='constrained')
    for key,label,color in [('sm','SM active','#2563eb'),('issue','SM instruction issue','#a855f7')]:
        axes[0].plot(x,[r[key] for r in rows],label=label,color=color,lw=1.3)
    for key,label,color in [('dram_read','DRAM read','#059669'),('dram_write','DRAM write','#f59e0b'),('pcie_tx','PCIe TX','#64748b')]:
        axes[1].plot(x,[r[key] for r in rows],label=label,color=color,lw=1.3)
    axes[2].fill_between(x,[r['cpu_cores'] for r in rows],color='#0f766e',alpha=.6)
    axes[2].set_ylabel('CPU cores used')
    axes[2].set_ylim(0,6.5)
    names = ['preprocessing','trace and quotient','quotient commitment through queries','query reconstruction']
    for i,name in enumerate(names):
        for p in report['phase_intervals']:
            if p['name']==name:
                axes[3].broken_barh([(p['start_seconds'],p['duration_seconds'])],(i-.35,.7),facecolors=['#94a3b8','#2563eb','#f59e0b','#059669'][i])
    axes[3].set_yticks(range(4),['Preprocess','Trace / quotient','Late phase','Query'])
    axes[3].set_xlabel('Seconds from prover launch')
    axes[3].set_xlim(0,report['proof_seconds'])
    for ax in axes[:2]:
        ax.set_ylim(0,100)
        ax.set_ylabel('% of peak')
        ax.legend(loc='upper right',ncol=3,framealpha=.95)
    for ax in axes:
        ax.grid(axis='x',alpha=.15)
        ax.spines[['top','right']].set_visible(False)
    fig.suptitle('Eight-input hybrid proof · RTX 5080 · 6 CPU threads\n1000 Hz GPU counters shown as 0.5-second means; CPU sampled every 0.5 seconds',fontsize=14)
    fig.savefig(path)
    fig.savefig(path.with_suffix('.png'),dpi=150)
    plt.close(fig)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',type=Path,required=True)
    ap.add_argument('--sqlite',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--plot',type=Path)
    args=ap.parse_args()
    report=analyze(args.run.resolve(),args.sqlite.resolve())
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    if args.plot:
        plot(report,args.plot)
    print(json.dumps({k:report[k] for k in ('proof_seconds','fleet_seconds','cpu_audited','clock','timeline_records')},indent=2))


if __name__=='__main__':
    main()
