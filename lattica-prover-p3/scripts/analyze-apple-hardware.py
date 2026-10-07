#!/usr/bin/env python3
"""Reproducible analysis of an already completed Apple diagnostic pair."""
import argparse
import collections
import hashlib
import html
import json
from pathlib import Path
import re
import statistics
from datetime import datetime, timezone

GIB=1<<30
ROOT=Path(__file__).resolve().parents[1]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def fields(line):
    return {m[1]:m[2] if m[2] is not None else m[3]
            for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))',line)}

def union_ns(intervals):
    total=0;end=None
    for start,stop in sorted(intervals):
        if stop<start:raise ValueError('reversed interval')
        total+=max(0,stop-max(start,end if end is not None else start))
        end=max(stop,end if end is not None else stop)
    return total

def log_lines(path):
    with Path(path).open() as source:
        yield from source

def analyze_log(path):
    commands={};waits=[];timeline=collections.defaultdict(list);spans=collections.defaultdict(int)
    checkpoints=[];metal_checks=[];clocks=[];nodes=[];quotients=[];last_metal={};duplicates=0
    for line in log_lines(path):
        if line.startswith('metal_profile '):
            row=json.loads(line[len('metal_profile '):])
            if row['kind']=='command':
                if row['id'] in commands:duplicates+=1
                commands[row['id']]=row
            elif row['kind']=='wait':waits.append(row)
        elif line.startswith('host_timeline_interval '):
            row=fields(line);timeline[row['thread']].append((int(row['start_ns']),int(row['end_ns']),row['target'],row['name']))
        elif line.startswith('performance_span '):
            row=fields(line);spans[row['target']+' / '+row['name']]+=int(row['total_ns'])
        elif line.startswith('host_timeline_checkpoint '):checkpoints.append(fields(line))
        elif line.startswith('metal_profile_checkpoint '):metal_checks.append(fields(line))
        elif line.startswith('host_timeline_clock '):clocks.append(fields(line))
        elif line.startswith('grouped_node_complete '):nodes.append(fields(line))
        elif line.startswith('metal_quotient '):quotients.append(fields(line))
        elif line.startswith('metal_checkpoint '):last_metal=fields(line)
    phases=collections.defaultdict(lambda:{'commands':0,'dispatches':0,'gpu_seconds':0.0})
    gpu=[];invalid=0;phase_intervals=collections.defaultdict(list)
    for row in commands.values():
        p=phases[row['phase']];p['commands']+=1;p['dispatches']+=row['dispatches']
        if row['timestamp_valid']:
            interval=(row['gpu_start_ns'],row['gpu_end_ns']);gpu.append(interval)
            phase_intervals[row['phase']].append(interval)
            p['gpu_seconds']+=(interval[1]-interval[0])/1e9
        else:invalid+=1
    for name,p in phases.items():
        p['gpu_duration_sum_seconds']=p['gpu_seconds']
        p['gpu_seconds']=union_ns(phase_intervals[name])/1e9
    wait_intervals=[(w['start_ns'],w['end_ns']) for w in waits]
    per_thread=collections.defaultdict(list)
    for row in waits:per_thread[row['thread']].append((row['start_ns'],row['end_ns']))
    timeline_overlaps=0;entered=collections.defaultdict(int)
    for intervals in timeline.values():
        previous=None
        for start,end,target,name in sorted(intervals):
            timeline_overlaps+=int(previous is not None and start<previous)
            previous=max(previous or end,end)
            entered[target+' / '+name]+=end-start
    mapped=[]
    for c in clocks:
        before=int(c['mach_before_ns']);after=int(c['mach_after_ns']);relative=int(c['timeline_ns'])
        mapped.append({'offset_ns':(before+after)//2-relative,'uncertainty_ns':after-before})
    cpu_samples=[]
    for sample in sorted(Path(path).parent.glob('cpu-sample-*.txt')):
        lines=sample.read_text(errors='replace').splitlines()
        # macOS sample supplies an explicitly aggregated, non-tree top-of-stack section.
        start=next((i for i,s in enumerate(lines) if s.startswith('Sort by top of stack')) ,None)
        top=[]
        if start is not None:
            for s in lines[start+1:]:
                if s.startswith('Binary Images:'):break
                if s.strip():top.append(s.strip())
                if len(top)>=14:break
        cpu_samples.append({'file':str(sample),'sha256':digest(sample),'top_of_stack':top})
    quality={'gpu_commands':len(commands),'duplicate_ids':duplicates,'invalid_gpu_timestamps':invalid,
             'dispatch_accounting_match':sum(c['dispatches'] for c in commands.values())==int(last_metal['kernel_calls']) if last_metal else None,
             'blit_accounting_match':sum(c['dispatches']==0 for c in commands.values())==int(last_metal['blit_calls']) if last_metal else None,
             'unknown_wait_ids':sum(w['id'] is None for w in waits),
             'metal_outstanding_at_last_checkpoint':int(metal_checks[-1]['outstanding']) if metal_checks else None,
             'metal_dropped':max((int(c['dropped']) for c in metal_checks),default=0),
             'host_dropped':max((int(c['dropped']) for c in checkpoints),default=0),
             'host_malformed':max((int(c['malformed']) for c in checkpoints),default=0),
             'host_thread_interval_overlaps':timeline_overlaps,
             'clock_maps':len(mapped),'clock_max_uncertainty_ns':max((m['uncertainty_ns'] for m in mapped),default=0)}
    return {'worker_log_sha256':digest(path),'phases':dict(phases),'gpu_busy_union_seconds':union_ns(gpu)/1e9,
            'cpu_wait_union_seconds':union_ns(wait_intervals)/1e9,
            'cpu_wait_thread_seconds':sum(union_ns(v) for v in per_thread.values())/1e9,
            'entered_thread_wall_seconds':{k:v/1e9 for k,v in sorted(entered.items(),key=lambda p:-p[1])},
            'inclusive_spans_seconds':{k:v/1e9 for k,v in sorted(spans.items(),key=lambda p:-p[1])},
            'quality':quality,'clock_correlations':mapped,'nodes':nodes,'quotient_programs':quotients,
            'last_metal':last_metal,'cpu_samples':cpu_samples}

def component_summary(path):
    report=json.loads(Path(path).read_text());result=[]
    for n in sorted({s['elements'] for s in report['samples']}):
        med={b:statistics.median(s['ns_per_element'] for s in report['samples'] if s['elements']==n and s['backend']==b) for b in ('p3','sme2')}
        result.append({'elements':n,'p3_ns_per_element':med['p3'],'sme2_ns_per_element':med['sme2'],'sme2_speedup':med['p3']/med['sme2']})
    return {'path':str(path),'sha256':digest(path),'results':result,'historical_component_only':True}

def recommendations(analyses, windows):
    reference=analyses['reference'];resident=analyses['resident'];seconds=windows[0]['seconds']
    result=[]
    for phase,title,change,location in (
        ('lde_absorb','Specialize streaming LDE hashing for the Apple GPU',
         'Profile register pressure and integer arithmetic in the fused LDE-to-Poseidon path; prototype one exact-integer specialization and compare layouts without adding host copies.',
         'src/metal_compute/kernels.metal: lde_absorb; src/block_v2/gpu_hash/engine/lde_execute.rs'),
        ('ntt_tile','Tune the Metal NTT around the actual transform geometry',
         'Evaluate stage fusion, threadgroup layout and twiddle reuse on the observed sizes. Retain the reference kernel as the fallback; the existing optimized variant is not automatically faster.',
         'src/metal_compute/kernels.metal: ntt_tile / ntt_tile_cached; src/metal_compute/resident.rs'),
    ):
        p=reference['phases'].get(phase,{'gpu_seconds':0,'commands':0})
        result.append({'title':title,'classification':'measured hotspot; proposed optimization',
            'evidence':f"The reference spent {p['gpu_seconds']:.2f}s in {p['commands']:,} command buffers for {phase}.",
            'implementation':change,'integration':location,
            'validation':'Use observed matrix sizes; compare exact outputs, commitments and paths with the CPU oracle, then the existing proof-byte equivalence test. Only a winning component warrants one matched full-proof pair.',
            'benefit_and_risk':f"Halving this kernel time gives an optimistic ceiling of {p['gpu_seconds']/2:.2f}s ({50*p['gpu_seconds']/seconds:.1f}% of reference latency), assuming all savings reach the critical path. This is a projection, not a measured gain. Register spills, occupancy and extra memory traffic can erase the benefit. Effort is medium to high; retain the generic Metal and CPU paths."})
    result.sort(key=lambda r:reference['phases'].get('lde_absorb' if 'hashing' in r['title'] else 'ntt_tile',{}).get('gpu_seconds',0),reverse=True)
    opening=sum(p['commands'] for name,p in reference['phases'].items() if name.startswith('opening_'))
    opening_time=sum(p['gpu_seconds'] for name,p in reference['phases'].items() if name.startswith('opening_'))
    quotient=resident['phases'].get('quotient_eval',{}).get('gpu_seconds',0)
    result.append({'title':'Reduce fine-grained dispatch and CPU/GPU boundary overhead',
        'classification':'measured work amplification; synchronization hypothesis',
        'evidence':f"The reference issued {opening:,} opening command buffers for {opening_time:.2f}s of GPU execution. The resident run spent {quotient:.2f}s in the quotient interpreter. Command counts, wait intervals and CPU samples are available in the evidence.",
        'implementation':'Start with a component experiment that batches adjacent opening reductions without CPU-visible dependencies. Separately retain CPU quotient evaluation as the control before considering any replacement of the row-wise Metal interpreter. Preserve buffer ownership, dependency ordering and bounded workspaces.',
        'integration':'src/metal_compute/mod.rs: compute_command / flush; src/block_v2/opening_pcs.rs; src/block_v2/gpu_quotient_prover/metal.rs',
        'validation':'Check unchanged reduced values, transcript order and proof bytes; verify fewer submissions without extra waits or copied bytes. Treat dispatch batching and quotient placement as separate experiments.',
        'benefit_and_risk':'No numeric speedup is claimed: queued waits include real GPU work, and host work is not all launch overhead. Removing dependencies incorrectly can corrupt proofs; increasing batching can raise live memory. Effort is medium to high.'})
    return result

def memory_summary(run):
    path=Path(str(run)+'-system-memory.jsonl')
    samples=[json.loads(s) for s in path.read_text().splitlines()];good=[s for s in samples if 'vm_pages' in s]
    result=[]
    for label in ('reference','resident'):
        resources=[json.loads(s) for s in (run/label/'resources.jsonl').read_text().splitlines()]
        rows=[s for s in good if resources[0]['monotonic']<=s['monotonic']<=resources[-1]['monotonic']]
        result.append({'label':label,'sample_count':len(rows),
            'peak_prover_footprint_bytes':max(sum(p.get('phys_footprint_bytes',0) for p in s['benchmark_processes'] if p['process']=='block-v2-metal-grouped-probe') for s in rows),
            'min_system_free_bytes':min(s['vm_pages']['Pages free']*s['page_size_bytes'] for s in rows),
            'pressure_levels':sorted({s['pressure'] for s in rows})})
    return result,{'path':str(path),'sha256':digest(path),'sampling_errors':len(samples)-len(good)}

HARDWARE_ROUTES=[
    {'route':'Metal GPU + unified memory','verdict':'Highest priority','reason':'Already executes exact transforms, Poseidon/Merkle work, reductions and experimental quotient evaluation. Prioritize measured kernel costs and CPU/GPU boundaries; shared DRAM does not remove layout copies or synchronization.'},
    {'route':'NEON / packed Plonky3','verdict':'Keep as CPU baseline','reason':'p3-goldilocks 0.6.1 selects aarch64_neon; the measured packing width is two u64 elements. Inspect scalar tails, batch inversion, FRI and reductions before adding another backend.'},
    {'route':'SME2 / streaming SVE','verdict':'Defer general substitution','reason':'This Mac reports SME and SME2; the existing C bridge uses eight streaming u64 lanes but lost to NEON at every measured size. Consider only a measured coarse operation that amortizes transitions; the experiment does not use the ZA matrix tile.'},
    {'route':'Accelerate / vDSP','verdict':'No direct proof-arithmetic replacement identified','reason':'The hot path needs exact Goldilocks and cubic extension arithmetic, not an ordinary floating-point FFT or BLAS product. A limb decomposition would require explicit exactness bounds and conversion-cost evidence.'},
    {'route':'Private Apple AMX instructions','verdict':'Excluded from the recommended path','reason':'Use supported Apple/Arm interfaces. No private instruction backend is needed to investigate the measured hotspots, and none was found in the current prover.'},
    {'route':'M5 GPU TensorOps accelerators','verdict':'Low priority; feasibility unproved','reason':'These are GPU accelerators, distinct from the Neural Engine. An exact mapping of modular arithmetic and reduction, including integer ranges and conversion costs, has not been established for this workload.'},
    {'route':'Neural Engine / Core ML','verdict':'No practical hot-path mapping identified','reason':'The current workload is exact cryptographic arithmetic with transcript dependencies, not model inference. Core ML typed execution is not an established exact modular-arithmetic backend. Do not add an unrelated model just to use the engine.'},
]

STACK_AUDIT=[
    {'stage':'Zig node, wallet and acceptance','implementation':'src/node.zig; src/wallet.zig; src/poseidon2.zig','finding':'Inspected production entry points and native hashing. No timing attribution from the recursive fixture; hardware changes here need a separate production-path measurement.'},
    {'stage':'Zig/Rust FFI and encoding','implementation':'src/ffi.zig; src/prover_abi.zig; lattica-prover-p3/src/lib.rs; src/config.rs','finding':'Witness and proof buffers cross the C ABI; Zig returns an exact-sized proof copy. Production spend proving and canonical proof encoding are separate from the experimental Metal worker.'},
    {'stage':'Witness, symbolic programs and preprocessing','implementation':'src/block_v2/recursive.rs; src/bin/grouped_common/mod.rs','finding':'CPU work with separate setup spans. Wrapper and merge shapes reuse setup within a job. The end-of-job preprocessing cache retains only up to 2 GiB and otherwise evicts; increasing retention needs a memory study, not a blanket cache-size increase.'},
    {'stage':'CPU field arithmetic and openings','implementation':'p3-goldilocks 0.6.1 aarch64_neon; src/block_v2/opening_pcs.rs; src/block_v2/batched_fri.rs','finding':'NEON is already selected by the native build. Opening interpolation uses a packed dot product; batch inversion, FRI and host reductions remain candidates only where the captured CPU evidence shows cost.'},
    {'stage':'GPU transforms and commitments','implementation':'src/metal_compute/kernels.metal; src/block_v2/gpu_hash/engine/lde_execute.rs','finding':'Exact Goldilocks NTT/LDE and Poseidon/Merkle operations run on Metal. Per-kernel timing identifies the dominant command groups; optimized variants are experiments, not automatically selected improvements.'},
    {'stage':'Resident quotient and data movement','implementation':'src/block_v2/gpu_quotient_prover/metal.rs; src/metal_compute/quotient.metal; src/metal_compute/resident.rs','finding':'The resident quotient path marshals inputs on the CPU, then interprets validated postfix instructions per GPU row using exact cubic arithmetic. SharedWords synchronizes CPU-visible access; unified memory still has conversion and ordering costs.'},
    {'stage':'Proof output and independent acceptance','implementation':'src/block_v2/codec.rs; src/bin/block_v2_grouped_artifact_audit.rs','finding':'Each benchmark deletes local inner artifacts, retains a root-only bundle and requires an independent CPU audit. No protocol or verifier behavior changed in this analysis.'},
]

SOURCES=[
    {'title':'Apple XNU: ARM SME','url':'https://github.com/apple-oss-distributions/xnu/blob/main/doc/arm/sme.md','use':'Streaming-mode state, transitions and vector/matrix distinctions.'},
    {'title':'Apple Accelerate overview','url':'https://developer.apple.com/accelerate/','use':'Supported vector, DSP and matrix-library interfaces.'},
    {'title':'Apple: custom operations with Metal tensors','url':'https://developer.apple.com/videos/play/wwdc2026/330/','use':'M5 GPU TensorOps and data-format requirements; not a modular-arithmetic guarantee.'},
    {'title':'Apple Core ML typed execution','url':'https://apple.github.io/coremltools/docs-guides/source/typed-execution.html','use':'Compute-unit selection and execution precision.'},
    {'title':'Apple Metal GPU counter sampling','url':'https://developer.apple.com/documentation/metal/gpu-counters-and-counter-sample-buffers','use':'Optional richer future profiling; this run uses existing command-buffer timestamps.'},
]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--sme2',type=Path,required=True)
    parser.add_argument('--html',type=Path,required=True)
    args=parser.parse_args();run=args.run.resolve();raw=json.loads((run/'result.json').read_text())
    if raw['status']!='COMPLETE_VERIFIED_SCREEN' or not raw.get('diagnostic_profile'):
        raise RuntimeError('requires a complete, verified diagnostic pair')
    windows=raw['windows']
    if [w['label'] for w in windows]!=['reference','resident'] or any(w['workers']!=1 for w in windows):
        raise RuntimeError('requires one reference and one resident worker, sequentially')
    analyses={w['label']:analyze_log(run/w['label']/'job-0/worker.log') for w in windows}
    for label,a in analyses.items():
        q=a['quality']
        if not q['gpu_commands'] or not q['clock_maps'] or any(q[k] for k in ('duplicate_ids','invalid_gpu_timestamps','host_malformed','host_thread_interval_overlaps')):
            raise RuntimeError(f'{label}: invalid trace quality {q}')
        if not q['dispatch_accounting_match'] or not q['blit_accounting_match']:
            raise RuntimeError(f'{label}: diagnostic work counts disagree with native accounting')
        if len(a['nodes'])!=7 or any(n['resumed']!='false' for n in a['nodes']):raise RuntimeError('not seven fresh proofs')
    memory,observer=memory_summary(run)
    ratio=windows[1]['seconds']/windows[0]['seconds']
    report={'schema':'apple-hardware-analysis-v1','status':'COMPLETE','generated_utc':datetime.now(timezone.utc).isoformat(),
        'headline':f'The resident pipeline took {ratio:.2f}× as long, even without a competing worker.',
        'summary':f"Retain the reference path for latency. The resident quotient interpreter accounts for {analyses['resident']['phases'].get('quotient_eval',{}).get('gpu_seconds',0):.2f}s of GPU intervals. The best next experiments target the measured reference kernels and excessive fine-grained dispatch.",
        'git_commit':raw['git_commit'],'windows':windows,'analysis':analyses,'build':raw['build'],
        'hardware':raw['hardware'],'diagnostic_profile':True,'memory_observations':memory,'observer':observer,
        'kernel_variant':raw['kernel_variant'],'workgroup':raw['workgroup'],'kernel_screen':raw.get('kernel_screen'),
        'raw_result_path':str(run/'result.json'),'raw_result_sha256':digest(run/'result.json'),
        'analyzer_sha256':digest(__file__),'qualification':raw['qualification'],
        'sme2':component_summary(args.sme2),'hardware_routes':HARDWARE_ROUTES,'stack_audit':STACK_AUDIT,'sources':SOURCES,
        'recommendations':recommendations(analyses,windows),
        'limitations':[
            'One instrumented pair, not a statistical performance-promotion experiment. CPU sampling and trace recording add overhead; there were no automatic repeats.',
            'The unit is an eight-wallet research aggregation with seven recursive proofs and an independent CPU audit. It is not a full block or accepted-transaction throughput.',
            'Host entered-span durations are wall time per thread, not CPU time; inclusive spans, CPU waits and GPU intervals overlap and must not be summed.',
            'GPU groups identify expensive work, not an exclusive end-to-end breakdown. Quantitative improvement ceilings are conditional projections, not measured gains.',
            'Both configurations use the same unified-memory Mac. Historical Linux figures differ in hardware and implementation and do not isolate a unified-memory architecture effect.',
            'Only Command Line Tools were installed: xctrace and the offline metal compiler were unavailable. Existing Metal timestamps and macOS sample were used; no Xcode installation was required.',
            'Production Zig/C-ABI paths were inspected, but this fixture profiles the experimental recursive prover. Further production-path measurements are needed before claiming production latency gains.',
        ]}
    diagnostics=run/'diagnostics'
    report['diagnostic_artifacts']={p.name:{'path':str(p),'sha256':digest(p)} for p in sorted(diagnostics.glob('*')) if p.is_file()}
    for name in ('readiness.json','hardware.json','post-run-process-check.json'):
        p=diagnostics/name
        if p.exists():report[name[:-5]]=json.loads(p.read_text())
    for w in windows:
        failed=[s for s in w.get('diagnostic_samples',[]) if s['status']!='PASS']
        if failed:report['limitations'].append(f"{w['label']} CPU sampler failures: {failed}")
    for label,a in analyses.items():
        if a['quality']['metal_dropped'] or a['quality']['host_dropped']:
            report['limitations'].append(f"{label} has dropped diagnostic records; timing attribution is incomplete and must not be extrapolated to unobserved work.")
    (run/'analysis.json').write_text(json.dumps(report,indent=2)+'\n')
    render(report,args.html)
    print(json.dumps({'status':report['status'],'latency_ratio':ratio,'html':str(args.html),'trace_quality':{k:v['quality'] for k,v in analyses.items()}},indent=2))

def render(report, destination):
    esc=lambda v:html.escape(str(v))
    windows=report['windows'];analyses=report['analysis'];maximum=max(w['seconds'] for w in windows)
    latency=''.join(f'<div class="row"><b>{esc(w["label"])} · 1 worker · 18 threads</b><div class="track"><div class="bar latency-bar" style="width:{100*w["seconds"]/maximum:.2f}%"></div></div><strong>{w["seconds"]:.2f} seconds</strong><small>7 fresh proofs · independent CPU audit PASS · {w["aggregate_peak_rss_bytes"]/GIB:.2f} GiB peak sampled process RSS</small></div>' for w in windows)
    kernel_sections=[]
    for label,a in analyses.items():
        phases=sorted(a['phases'].items(),key=lambda p:-p[1]['gpu_seconds'])[:8]
        scale=max((p['gpu_seconds'] for _,p in phases),default=1)
        bars=''.join(f'<div class="kernel-row"><span>{esc(name)}</span><div class="track"><div class="bar kernel-bar" style="width:{100*p["gpu_seconds"]/scale:.2f}%"></div></div><b>{p["gpu_seconds"]:.2f}s</b><small>{p["commands"]:,} command buffers · {p["dispatches"]:,} dispatches</small></div>' for name,p in phases)
        kernel_sections.append(f'<article><h3>{esc(label)}</h3>{bars}<p>GPU active intervals: {a["gpu_busy_union_seconds"]:.2f}s union. CPU waiting: {a["cpu_wait_union_seconds"]:.2f}s union across recorded wait calls.</p></article>')
    recommendations=''.join(f'<article class="card"><p class="eyebrow">Priority {i+1} · {esc(item["classification"])}</p><h3>{esc(item["title"])}</h3><p>{esc(item["evidence"])}</p><p><b>Implementation:</b> {esc(item["implementation"])}</p><p><b>Validation:</b> {esc(item["validation"])}</p><p><b>Benefit and risk:</b> {esc(item["benefit_and_risk"])}</p><small>{esc(item["integration"])}</small></article>' for i,item in enumerate(report['recommendations']))
    routes=''.join(f'<tr><td>{esc(r["route"])}</td><td>{esc(r["verdict"])}</td><td>{esc(r["reason"])}</td></tr>' for r in report['hardware_routes'])
    stack=''.join(f'<tr><td>{esc(s["stage"])}</td><td>{esc(s["finding"])}<small>{esc(s["implementation"])}</small></td></tr>' for s in report['stack_audit'])
    quality=''.join(f'<tr><td>{esc(label)}</td><td>{a["quality"]["gpu_commands"]:,}</td><td>{a["quality"]["metal_dropped"]}</td><td>{a["quality"]["host_dropped"]}</td><td>{a["quality"]["duplicate_ids"]}</td><td>{a["quality"]["invalid_gpu_timestamps"]}</td></tr>' for label,a in analyses.items())
    samples=''.join(f'<details><summary>{esc(label)} · {esc(Path(s["file"]).stem)}</summary><pre>{esc(chr(10).join(s["top_of_stack"][:8]))}</pre></details>' for label,a in analyses.items() for s in a['cpu_samples'])
    sme=''.join(f'<tr><td>{r["elements"]:,}</td><td>{r["p3_ns_per_element"]:.3f}</td><td>{r["sme2_ns_per_element"]:.3f}</td><td>{r["sme2_speedup"]:.2f}×</td></tr>' for r in report['sme2']['results'])
    sources=''.join(f'<li><a href="{esc(r["url"])}">{esc(r["title"])}</a> — {esc(r["use"])}</li>' for r in report['sources'])
    notes=''.join(f'<li>{esc(n)}</li>' for n in report['limitations'])
    memory=''.join(f'<tr><td>{esc(m["label"])}</td><td>{m["peak_prover_footprint_bytes"]/GIB:.2f}</td><td>{m["min_system_free_bytes"]/GIB:.2f}</td><td>{esc(m["pressure_levels"])}</td></tr>' for m in report['memory_observations'])
    data=json.dumps(report).replace('<','\\u003c')
    destination.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lattica · Apple hardware acceleration analysis</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101724;color:#e9eef8;font:16px/1.6 system-ui}}main{{max-width:1100px;margin:auto;padding:38px 24px 64px}}h1{{font-size:clamp(30px,5vw,46px);line-height:1.15;max-width:850px}}h2{{margin-top:42px}}h3{{line-height:1.3}}a{{color:#93d9ef}}small,.muted{{display:block;color:#b4c2d7}}.eyebrow{{color:#67c9ba;font-weight:700;letter-spacing:.07em;text-transform:uppercase;font-size:12px}}.callout,.card{{background:#182234;border:1px solid #334056;border-radius:12px;padding:20px;margin:20px 0}}.callout{{border-left:4px solid #67c9ba}}.row{{margin:24px 0}}.track{{background:#29364b;border-radius:5px;height:24px;margin:8px 0}}.bar{{height:100%;border-radius:5px;background:#67c9ba}}.kernel-row{{margin:20px 0}}.kernel-row span{{font-family:ui-monospace,monospace;overflow-wrap:anywhere}}.kernel-row .track{{height:17px}}.kernel-row small{{font-size:12px}}.columns{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:32px}}.flow{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}}.box{{background:#25334a;padding:10px 14px;border-radius:8px}}.table-scroll{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:14px}}td,th{{padding:12px 8px;text-align:left;border-bottom:1px solid #334056;vertical-align:top}}button{{border:0;border-radius:7px;background:#67c9ba;color:#101724;padding:12px 18px;font:inherit;cursor:pointer}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}code{{overflow-wrap:anywhere}}@media(max-width:650px){{.columns{{grid-template-columns:1fr}}main{{padding:24px 20px}}.card{{padding:16px}}}}
</style><main><p class="eyebrow">Measured analysis · October 4, 2026</p><h1>Where Apple hardware can help Lattica</h1><p>Apple M5 Pro · 6 Super + 12 Performance CPU cores · 64 GiB unified memory</p>
<div class="callout"><b>{esc(report['headline'])}</b><p>{esc(report['summary'])}</p></div>
<h2>One verified aggregation: observed latency</h2><p>One worker per configuration, run sequentially. Lower is better. Both runs include diagnostic tracing and two five-second CPU samples.</p>{latency}
<h2>The stack and the measured boundary</h2><p><b>Production path — inspected, not timed by this fixture</b></p><div class="flow"><span class="box">Zig node / wallet</span>→<span class="box">C ABI + encoded witness</span>→<span class="box">Rust spend / batch prover</span>→<span class="box">Proof encoding + host verification</span></div><p><b>Research aggregation — measured here</b></p><div class="flow"><span class="box">4 wrappers + 3 merges</span>→<span class="box">Trace + preprocessing</span>→<span class="box">LDE / commitment / quotient / FRI</span>→<span class="box">Root-only CPU audit</span></div><p>CPU and Metal work alternate inside the proving stages. Goldilocks field arithmetic, extension-field arithmetic and transcript hashing require exact results. The Metal research feature does not activate the Zig production path.</p>
<div class="table-scroll"><table><thead><tr><th>Stack stage</th><th>Implementation audit</th></tr></thead><tbody>{stack}</tbody></table></div>
<h2>Where the GPU spends time</h2><p>Union of completed command-buffer intervals within each kernel group. Each configuration has its own horizontal scale; groups can overlap. CPU waits overlap GPU work and must not be added to it.</p><div class="columns">{''.join(kernel_sections)}</div>
<h2>CPU stack samples</h2><p>Two five-second snapshots per worker, sampled every 10 ms. These are top-of-stack sample counts across threads, including blocked threads; they are not CPU-time percentages. They help distinguish host arithmetic from waiting and Rayon coordination.</p>{samples}
<h2>Ranked implementation opportunities</h2><p>These are implementation recommendations, not measured speedup claims. No new acceleration kernel was implemented for this analysis.</p>{recommendations}
<h2>Hardware suitability</h2><div class="table-scroll"><table><thead><tr><th>Route</th><th>Verdict</th><th>Reason</th></tr></thead><tbody>{routes}</tbody></table></div>
<h2>SME2: reuse the existing evidence</h2><p>Historical isolated multiplication test; median nanoseconds per element. The packed Plonky3 baseline uses NEON. A ratio below 1 means SME2 was slower. These are not full-proof timings.</p><div class="table-scroll"><table><thead><tr><th>Elements</th><th>NEON ns/element</th><th>SME2 ns/element</th><th>SME2 speed ratio</th></tr></thead><tbody>{sme}</tbody></table></div>
<h2>Memory and trace quality</h2><p>RSS, physical footprint, wired and compressed memory overlap. Physical footprint below is sampled about every two seconds; pressure level 1 means normal.</p><div class="table-scroll"><table><thead><tr><th>Configuration</th><th>Prover footprint peak GiB</th><th>System free minimum GiB</th><th>Pressure levels</th></tr></thead><tbody>{memory}</tbody></table></div><div class="table-scroll"><table><thead><tr><th>Trace</th><th>GPU commands</th><th>GPU records dropped</th><th>Host segments dropped</th><th>Duplicate IDs</th><th>Invalid GPU timestamps</th></tr></thead><tbody>{quality}</tbody></table></div>
<h2>Interpretation and limits</h2><ul>{notes}</ul><p>Base commit: <code>{esc(report['git_commit'])}</code>. The evidence records the exact modified source and binary hashes, raw logs, sampler results and analysis-script hash.</p>
<h2>Primary hardware references</h2><ul>{sources}</ul><button id="download">Download analysis evidence</button><details><summary>Full evidence and provenance</summary><pre id="details"></pre></details></main>
<script id="evidence" type="application/json">{data}</script><script>const data=JSON.parse(document.getElementById('evidence').textContent);document.getElementById('details').textContent=JSON.stringify(data,null,2);document.getElementById('download').onclick=()=>{{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{{type:'application/json'}}));a.download='apple-hardware-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0)}};</script></html>''')

if __name__=='__main__':
    main()
