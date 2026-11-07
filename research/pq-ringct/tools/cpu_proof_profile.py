"""Strict acceptance for CPU-only paired component/slice experiments."""
import json
import re
from collections import Counter
from pathlib import Path

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def selection(args, argv):
    if not getattr(args, 'cpu_proof', False):
        return None
    require(args.profile == 'cpu-proof' and args.build_label and args.seconds <= 1200,
            'CPU proof mode requires its recorded CPU profile and 20-minute limit')
    require(not any((args.expect_tests, args.expect_result, args.expect_direct_result,
                     args.full_workflow_case, args.benchmark, args.generation_only)),
            'CPU proof acceptance is separate from other result modes')
    require(Path(argv[0]).name == 'pq-ringct-cpu-proof' and len(argv[1:]) % 2 == 0,
            'CPU proof runner and paired options required')
    options = {}
    allowed = {'--case','--workload','--workers','--threads-per-proof','--retain','--mode',
               '--input','--request','--segments','--repetitions','--generate','--cpu-variant'}
    for k,v in zip(argv[1::2],argv[2::2]):
        require(k in allowed and k not in options, 'unknown/repeated CPU proof option')
        options[k] = v
    selected = dict(transactions={'n3':3,'n4':4}[options.get('--case','n3')],
                    workload=int(options.get('--workload','0')),
                    workers=int(options.get('--workers','1')),
                    threads_per_proof=int(options.get('--threads-per-proof','16')),
                    mode=options.get('--mode','native'), input=options.get('--input',''),
                    request=int(options.get('--request','0')),
                    segments=int(options.get('--segments','2')),
                    repetitions=int(options.get('--repetitions','1')))
    require(options.get('--retain','0') in ('0','1'), 'invalid cache selection')
    selected['cpu_variant'] = options.get('--cpu-variant','reference')
    require(selected['cpu_variant'] in ('reference','hash','memory','combined'), 'invalid CPU variant')
    selected['retain'] = options.get('--retain','0') == '1'
    require(selected['input'] and selected['workload'] in (0,1)
            and 1 <= selected['workers'] <= 16 and 1 <= selected['threads_per_proof'] <= 16
            and selected['workers'] * selected['threads_per_proof'] <= 16
            and selected['mode'] in ('plan','native','native-mix','paired','merge','arithmetic','graph-leaf','graph-parent')
            and selected['request'] >= 0
            and 1 <= selected['segments'] <= 4 and 1 <= selected['repetitions'] <= 5,
            'CPU proof dimensions')
    require(selected['mode']!='native-mix' or (selected['request']==0 and selected['segments']==1),
            'native-mix has a fixed representative selection')
    require(args.host_profile == ('standard' if selected['transactions']==3 else 'expanded-36'),
            'CPU proof host profile differs from N3/N4 selection')
    generate = options.get('--generate')
    require(generate in (None,'1'), 'invalid input generation selection')
    return dict(options=selected, generate=generate=='1')

def require_build(plan, executable):
    if plan.get('profile') == 'cpu-commitment':
        build=json.loads(Path(executable['build_record']).read_text())
        argv=build['command']
        require(argv[1:2]==['build'] and argv.count('--features')==1
                and argv[argv.index('--features')+1]=='cpu-proof-experiment'
                and '--no-default-features' in argv and argv.count('--example')==1
                and argv[argv.index('--example')+1]=='cpu_commitment_profile',
                'commitment screen requires explicit CPU-only example build')
        return
    if plan.get('cpu_proof') is None:
        return
    build=json.loads(Path(executable['build_record']).read_text())
    argv=build['command']
    require(argv[1:2]==['build'] and argv.count('--features')==1
            and argv[argv.index('--features')+1]=='cpu-proof-experiment'
            and '--no-default-features' in argv and argv.count('--bin')==1
            and argv[argv.index('--bin')+1]=='pq-ringct-cpu-proof',
            'CPU proof runner must have an explicit CPU-only build')

def validate(content, selected):
    prefix='CPU_PROOF_INPUTS ' if selected['generate'] else 'CPU_PROOF_PROFILE '
    reports=[json.loads(s[len(prefix):]) for s in content.splitlines() if s.startswith(prefix)]
    require(len(reports)==1, 'missing/duplicate CPU proof terminal')
    r=reports[0]
    if selected['generate']:
        require(r.get('verified') is True and r.get('private_entropy')=='os-fresh'
                and r.get('secret_keys_exported') is False
                and r.get('transactions')==selected['options']['transactions']
                and r.get('workload')==selected['options']['workload'], 'invalid fresh public inputs')
        return r
    require(r.get('schema')=='ringct-cpu-proof-profile-v2' and r.get('backend')=='cpu'
            and r.get('layout')=='paired-v1' and r.get('options')==selected['options']
            and r.get('gpu_contexts')==0 and r.get('gpu_proof_calls')==0
            and r.get('fresh_stark_randomness') is True and r.get('complete_workflow') is False
            and r.get('cleanup_complete') is True, 'CPU proof execution scope mismatch')
    records=r.get('records',[])
    inventories=[json.loads(s[len('CPU_PROOF_INVENTORY '):]) for s in content.splitlines()
                 if s.startswith('CPU_PROOF_INVENTORY ')]
    require(len(inventories)==1 and inventories[0].get('input_sha3_256')==r.get('input_sha3_256')
            and re.fullmatch('[0-9a-f]{64}',r.get('input_sha3_256','')) is not None,
            'CPU input inventory mismatch')
    options=selected['options']
    expected_kinds=Counter()
    mode=options['mode']
    if mode in ('native','paired','merge'):
        requests=[q for q in inventories[0].get('requests',[]) if q.get('request')==options['request']]
        require(sorted(q.get('case') for q in requests)==list(range(options['transactions'])),
                'CPU request inventory incomplete')
        for q in requests:
            count=min(options['segments'],q['segments'])
            require(count>0,'empty native slice')
            expected_kinds['native']+=count
            if mode!='native':
                require(q['kind']=='shake' and (count%2==0 or count==q['segments']),
                        'CPU slice is not a canonical SHAKE pair boundary')
                groups=(count+1)//2
                parents=groups-1 if mode=='merge' else 0
                expected_kinds['paired_compile']+=groups
                expected_kinds['parent_compile']+=parents
                expected_kinds['recursive_proof']+=groups+parents
    elif mode=='native-mix':
        require(options['request']==0 and options['segments']==1,'native-mix selection is fixed')
        expected_kinds.update(arithmetic=6*options['transactions'],native=3*options['transactions'])
    elif mode!='plan':
        count=options['transactions']*options['segments']
        expected_kinds['arithmetic']=count
        if mode!='arithmetic':
            parents=options['transactions']*(options['segments']-1) if mode=='graph-parent' else 0
            expected_kinds['graph_compile']=count
            expected_kinds['graph_parent_compile']=parents
            expected_kinds['graph_proof']=count+parents
    expected=0 if selected['options']['mode']=='plan' else selected['options']['repetitions']
    require(len(records)==expected, 'CPU proof repetitions incomplete')
    digests=set()
    for i, row in enumerate(records):
        require(row.get('repetition')==i and row.get('wall_ns',0)>0 and row.get('cleanup_complete') is True
                and row.get('admitted_device_bytes')==0 and row.get('completed_jobs',0)>0
                and row['completed_jobs']==row.get('planned_jobs')==len(row.get('jobs',[]))
                and 1<=row.get('peak_workers',0)<=selected['options']['workers']
                and 0<row.get('peak_admitted_host_bytes',0)<=((32 if selected['options']['transactions']==3 else 36)<<30),
                'CPU proof accounting or completion mismatch')
        require(Counter(job.get('kind') for job in row['jobs'])==expected_kinds,
                'CPU slice does not cover all selected jobs')
        for j,job in enumerate(row['jobs']):
            require(job.get('id')==j and job.get('elapsed_ns',0)>0, 'CPU job identity/timing')
            if job.get('kind') in ('native','recursive_proof','arithmetic','graph_proof'):
                digest=job.get('proof_digest','')
                require(job.get('mutation_checks')==2 and re.fullmatch('[0-9a-f]{64}',digest) is not None and digest not in digests,
                        'unqualified or repeated CPU proof')
                digests.add(digest)
    require(not any('"backend":"open_cl"' in s or '"backend":"cuda"' in s
                    for s in content.splitlines()), 'GPU stage in CPU proof record')
    return r


def validate_commitment(content, variant, tile):
    prefix='CPU_COMMITMENT_SCREEN '
    rows=[json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    require(len(rows)==6 and {(r.get('width'),r.get('repetition')) for r in rows}
            =={(w,i) for w in (94,200) for i in range(3)}, 'incomplete commitment screen')
    for r in rows:
        require(r.get('variant')==variant and r.get('tile_rows')==tile and r.get('threads')==16
                and r.get('height')==1<<18 and r.get('verified') is True
                and isinstance(r.get('commit_ns'),int) and r['commit_ns']>0,
                'invalid commitment screen evidence')
    return rows
