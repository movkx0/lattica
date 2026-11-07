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
        '--cpu-hash-kernel','--identity-overlap','--transaction','--compare-target','--candidate-first',
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
    selected['cpu_hash_kernel'] = options.get('--cpu-hash-kernel','existing')
    require(selected['cpu_hash_kernel'] in ('existing','interleaved2','interleaved4'), 'invalid CPU hash kernel')
    require(selected['cpu_hash_kernel']=='existing' or selected['cpu_variant'] in ('hash','combined'), 'interleaving requires tiled CPU hashing')
    for flag in ('identity-overlap','compare-target','candidate-first'):
        require(options.get('--'+flag,'0') in ('0','1'), 'invalid CPU boolean option')
        selected[flag.replace('-','_')] = options.get('--'+flag,'0') == '1'
    selected['transaction'] = int(options['--transaction']) if '--transaction' in options else None
    require(selected['transaction'] is None or 0 <= selected['transaction'] < selected['transactions'], 'transaction outside case')
    require(not selected['candidate_first'] or selected['compare_target'], 'candidate-first requires comparison')
    require(not selected['compare_target'] or (selected['transaction'] is not None
        and selected['workers']==1 and selected['threads_per_proof']==16 and not selected['retain']
        and selected['repetitions']==1 and selected['segments']==2 and selected['cpu_variant']=='combined'
        and selected['mode'] in ('paired','graph-parent')), 'invalid cold target comparison')
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
    require(r.get('schema')=='ringct-cpu-proof-profile-v3' and r.get('backend')=='cpu'
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
    cases = list(range(options['transactions'])) if options['transaction'] is None else [options['transaction']]
    expected_kinds=Counter()
    mode=options['mode']
    if mode in ('native','paired','merge'):
        requests=[q for q in inventories[0].get('requests',[]) if q.get('request')==options['request'] and q.get('case') in cases]
        require(sorted(q.get('case') for q in requests)==cases,
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
        expected_kinds.update(arithmetic=6*len(cases),native=3*len(cases))
    elif mode!='plan':
        count=len(cases)*options['segments']
        expected_kinds['arithmetic']=count
        if mode!='arithmetic':
            parents=len(cases)*(options['segments']-1) if mode=='graph-parent' else 0
            expected_kinds['graph_compile']=count
            expected_kinds['graph_parent_compile']=parents
            expected_kinds['graph_proof']=count+parents
    if options['compare_target']:
        compiler, proof = ('paired_compile','recursive_proof') if mode=='paired' else ('graph_parent_compile','graph_proof')
        expected_kinds[compiler]-=1
        expected_kinds[proof]-=1
        expected_kinds.update(target_compile=1,target_comparison=1)
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
            require(isinstance(job.get('service_ns'),int) and job['service_ns'] > 0, 'CPU service timing')
            if job.get('kind') in ('native','arithmetic'):
                require(job.get('cold_input_service_upper_ns') == job['service_ns'] + r.get('preparation_ns',0), 'native cold input preparation omitted')
            comparisons=job.get('comparisons',[])
            if job.get('kind')=='target_compile':
                require(0 < job.get('dependency_storage_bytes',0) <= 64 << 20
                    and job.get('compiled_storage_bytes',0) > job['dependency_storage_bytes'], 'target child backing was not retained/accounted')
            proofs=[job]
            if job.get('kind')=='target_comparison':
                require(options['compare_target'] and len(comparisons)==2 and job.get('proof_digest') is None,
                    'missing or duplicated target comparison')
                require([c.get('candidate') for c in comparisons]==[options['candidate_first'],not options['candidate_first']], 'target comparison order')
                for c in comparisons:
                    require(c.get('hash_kernel')==(options['cpu_hash_kernel'] if c['candidate'] else 'existing')
                        and c.get('identity_overlap')==(options['identity_overlap'] and c['candidate']), 'target tuning mismatch')
                    observation=c.get('observation',{})
                    require(observation.get('prepared_hit') is False and observation.get('compile_ns',0)>0
                        and observation.get('kind')==('recursive_proof' if mode=='paired' else 'graph_proof')
                        and observation.get('id')==j and not observation.get('comparisons')
                        and observation.get('service_ns',0)>=observation.get('compile_ns',0)+observation.get('registration_ns',0),
                        'target comparison omitted cold preparation')
                proofs=[c['observation'] for c in comparisons]
                require(job.get('mutation_checks')==4, 'target negative checks incomplete')
            else:
                require(not comparisons, 'unexpected target comparison')
            for proof in proofs:
                if proof.get('kind') in ('native','recursive_proof','arithmetic','graph_proof'):
                    digest=proof.get('proof_digest','')
                    require(proof.get('mutation_checks')==2 and re.fullmatch('[0-9a-f]{64}',digest) is not None and digest not in digests,
                        'unqualified or repeated CPU proof')
                    digests.add(digest)
    require(not any('"backend":"open_cl"' in s or '"backend":"cuda"' in s
                    for s in content.splitlines()), 'GPU stage in CPU proof record')
    return r


def validate_commitment(content, variant, tile, kernel='existing', threads=16):
    prefix='CPU_COMMITMENT_SCREEN '
    rows=[json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    require(len(rows)==12 and {(r.get('width'),r.get('matrices'),r.get('repetition')) for r in rows}
        =={(w,n,i) for w,n in ((94,1),(200,1),(51,1),(3,16)) for i in range(3)}, 'incomplete commitment screen')
    for r in rows:
        require(r.get('variant')==variant and r.get('tile_rows')==tile and r.get('threads')==threads and r.get('hash_kernel')==kernel
                and r.get('height')==1<<18 and r.get('verified') is True
                and isinstance(r.get('commit_ns'),int) and r['commit_ns']>0,
                'invalid commitment screen evidence')
    return rows
