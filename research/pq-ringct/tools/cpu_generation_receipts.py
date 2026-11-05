"""Strict CPU generation receipts; never substitutes for GPU proving evidence."""
import math
import json

def require(ok, message):
    if not ok: raise ValueError(message)

def integer(value, name, *, positive=False):
    require(type(value) is int and 0 <= value < 1 << 128 and (not positive or value > 0), 'invalid CPU generation ' + name)
    return value

def fields(value, names, name):
    require(type(value) is dict and set(value) == set(names.split()), 'invalid CPU generation fields: ' + name)
    return value

STATISTICS = 'parameters_ns inputs_ns spend_ns encoding_ns cleanup_ns attempts random_calls random_blocks proposals parameter_cache_hits status'
TOTALS = 'run_id verified whole_stage_ns spend_ns verification_ns attempts random_calls random_blocks proposals parameter_cache_hits cleanup_complete gpu_contexts gpu_generation_calls'

def validate(generation, terminal, summaries, count, private_gpu_reports):
    fields(generation, 'cpu spends seconds managed_peak_bytes witness_completed_calls witness_device_calls witness_device_ns', 'totals')
    cpu = fields(generation['cpu'], TOTALS, 'CPU totals')
    for key,value in cpu.items():
        if key != 'cleanup_complete': integer(value,key)
    run_id = integer(cpu['run_id'], 'run id', positive=True)
    require(integer(generation['spends'], 'spends') == cpu['verified'] == count and len(summaries) == count, 'incomplete CPU generation inventory')
    for key in ('managed_peak_bytes', 'witness_completed_calls', 'witness_device_calls', 'witness_device_ns'):
        require(type(generation[key]) is int and generation[key] == 0, 'CPU generation claims GPU work')
    require(cpu['gpu_contexts'] == cpu['gpu_generation_calls'] == private_gpu_reports == 0
            and type(cpu['gpu_contexts']) is int and type(cpu['gpu_generation_calls']) is int,
            'CPU generation has GPU contexts/calls/receipts')
    require(cpu['cleanup_complete'] is True, 'CPU workspace not retired')
    fields(terminal, 'schema session_id cpu_run_id operations session stark_proofs registrations', 'terminal')
    require(terminal['schema'] == 'ringct-cpu-generation-terminal-v1'
            and terminal['session_id'] is None and terminal['session'] is None
            and integer(terminal['cpu_run_id'], 'terminal run') == run_id and terminal['operations'] == generation,
            'CPU terminal identity or operations mismatch')
    require(integer(terminal['stark_proofs'], 'terminal stark proofs') == integer(terminal['registrations'], 'terminal registrations') == 0, 'CPU terminal claims proving work')
    summed = dict.fromkeys(('spend_ns','verification_ns','attempts','random_calls','random_blocks','proposals','parameter_cache_hits'), 0)
    elapsed = 0
    for ordinal, summary in enumerate(summaries):
        fields(summary, 'run_id ordinal elapsed_ns generation_ns verification_ns statistics', 'spend')
        require(integer(summary['run_id'], 'summary run') == run_id and integer(summary['ordinal'], 'summary ordinal') == ordinal, 'CPU generation reordered or rebound')
        stats = fields(summary['statistics'], STATISTICS, 'statistics')
        for k,v in stats.items(): integer(v,k)
        require(stats['status'] == 0 and 0 < stats['attempts'] <= 1024
                and 0 < stats['random_calls'] <= 1 << 24 and 0 < stats['random_blocks'] <= 1 << 32
                and 0 < stats['proposals'] <= 1 << 28 and stats['parameter_cache_hits'] in (0,1),
                'CPU generation failed or exceeded limits')
        generation_ns = integer(summary['generation_ns'], 'generation ns', positive=True)
        verification_ns = integer(summary['verification_ns'], 'verification ns', positive=True)
        tx_elapsed = integer(summary['elapsed_ns'], 'elapsed ns', positive=True)
        stages = sum(stats[k] for k in ('parameters_ns','inputs_ns','spend_ns','encoding_ns','cleanup_ns'))
        require(0 < stages <= generation_ns and generation_ns + verification_ns <= tx_elapsed,
                'CPU generation timing omits work')
        elapsed += tx_elapsed
        for key in summed: summed[key] += verification_ns if key == 'verification_ns' else stats[key]
    require(all(integer(cpu[k], k) == v for k,v in summed.items()), 'CPU generation totals differ from spends')
    whole = integer(cpu['whole_stage_ns'],'whole stage ns',positive=True)
    require(elapsed <= whole, 'CPU complete stage omits transactions/cleanup')
    seconds = generation['seconds']
    require(type(seconds) in (int,float) and math.isfinite(seconds) and seconds > 0
            and abs(seconds - whole/1e9) <= max(1e-12, 4*math.ulp(seconds)), 'CPU generation seconds mismatch')
    return dict(backend='cpu',run_id=run_id,verified=count,cleanup_complete=True,gpu_generation_calls=0)

def metadata_handoff(content, count):
    """Audit fresh CPU completion before any observed GPU metadata receipts."""
    summaries, terminal, terminal_line, gpu_lines = [], None, None, []
    for line_number,line in enumerate(content.splitlines()):
        if line.startswith(('owned_generation_report ', 'owned_generation_spend ')):
            raise ValueError('fresh CPU metadata profile contains GPU generation work')
        if line.startswith('owned_generation_cpu_spend '):
            require(terminal is None and len(summaries) < count, 'extra CPU spend or spend follows terminal')
            summaries.append(json.loads(line.split(' ',1)[1]))
        if line.startswith('owned_generation_terminal '):
            require(terminal is None, 'duplicate CPU generation terminal')
            terminal=json.loads(line.split(' ',1)[1]);terminal_line=line_number
        if line.startswith('proving_stage_report '): gpu_lines.append(line_number)
    require(terminal is not None, 'fresh metadata has no CPU completion receipt')
    result=validate(terminal.get('operations'),terminal,summaries,count,0)
    require(all(line > terminal_line for line in gpu_lines), 'GPU metadata receipt precedes CPU cleanup')
    result['gpu_metadata_receipts_after_terminal']=len(gpu_lines)
    return result
