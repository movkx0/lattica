"""CPU generation-only receipt validation, separate from GPU proof acceptance."""
import json
from pathlib import Path

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def selection(args, argv):
    if not getattr(args, 'generation_only', False):
        return None
    require(args.profile == 'research-compile' and args.build_label,
            'generation-only requires a recorded CPU research build')
    require(not any((args.expect_tests, args.expect_result, args.expect_direct_result,
                     args.full_workflow_case, args.benchmark)), 'generation-only cannot accept proving results')
    require(Path(argv[0]).name == 'matrict-bench' and argv[1:2] == ['generation'],
            'generation-only requires matrict-bench generation')
    require(len(argv[2:]) % 2 == 0, 'generation arguments need values')
    options = {}
    allowed = {'--transactions', '--samples', '--setup-seed', '--context', '--aes-lanes',
               '--cache-public-parameters', '--reuse-workspace'}
    for key, value in zip(argv[2::2], argv[3::2]):
        require(key in allowed and key not in options, 'unknown/repeated generation option')
        options[key] = value
    selected = dict(transactions=int(options.get('--transactions', '1')),
                    samples=int(options.get('--samples', '100')),
                    aes_lanes=int(options.get('--aes-lanes', '1')),
                    setup_seed=options.get('--setup-seed', '11' * 32),
                    context=options.get('--context', '22' * 32))
    for key in ('cache-public-parameters', 'reuse-workspace'):
        value = options.get('--' + key, '0' if key.startswith('cache') else '1')
        require(value in ('0', '1'), 'generation booleans must be 0 or 1')
        selected[key.replace('-', '_')] = value == '1'
    require(selected['transactions'] in (1, 3, 4) and 1 <= selected['samples'] <= 1000
            and selected['aes_lanes'] in (1, 4, 8), 'unsupported generation dimensions')
    for key in ('setup_seed', 'context'):
        require(len(selected[key]) == 64 and len(bytes.fromhex(selected[key])) == 32,
                'generation public seed/context requires 32 bytes')
        selected[key] = selected[key].lower()
    return selected

def require_build(plan, executable):
    if plan.get('generation_only') is None:
        return
    build = json.loads(Path(executable['build_record']).read_text())
    argv = build['command']
    require(argv[1:2] == ['build'] and argv.count('--features') == 1
            and argv[argv.index('--features') + 1] == 'native-matrict'
            and argv.count('--bin') == 1 and argv[argv.index('--bin') + 1] == 'matrict-bench',
            'CPU generation requires native-matrict-only binary; no GPU or deterministic-entropy feature')

def validate(content, selected):
    prefix = 'CPU_GENERATION_PROFILE '
    reports = [json.loads(line[len(prefix):]) for line in content.splitlines() if line.startswith(prefix)]
    require(len(reports) == 1, 'expected exactly one CPU generation report')
    report = reports[0]
    require(report.get('schema') == 'lattica-cpu-generation-profile-v1'
            and report.get('backend') == 'cpu' and report.get('private_entropy') == 'os-fresh'
            and report.get('gpu_contexts') == 0 and report.get('gpu_generation_calls') == 0
            and report.get('recursive_workflow_started') is False,
            'generation report is not CPU-only fresh-entropy execution')
    require(all(report.get(k) == v for k, v in selected.items()), 'generation selection differs from launch')
    require(report.get('context_lifetime') == 'cold-per-sample' and 0 < report.get('workspace_bytes', 0) < 16 << 20,
            'unbounded or unspecified generation workspace')
    require(not any(marker in content for marker in ('proving_stage_report', 'OPENCL_OPT_RESULT',
            'NATIVE_EXECUTION_RECEIPT', 'FULL_WORKFLOW_RESULT')), 'CPU generation contains proving evidence')
    records = report.get('records', [])
    require(len(records) == selected['samples'], 'incomplete generation samples')
    hashes = set()
    for i, record in enumerate(records):
        require(record.get('sample') == i and record.get('whole_stage_ns', 0) > 0,
                'unordered or unmeasured generation sample')
        transactions = record.get('transactions', [])
        require(len(transactions) == selected['transactions'], 'incomplete generation batch')
        subtotal = 0
        for ordinal, tx in enumerate(transactions):
            stats = tx.get('statistics', {})
            require(tx.get('verified') is True and stats.get('status') == 0, 'unverified/refused transaction')
            require(0 < stats.get('attempts', 0) <= 1024 and 0 < stats.get('random_calls', 0) <= 1 << 24
                    and 0 < stats.get('random_blocks', 0) <= 1 << 32
                    and 0 < stats.get('proposals', 0) <= 1 << 28, 'generation limits missing/exceeded')
            hit = int(selected['cache_public_parameters'] and selected['reuse_workspace'] and ordinal > 0)
            require(stats.get('parameter_cache_hits') == hit, 'unexpected public parameter cache behavior')
            stage = sum(stats.get(k, 0) for k in ('parameters_ns', 'inputs_ns', 'spend_ns', 'encoding_ns', 'cleanup_ns'))
            require(0 < stage <= tx.get('generation_ns', 0)
                    and 0 < tx.get('verification_ns', 0)
                    and tx['generation_ns'] + tx['verification_ns'] <= tx.get('whole_transaction_ns', 0),
                    'generation stage timing does not reconcile')
            digest = tx.get('output_sha3_256', '')
            require(len(digest) == 64 and len(bytes.fromhex(digest)) == 32 and digest not in hashes,
                    'missing/repeated fresh output digest')
            hashes.add(digest)
            subtotal += tx['whole_transaction_ns']
        require(subtotal <= record['whole_stage_ns'], 'whole generation stage omits transaction work')
    return report
