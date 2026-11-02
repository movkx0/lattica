import copy
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import opencl_private_spend_validate as runner
from test_opencl_private_spend_validate import arguments
from metadata_stage_profile import SELECTOR, PREFIX, cache_rates, preparation_detail, validate


class MetadataStageTests(unittest.TestCase):
    def test_reuse_counters_and_variant_require_complete_scope(self):
        for variant in ('baseline', 'structure', 'verifier', 'arithmetic', 'all'):
            r = self.fixture()
            r.update(reuse_variant=variant, reuse_counters=[3, 0, 0,
                3 if variant in ('all', 'structure') else 0,
                9 if variant in ('all', 'verifier') else 0, 3, 0,
                12 if variant in ('all', 'arithmetic') else 0])
            self.assertEqual(validate(self.text(r))['reuse_variant'], variant)
            for index in (3, 4, 6, 7):
                bad = copy.deepcopy(r)
                bad['reuse_counters'][index] = 1 if index == 6 else 0 if bad['reuse_counters'][index] else 1
                with self.assertRaises(ValueError): validate(self.text(bad))
        r['reuse_variant'] = 'invalid'
        with self.assertRaises(ValueError): validate(self.text(r))

    def test_reuse_selector_is_confined_to_metadata_profile(self):
        options = dict(profile='full', expect_tests=True, build_label='build',
            command=['/tmp/profile', SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture'],
            metadata_stage_profile=True, retained_tree_storage='host',
            device_uuid='GPU-11111111-2222-3333-4444-555555555555')
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            for variant in ('baseline', 'structure', 'verifier', 'arithmetic', 'all'):
                plan = runner.build_plan(arguments(**options, metadata_reuse_variant=variant))
                self.assertEqual(plan['environment']['LATTICA_RINGCT_METADATA_REUSE_VARIANT'], variant)
                self.assertEqual(plan['metadata_reuse_variant'], variant)
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**{**options, 'metadata_stage_profile': False}, metadata_reuse_variant='all'))
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**options, metadata_reuse_variant='invalid'))

    def test_endpoint_reuse_requires_all_adoptions_and_valid_variant(self):
        for variant in ('reference', 'nodes', 'endpoints', 'fields', 'all'):
            record = self.fixture()
            record.update(hash_variant=variant, endpoint_adoptions=21 if variant in ('all', 'endpoints') else 0)
            self.assertEqual(validate(self.text(record))['hash_variant'], variant)
            record['endpoint_adoptions'] += 1
            with self.assertRaises(ValueError): validate(self.text(record))
        record.update(hash_variant='unknown')
        with self.assertRaises(ValueError): validate(self.text(record))

    def test_detail_is_explicit_and_complete(self):
        command = ['/tmp/profile', SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture']
        options = dict(profile='full', expect_tests=True, build_label='build', command=command,
            metadata_stage_profile=True, metadata_preparation_detail=True, retained_tree_storage='host',
            device_uuid='GPU-11111111-2222-3333-4444-555555555555')
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            plan = runner.build_plan(arguments(**options))
            self.assertTrue(plan['metadata_preparation_detail'])
            self.assertEqual(plan['environment']['LATTICA_RINGCT_METADATA_PREPARATION_DETAIL'], '1')
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**{**options, 'metadata_stage_profile': False}))
        with self.assertRaises(ValueError):
            validate(self.text(self.fixture()), require_preparation_detail=True)
        # Fixed synthetic records exercise acceptance independently of local evidence.
        counter = dict(calls=1, wall_ns=1, device_calls=1, device_ns=1, allocations=1,
                       allocated_words=1, uploaded_bytes=1, downloaded_bytes=1, metric_ns=[1]*6)
        operation = dict(schema='ringct-preparation-operations-v1', complete=True,
            families=['node_commitment', 'field_commitment', 'arithmetic', 'other'],
            metrics=['allocation', 'kernel_setup', 'upload_enqueue', 'readback_wait', 'cleanup', 'device_wait'],
            counters=[counter]*4)
        graph = dict(steps=['input_validation', 'scope_startup', 'imports', 'relation', 'finalize'],
                     completed=5, wall_ns=[1]*5)
        source = dict(steps=['registration', 'algebra', 'tree', 'statement', 'manifest', 'native',
                            'crypto', 'auxiliary', 'producer'], completed=9, wall_ns=[1]*9)
        rows = [('RINGCT_PREPARATION_OPERATIONS ', operation)]*27 + [('RINGCT_GRAPH_PREPARATION_PROFILE ', graph)]*3 + [('RINGCT_SOURCE_PREPARATION_PROFILE ', source)]*3
        def content():
            return '\n'.join(prefix + json.dumps(row) for prefix, row in rows)
        timing = dict(graph_sources_ns=15, source_preparation_ns=27)
        self.assertTrue(preparation_detail(content(), timing, True)['metrics_overlap'])
        for mutate in (lambda: operation.update(complete=False),
                       lambda: graph.update(completed=4),
                       lambda: counter.update(metric_ns=[1]*5),
                       lambda: source.update(wall_ns=[10]*9)):
            original = copy.deepcopy(rows)
            mutate()
            with self.assertRaises(ValueError):
                preparation_detail(content(), timing, True)
            rows = original
            operation, graph, source = rows[0][1], rows[27][1], rows[30][1]
            counter = operation['counters'][0]
        rows.pop()
        with self.assertRaises(ValueError):
            preparation_detail(content(), timing, True)

    def test_selector_limits_and_exclusivity(self):
        command = ['/tmp/profile', SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture']
        options = dict(profile='full', expect_tests=True, build_label='build', command=command,
                       metadata_stage_profile=True, retained_tree_storage='host',
                       device_uuid='GPU-11111111-2222-3333-4444-555555555555')
        with patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            plan = runner.build_plan(arguments(**options))
            self.assertEqual(plan['cpu_quota'], '1600%')
            self.assertEqual(plan['memory_max_bytes'], 47 << 30)
            self.assertEqual(plan['environment']['LATTICA_V2_HOST_OUTPUT_BYTES'], str(24 << 30))
            self.assertEqual(plan['environment']['LATTICA_RINGCT_METADATA_STAGE_PROFILE'], 'n3-paired-v1')
            self.assertEqual(plan['environment']['RUST_MIN_STACK'], str(8 << 20))
            for changed in (dict(profile='research-compile-large'), dict(build_label=None),
                            dict(retained_tree_storage='device'), dict(device_uuid=None),
                            dict(command=command[:1] + ['another_test'] + command[2:]),
                            dict(full_workflow_case=True), dict(host_profile='expanded-36')):
                with self.assertRaises(ValueError):
                    runner.build_plan(arguments(**{**options, **changed}))

    def test_table_hits_are_not_compiler_misses(self):
        c = dict(hits=60, misses=40, table_hits=30, failed_computations=0, evictions=1)
        result = cache_rates(c)
        self.assertEqual(result['memory_miss_rate'], 0.4)
        self.assertEqual(result['cold_miss_rate'], 0.1)
        self.assertEqual(result['cold_misses'], 10)
        with self.assertRaises(ValueError):
            cache_rates({**c, 'table_hits': 41})

    def test_fixture_replay_is_pinned_and_capture_is_exclusive(self):
        command = ['/tmp/profile', SELECTOR, '--exact', '--ignored', '--test-threads=1', '--nocapture']
        options = dict(profile='full', expect_tests=True, build_label='build', command=command,
                       metadata_stage_profile=True, retained_tree_storage='host',
                       device_uuid='GPU-11111111-2222-3333-4444-555555555555')
        with tempfile.TemporaryDirectory() as directory, patch.object(runner, 'identity_physical_cpus', return_value=list(range(16))):
            fixture = Path(directory) / 'public.bin'
            fixture.write_bytes(b'public test fixture')
            for workers in (1, 8, 16):
                plan = runner.build_plan(arguments(**options, metadata_workers=workers, metadata_fixture_in=str(fixture)))
                self.assertEqual(plan['metadata_fixture_sha256'], runner.sha(fixture))
                self.assertEqual(plan['environment']['LATTICA_RINGCT_METADATA_WORKERS'], str(workers))
                self.assertEqual(plan['environment']['LATTICA_RINGCT_METADATA_FIXTURE_IN'], str(fixture))
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**options, metadata_fixture_in=str(fixture), metadata_fixture_out=str(fixture)))
            with self.assertRaises(ValueError):
                runner.build_plan(arguments(**options, metadata_fixture_in=str(fixture) + '.missing'))

    def fixture(self):
        timing = dict(setup_ns=1, graph_sources_ns=2, source_preparation_ns=3,
                      inventory_ns=4, reservation_ns=5, constructors_ns=10,
                      native_constructors_ns=1, crypto_constructors_ns=2,
                      graph_constructors_ns=3, final_aggregation_ns=4, total_ns=25)
        families = [dict(requests=3, cache_hits=1, table_hits=1, cold_misses=1, compile_ns=1)
                    for _ in range(13)]
        cache = dict(hits=13, misses=26, table_hits=13, failed_computations=0, evictions=0)
        return dict(schema='ringct-complete-metadata-profile-v1', transactions=3,
                    layout='paired-v1', setup_seed=[17]*32, context=[34]*32,
                    host_profile='standard', metadata_workers=16, complete_metadata=True,
                    input_randomness='fixed-public-parameters-fresh-private-entropy',
                    complete_workflow=False, recursive_proofs_generated=0,
                    retirement='process-teardown-incomplete-case-owners-retained',
                    native_input_generation_ns=10, generation_and_startup_ns=11,
                    timing=timing, registered_cache=cache.copy(), native_cache=cache.copy(),
                    native_families=families, expensive_misses=[None]*32, planner={})

    def text(self, record):
        return 'RINGCT_METADATA_TIMING ' + json.dumps(record['timing']) + '\n' + PREFIX + json.dumps(record)

    def test_incomplete_clocks_failed_compilation_and_workflow_receipts_are_refused(self):
        r = self.fixture()
        self.assertAlmostEqual(validate(self.text(r))['combined']['cold_miss_rate'], 1/3)
        for mutate in (lambda r: r.update(complete_metadata=False),
                       lambda r: r.update(recursive_proofs_generated=1),
                       lambda r: r['timing'].update(total_ns=24),
                       lambda r: r['timing'].update(final_aggregation_ns=5),
                       lambda r: r['native_families'][0].update(cold_misses=2),
                       lambda r: r['native_cache'].update(failed_computations=1)):
            bad = copy.deepcopy(r)
            mutate(bad)
            with self.assertRaises(ValueError): validate(self.text(bad))
        for text in (self.text(r).split('\n')[1], self.text(r) + '\n' + self.text(r),
                     self.text(r) + '\nRINGCT_FULL_WORKFLOW_CASE {}'):
            with self.assertRaises(ValueError): validate(text)
