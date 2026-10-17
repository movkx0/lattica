#!/usr/bin/env python3
"""Controller failure, accounting and artifact checks; no proving or benchmarking."""
import importlib.util
import io
import json
import os
import socket
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("throughput", Path(__file__).with_name("bench-apple-throughput.py"))
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)

spec_c = importlib.util.spec_from_file_location("concurrency", Path(__file__).with_name("bench-apple-concurrency.py"))
C = importlib.util.module_from_spec(spec_c); spec_c.loader.exec_module(C)

class Throughput(unittest.TestCase):
    def test_phase_pools_validate_independently_and_accept_historical_events(self):
        def event(clock, admitted, pid, pool=None, slot=0):
            fields = dict(pid=str(pid), slot=str(slot), waited_ms='3')
            if pool is not None: fields['pool'] = pool
            return clock, admitted, fields
        rows = [event(1, True, 1), event(2, True, 2, 'late'), event(3, False, 1), event(4, False, 2, 'late')]
        result = C.phase_evidence(rows, 2)
        self.assertEqual(result['max_concurrent_heavy_phases'], 1)
        self.assertEqual(result['max_concurrent_late_phases'], 1)
        self.assertEqual(result['phase_wait_ms'], dict(heavy=3, late=3))
        self.assertEqual(C.phase_evidence([rows[0], rows[2]])['max_concurrent_late_phases'], 0)
        for invalid in [rows + [event(5, True, 3)], rows + [event(5, False, 99)],
                        [event(1, True, 1), event(2, True, 2)], [event(1, True, 1, 'heavy', 2)]]:
            with self.assertRaises(RuntimeError): C.phase_evidence(invalid, 2)
        with self.assertRaises(RuntimeError): C.phase_evidence(rows)

    def test_query_pool_independent_overlap_and_disabled_compatibility(self):
        def event(t, admit, pool, pid):
            return t, admit, dict(pool=pool, pid=str(pid), slot='0', waited_ms='1')
        rows = [event(1, True, 'heavy', 1), event(2, True, 'late', 2), event(3, True, 'query', 2),
                event(4, False, 'query', 2), event(5, False, 'late', 2), event(6, False, 'heavy', 1)]
        evidence = C.phase_evidence(rows, 2, 1)
        self.assertEqual(evidence['max_concurrent_query_phases'], 1)
        self.assertEqual(evidence['phase_admissions'], dict(heavy=1, late=1, query=1))
        with self.assertRaises(RuntimeError): C.phase_evidence(rows, 2)
        with self.assertRaises(RuntimeError): C.phase_evidence(rows[:3]+[event(3.5, True, 'query', 3)]+rows[3:], 2, 1)

    def test_headroom_options_reject_invalid_requests_before_reading_files(self):
        script = str(Path(__file__).with_name('bench-apple-concurrency.py'))
        for options in [('--query-scratch-mib', '0', '--memory-optimized'),
                        ('--query-scratch-mib', '8192', '--memory-optimized'),
                        ('--query-scratch-mib', '2048'), ('--late-phase-slots', '2'), ('--compact-salts',), ('--query-phase-slots', '1'), ('--query-phase-slots', '0', '--memory-optimized')]:
            result = subprocess.run(['python3', script, '--build', '/missing', '--qualification', '/missing',
                                     '--reference', '/missing', '--out', '/missing', *options], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('error:', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_concurrent_reference_workers_require_compact_cpu_pipeline(self):
        options = dict(pipeline='reference', compact_data='1', query_gather='1', quotient='cpu')
        for workers in (2, 3, 4, 5):
            T.validate_candidate_workers(workers, options)
            for key, value in [('compact_data', '0'), ('query_gather', '0'), ('quotient', 'gpu')]:
                with self.subTest(workers=workers, key=key), self.assertRaises(ValueError):
                    T.validate_candidate_workers(workers, {**options, key: value})
        T.validate_candidate_workers(1, {**options, 'compact_data': '0'})
        for workers in (3, 4, 5):
            with self.assertRaises(ValueError):
                T.validate_candidate_workers(workers, {**options, 'pipeline': 'resident'})

    def test_three_workers_partition_threads_and_keep_gpu_allowance(self):
        options = dict(pipeline='reference', compact_data='1', query_gather='1', quotient='cpu')
        with patch.dict(os.environ, {'LATTICA_V2_GPU_MANAGED_BYTES': str(7*T.GIB)}):
            env = T.policy(3, True, Path('/tmp/scratch'), 'reference', 256, options=options)
        self.assertEqual(env['RAYON_NUM_THREADS'], '6')
        self.assertEqual(env['LATTICA_V2_GPU_MANAGED_BYTES'], str(7*T.GIB))
        self.assertEqual(env['LATTICA_V2_METAL_QUOTIENT'], 'cpu')
        self.assertEqual(env['LATTICA_V2_GPU_COMPACT_PROVER_DATA'], '1')
        self.assertNotIn('LATTICA_V2_METAL_RSS_LIMIT_BYTES', env)

    def test_four_and_five_workers_partition_threads_and_keep_memory_controls(self):
        options = dict(pipeline='reference', compact_data='1', query_gather='1', quotient='cpu')
        controls = {'LATTICA_V2_GPU_MANAGED_BYTES': str(7*T.GIB),
                    'LATTICA_APPLE_PHASE_SLOTS': '2', 'LATTICA_APPLE_MEMORY_RECLAIM': '1',
                    'LATTICA_APPLE_LDE_SCRATCH_BYTES': str(2*T.GIB),
                    'LATTICA_APPLE_QUERY_SCRATCH_BYTES': str(2*T.GIB), 'LATTICA_APPLE_LATE_PHASE_SLOTS': '2',
                    'LATTICA_APPLE_COMPACT_SALTS': '1', 'LATTICA_APPLE_QUERY_PHASE_SLOTS': '1',
                    'LATTICA_APPLE_PHASE_DIR': '/tmp/test-phases',
                    'LATTICA_APPLE_SHARED_PREPROCESSING_DIR': '/tmp/test-public-prefixes'}
        for workers, threads, total in ((4, 4, 16), (5, 3, 15)):
            with self.subTest(workers=workers), patch.dict(os.environ, controls):
                env = T.policy(workers, True, Path('/tmp/scratch'), 'reference', 256, options=options)
                self.assertEqual(env['RAYON_NUM_THREADS'], str(threads))
                self.assertEqual(workers * int(env['RAYON_NUM_THREADS']), total)
                self.assertTrue(all(env[k] == v for k, v in controls.items()))
                self.assertNotIn('LATTICA_V2_METAL_RSS_LIMIT_BYTES', env)
                with self.assertRaises(ValueError):
                    T.policy(workers, True, Path('/tmp/scratch'), 'reference', 256, options={**options, 'pipeline': 'resident'})

    def test_five_worker_cli_requires_current_memory_profile_before_any_io(self):
        base = ['--build', '/missing', '--qualification', '/missing', '--reference', '/missing',
                '--out', '/missing', '--workers', '5']
        controls = ['--memory-optimized', '--compact-salts', '--late-phase-slots', '1',
                    '--query-phase-slots', '1', '--query-scratch-mib', '1024']
        parsed = C.parse_args(base + controls)
        self.assertEqual((parsed.workers, parsed.managed_gib), (5, 7))
        for flag in ('--memory-optimized', '--compact-salts', '--late-phase-slots',
                     '--query-phase-slots', '--query-scratch-mib'):
            bad = controls.copy(); index = bad.index(flag)
            del bad[index:index + (1 if flag in ('--memory-optimized', '--compact-salts') else 2)]
            with self.subTest(missing=flag), patch('sys.stderr',new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                C.parse_args(base + bad)
            self.assertEqual(error.exception.code, 2)
        for flag, value in (('--late-phase-slots','2'),('--query-phase-slots','2'),('--query-scratch-mib','2048')):
            bad = controls.copy(); bad[bad.index(flag)+1] = value
            with self.subTest(flag=flag), patch('sys.stderr',new_callable=io.StringIO), self.assertRaises(SystemExit):
                C.parse_args(base + bad)

    def test_stagger_waits_for_complete_marker_and_checks_resources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'worker.log'
            path.write_text('proof_sta')
            owned = Mock()
            worker = Mock()
            worker.poll.return_value = None
            sampler = Mock()
            def append_marker(_):
                with path.open('a') as f:
                    f.write('rt mode=1 setup_ms=10\n')
            with patch.object(T.time, 'sleep', side_effect=append_marker) as sleep:
                T.wait_for_preprocessing(owned, worker, path, [sampler])
            sleep.assert_called_once()
            self.assertEqual(owned.sample.call_count, 2)
            self.assertEqual(sampler.poll.call_count, 2)

    def test_stagger_propagates_exit_and_memory_pressure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'worker.log'; path.write_text('')
            owned = Mock(); worker = Mock(); worker.poll.return_value = 1
            with self.assertRaisesRegex(RuntimeError, 'exited before preprocessing'):
                T.wait_for_preprocessing(owned, worker, path, [])
            owned.sample.side_effect = RuntimeError('memory pressure invalidates screen')
            with self.assertRaisesRegex(RuntimeError, 'memory pressure'):
                T.wait_for_preprocessing(owned, worker, path, [])

    def test_candidate_controls_are_isolated_from_reference_and_environment(self):
        inherited = {v[0]: v[2][-1] for v in T.TUNING.values()}
        with patch.dict(os.environ, inherited):
            options = dict(pipeline="reference", poseidon_diagonal="specialized", ntt_tables="on",
                           direct_readback="1", denominator_cache="1", query_gather="1", compact_data="1")
            ref = T.policy(1, False, Path('/tmp/scratch'), 'reference', 256, options=options)
            candidate = T.policy(1, True, Path('/tmp/scratch'), 'reference', 256, options=options)
            self.assertEqual(ref['LATTICA_V2_METAL_POSEIDON_DIAGONAL'], 'reference')
            self.assertEqual(ref['LATTICA_V2_METAL_NTT_TABLES'], 'off')
            self.assertEqual(ref['LATTICA_V2_METAL_QUOTIENT'], 'cpu')
            self.assertEqual(candidate['LATTICA_V2_METAL_POSEIDON_DIAGONAL'], 'specialized')
            self.assertEqual(candidate['LATTICA_V2_METAL_NTT_TABLES'], 'on')
            self.assertEqual(candidate['LATTICA_V2_METAL_PIPELINE'], 'reference')
            self.assertEqual(candidate['LATTICA_V2_METAL_BATCH'], '1')
            for key in ('DIRECT_READBACK', 'OPENING_DENOMINATOR_CACHE', 'QUERY_GATHER', 'COMPACT_PROVER_DATA'):
                self.assertEqual(ref['LATTICA_V2_GPU_' + key], '0')
                self.assertEqual(candidate['LATTICA_V2_GPU_' + key], '1')
            hybrid = T.policy(1, True, Path('/tmp/scratch'), 'reference', 256,
                              options=dict(quotient='cpu', prefix_store='fused'))
            self.assertEqual(hybrid['LATTICA_V2_METAL_PIPELINE'], 'resident')
            self.assertEqual(hybrid['LATTICA_V2_METAL_QUOTIENT'], 'cpu')
            self.assertEqual(hybrid['LATTICA_V2_METAL_PREFIX_STORE'], 'fused')
            with self.assertRaises(ValueError):
                T.policy(1, True, Path('/tmp/scratch'), 'reference', 256, options={'ntt_tables':'invalid'})
            line = 'metal_tuning poseidon_diagonal=reference ntt_tables=false ntt_tile_log2=12 prefix_store=separate quotient=cpu'
            T.verify_tuning(line, ref)
            for bad in ('', line.replace('quotient=cpu', 'quotient=gpu'), line + '\n' + line.replace('ntt_tables=false', 'ntt_tables=true')):
                with self.assertRaises(RuntimeError): T.verify_tuning(bad, ref)

    def test_diagnostics_require_explicit_opt_in(self):
        with patch.dict(os.environ,{"LATTICA_PROFILE_TIMELINE":"1"}):
            for enabled in (False,True):
                for candidate in (False,True):
                    env=T.policy(1,candidate,Path('/tmp/scratch'),'reference',256,enabled)
                    self.assertEqual(env['LATTICA_PROFILE_TIMELINE'],str(int(enabled)))
                    self.assertEqual(env['LATTICA_V2_METAL_TIMEOUT_SECONDS'],'none')

    def test_stack_sampling_is_triggered_once_per_selected_proof(self):
        with tempfile.TemporaryDirectory() as tmp,patch('sys.stdout',new_callable=io.StringIO):
            job=Path(tmp);log=job/'worker.log';log.write_text('')
            owned=Mock();worker=Mock(pid=123);worker.poll.return_value=None
            sampled=Mock();sampled.poll.return_value=0;owned.spawn.return_value=sampled
            handles=[];sampler=T.StackSampler(owned,worker,job,handles)
            try:
                log.write_text('proof_sta');sampler.poll();owned.spawn.assert_not_called()
                with log.open('a') as f:f.write('rt mode=1\n'+('proof_start mode=3\n'*6))
                sampler.poll();sampler.poll()
                self.assertEqual(owned.spawn.call_count,2)
                for call in owned.spawn.call_args_list:
                    self.assertEqual(call.args[0][:5],['/usr/bin/sample','123','5','10','-file'])
                    Path(call.args[0][5]).write_text('CPU stack sample')
                self.assertEqual([row['status'] for row in sampler.summary()],['PASS','PASS'])
            finally:
                for handle in handles:handle.close()

    def test_resource_partition_and_cpu_isolation(self):
        with patch.dict(os.environ, {"LATTICA_V2_METAL_PIPELINE":"resident", "LATTICA_V2_METAL_BATCH":"8", "LATTICA_V2_METAL_RSS_LIMIT_BYTES":str(44*T.GIB), "LATTICA_SPILL_MAX_BYTES":"1", "LATTICA_V2_METAL_TIMEOUT_SECONDS":"900"}):
            for n in (1, 2):
                env=T.policy(n, True, Path("/tmp/scratch"), "optimized", 128)
                self.assertEqual(int(env["RAYON_NUM_THREADS"])*n,18)
                self.assertEqual(env["LATTICA_V2_GPU_COMPACT_PROVER_DATA"],"1")
                self.assertEqual(env["LATTICA_V2_GPU_PARALLEL_READBACK"],"0")
                self.assertNotIn("LATTICA_V2_METAL_RSS_LIMIT_BYTES",env)
                self.assertNotIn("LATTICA_SPILL_MAX_BYTES",env)
                self.assertEqual(env["LATTICA_V2_METAL_TIMEOUT_SECONDS"],"none")
            reference=T.policy(1, False, Path("/tmp/scratch"), "reference", 256)
            self.assertEqual(int(reference["LATTICA_SPILL_MAX_BYTES"]),34*T.GIB)
            self.assertEqual(reference["LATTICA_V2_METAL_TIMEOUT_SECONDS"],"none")
            cpu=T.baseline.environment(T.baseline.arm("cpu",9),Path("/tmp/scratch"),False)
            self.assertEqual(cpu["LATTICA_V2_METAL_PIPELINE"],"reference")
            self.assertEqual(cpu["LATTICA_V2_METAL_BATCH"],"1")
            for key in T.baseline.GPU_KEYS: self.assertEqual(cpu["LATTICA_V2_GPU_"+key],"0")

    def test_worker_estimates_overlap_scratch_and_select_concurrency(self):
        for gib,capacity,selected,threads in ((64,2,2,9),(32,1,1,18),(24,0,0,0),(128,5,2,9)):
            with self.subTest(memory_gib=gib):
                plan=T.plan_workers(gib*T.GIB)
                self.assertEqual(plan["per_worker_estimate_bytes"],21*T.GIB)
                self.assertEqual(plan["estimated_workers"],capacity)
                self.assertEqual(plan["selected_workers"],selected)
                self.assertEqual(plan["threads_per_worker"],threads)
                self.assertFalse(plan["allocation_limits_enforced"])
        self.assertEqual(T.plan_workers(64*T.GIB,1)["selected_workers"],1)
        self.assertEqual(T.plan_workers(32*T.GIB,2)["selected_workers"],1)
        policy=dict(T.baseline.MEMORY_POLICY,resident_scratch_estimate_bytes=20*T.GIB)
        self.assertEqual(T.plan_workers(64*T.GIB,memory_policy=policy)["per_worker_estimate_bytes"],24*T.GIB)
        for bad in (0,-1,True,"17",1<<64):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                T.plan_workers(64*T.GIB,memory_policy=dict(policy,resident_backing_estimate_bytes=bad))

    def test_worker_plan_checks_capacity_before_launch(self):
        with patch.object(T.subprocess,"check_output",return_value=str(24*T.GIB)),patch("sys.stdout",new_callable=io.StringIO):
            with self.assertRaisesRegex(RuntimeError,"no worker capacity"):
                T.resident_worker_plan()

    def test_rss_above_former_cap_is_observed_without_stopping(self):
        resource=io.StringIO()
        normal={"pressure":1,"swap_used_bytes":0}
        worker=Mock(pid=os.getpid()+1)
        worker.poll.return_value=None
        sample=Mock(stdout=f"{os.getpid()} {T.GIB//1024}\n{worker.pid} {50*T.GIB//1024}\n")
        with patch.object(T,"observations",return_value=normal), patch.object(T.subprocess,"run",return_value=sample):
            owned=T.OwnedProcesses(resource)
            owned.children=[(worker,"worker",None)]
            owned.sample()
            self.assertEqual(owned.peak,51*T.GIB)
            self.assertEqual(owned.worker_peaks[str(worker.pid)],50*T.GIB)
            self.assertEqual(json.loads(resource.getvalue())["aggregate_rss"],51*T.GIB)
            with patch.object(T,"observations",return_value={**normal,"pressure":2}):
                with self.assertRaisesRegex(RuntimeError,"memory pressure"):
                    owned.sample()

    def test_close_terminates_and_reaps_owned_children(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(T,"observations",return_value={"pressure":1,"swap_used_bytes":0}):
            with open(Path(tmp)/"resources","w") as resource, open(Path(tmp)/"child","w") as log:
                owned=T.OwnedProcesses(resource)
                child=owned.spawn(["/bin/sleep","30"],os.environ,log)
                owned.close()
                self.assertIsNotNone(child.poll())
                with self.assertRaises(ChildProcessError):os.waitpid(child.pid,os.WNOHANG)

    def test_cleanup_reaps_child_when_process_group_signal_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(T,"observations",return_value={"pressure":1,"swap_used_bytes":0}):
            with open(Path(tmp)/"resources","w") as resource, open(Path(tmp)/"child","w") as log:
                owned=T.OwnedProcesses(resource)
                child=owned.spawn(["/bin/sleep","30"],os.environ,log)
                with patch.object(T.os,"killpg",side_effect=PermissionError("denied")):
                    owned.close()
                self.assertIsNotNone(child.poll())
                with self.assertRaises(ChildProcessError):os.waitpid(child.pid,os.WNOHANG)

    def test_elapsed_time_does_not_stop_screen(self):
        resource=io.StringIO()
        sample=Mock(stdout=f"{os.getpid()} 1024\n")
        with patch.object(T,"observations",return_value={"pressure":1,"swap_used_bytes":0}), \
             patch.object(T.subprocess,"run",return_value=sample), \
             patch.object(T.time,"monotonic",return_value=0) as clock, \
             patch("sys.stdout",new_callable=io.StringIO):
            owned=T.OwnedProcesses(resource)
            for elapsed in (901,3600,10800):
                clock.return_value=elapsed
                owned.sample()
            samples=[json.loads(line) for line in resource.getvalue().splitlines()]
            self.assertEqual([row["monotonic"] for row in samples],[901,3600,10800])
            self.assertFalse(owned.pressure_incident)

    def test_report_counts_windows_not_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            windows=[]
            for label,count,seconds in (("reference",1,200),("resident",2,180)):
                windows.append(dict(label=label,workers=count,seconds=seconds,verified_jobs_per_hour=count*3600/seconds,
                    aggregate_peak_rss_bytes=55*T.GIB,status="VERIFIED",jobs=[dict(index=i,proof_seconds=170,audited_completion_seconds=seconds,worker_peak_rss_bytes=10*T.GIB) for i in range(count)]))
            report=dict(status="COMPLETE_VERIFIED_SCREEN",git_commit="abc",windows=windows,throughput_ratio=2.22,target_met=True,aggregate_rss_limit_bytes=None,worker_rss_limit_bytes=None,resident_worker_plan=T.plan_workers(64*T.GIB),benchmark_budget_seconds=None,worker_timeout_seconds=None)
            path=Path(tmp)/"index.html";T.render(report,path);text=path.read_text()
            self.assertEqual(text.count('class="bar throughput-bar"'),2)
            self.assertEqual(text.count("<td>PASS</td>"),3)
            self.assertIn("not accepted blockchain transactions",text)
            self.assertIn("no fixed aggregate RSS cap",text)
            self.assertIn("2 worker(s), 21 GiB estimated per worker",text)
            self.assertIn("without a fixed backing or scratch ceiling",text)
            self.assertIn("No total screen deadline or proving-worker timeout",text)
            self.assertIn("0–55 GiB",text)
            self.assertEqual(text.count('class="bar memory-bar" style="width:100.00%"'),2)
            evidence=text.split('id="evidence" type="application/json">')[1].split("</script>")[0]
            self.assertEqual(json.loads(evidence),report)
            del report["aggregate_rss_limit_bytes"]
            del report["resident_worker_plan"]
            T.render(report,path)
            self.assertIn("44 GiB aggregate RSS budget",path.read_text())

    @unittest.skipUnless(os.environ.get("LATTICA_TEST_METAL_WORKER"), "compiled worker integration")
    def test_private_worker_stop_eof_and_rejected_sequence(self):
        for frame,expected in ((b'{"stop":true}\n',0),(b'{"sequence":9,"args":[]}\n',1),(b'',0)):
            with self.subTest(frame=frame),tempfile.TemporaryDirectory() as tmp:
                parent,child=socket.socketpair()
                env={**os.environ,"LATTICA_V2_METAL_COORDINATOR_PID":str(os.getpid()),"LATTICA_V2_METAL_CONTROL_FD":str(child.fileno())}
                with open(Path(tmp)/"worker.log","w") as log:
                    worker=subprocess.Popen([os.environ["LATTICA_TEST_METAL_WORKER"],"--metal-worker"],env=env,pass_fds=(child.fileno(),),stdout=log,stderr=log)
                    child.close()
                    try:
                        if frame: parent.sendall(frame)
                        else: parent.close()
                        self.assertEqual(worker.wait(timeout=5),expected)
                    finally:
                        parent.close()
                        if worker.poll() is None: worker.kill();worker.wait()


if __name__=="__main__":unittest.main()
