//! Optimized-only correctness run over freshly generated, distinct transactions.
//! One serial context owns all eligible graph and batch OpenCL proving.
use lattica_pq_ringct_batch::{
    opencl::aggregate_with_context_and_witness_checks, BatchKey, BatchProof, Child, Plan,
    PUBLIC_VALUES,
};
use lattica_pq_ringct_research::{
    execution::ProvingContext,
    graph_crypto,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{GraphContext, Plan as GraphPlan},
    native::{self, private_spend_fixture::generate_spend_fixture, FixtureAmounts},
    opencl::Limits,
    proof_cache_policy::{CacheStatistics, ProofCachePolicy},
    recursive_aggregation::LeafStatement,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
    spend_pipeline::{AesLayout, Budgets, CompositeLayout, SpendPipeline, TranscriptLayout},
};
use lattica_prover_p3::block_v2::{
    machine::program::Val, native_gpu::private_spend::SpendLimits, profile::Config,
};
use p3_batch_stark::BatchProof as RawProof;
use p3_field::PrimeCharacteristicRing;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FILE_LIMIT: u64 = 64 << 20;
const GIB: u64 = 1 << 30;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(message).into())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn event(name: &str, details: Value) {
    eprintln!(
        "OPENCL_OPT_EVENT {}",
        json!({"event":name,"details":details})
    );
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    require(bytes.len() as u64 <= FILE_LIMIT, "artifact exceeds 64 MiB")?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= FILE_LIMIT,
        "invalid bounded artifact",
    )?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(FILE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 <= FILE_LIMIT,
        "artifact grew beyond allowance",
    )?;
    Ok(bytes)
}

struct Arguments {
    directory: PathBuf,
    counts: Vec<u32>,
    limits: Limits,
    native_bytes: u64,
    benchmark: bool,
}
fn arguments() -> Result<Option<Arguments>> {
    let mut values = BTreeMap::new();
    let mut benchmark = false;
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        if key == "--benchmark" {
            require(!benchmark, "duplicate --benchmark")?;
            benchmark = true;
            continue;
        }
        if key == "--help" {
            println!("pq-ringct-opencl-opt-validate --output-dir NEW_DIRECTORY --counts 3|4|3,4 --host-bytes N --device-bytes N --max-rows N --native-bytes N [--benchmark]\nFull correctness checks; optional end-to-end workflow timing; fresh distinct native transactions, FreshOnly caches, one serial OpenCL context. Launch through opencl_private_spend_validate.py with the full resource profile.");
            return Ok(None);
        }
        require(
            [
                "--output-dir",
                "--counts",
                "--host-bytes",
                "--device-bytes",
                "--max-rows",
                "--native-bytes",
            ]
            .contains(&key.as_str()),
            "unknown argument",
        )?;
        let value = args.next().ok_or("missing option value")?;
        require(values.insert(key, value).is_none(), "duplicate argument")?;
    }
    let get = |name: &str| values.get(name).ok_or_else(|| format!("missing {name}"));
    let counts = match get("--counts")?.as_str() {
        "3" => vec![3],
        "4" => vec![4],
        "3,4" => vec![3, 4],
        _ => return Err("counts must be 3, 4 or 3,4".into()),
    };
    let limits = Limits {
        host_bytes: get("--host-bytes")?.parse()?,
        device_bytes: get("--device-bytes")?.parse()?,
        max_rows: get("--max-rows")?.parse()?,
    };
    limits.validate()?;
    require(
        limits.device_bytes <= 8 * GIB,
        "optimization device allowance exceeds 8 GiB",
    )?;
    let native_bytes = get("--native-bytes")?.parse()?;
    require(
        (GIB..=24 * GIB).contains(&native_bytes),
        "native allowance must be 1 through 24 GiB",
    )?;
    require(
        native_bytes <= limits.host_bytes,
        "native allowance exceeds the shared worker host allowance",
    )?;
    require(
        !cfg!(debug_assertions),
        "fresh full validation requires release build",
    )?;
    Ok(Some(Arguments {
        directory: PathBuf::from(get("--output-dir")?),
        counts,
        limits,
        native_bytes,
        benchmark,
    }))
}

fn check_fresh(statistics: &CacheStatistics) -> Result<()> {
    require(
        statistics.policy == ProofCachePolicy::FreshOnly && statistics.families.len() == 5,
        "incorrect proof cache policy",
    )?;
    for family in statistics.families.values() {
        require(
            family.reads == 0 && family.hits == 0,
            "fresh run read cached proof payload",
        )?;
        require(
            family.fresh_proofs == family.proof_attempts,
            "incomplete fresh proof attempt",
        )?;
    }
    require(
        statistics
            .families
            .values()
            .map(|v| v.fresh_proofs)
            .sum::<u64>()
            > 0,
        "no fresh proofs produced",
    )
}

// These are serialized host-observed scopes, not device event durations or
// pure GPU compute. Preparation includes marshaling/control work; registration
// includes preprocessing. Direct verification and unscoped compilation are not
// completely represented, so this sum is never a throughput denominator.
fn gpu_operation_seconds(report: &Value) -> Result<[f64; 5]> {
    let values = [
        &report["operations"]["witness_preparation_seconds"],
        &report["operations"]["native_gpu_seconds"],
        &report["operations"]["prove_seconds"],
        &report["registration_seconds"],
        &report["operations"]["native_spend_seconds"],
    ];
    let mut seconds = [0.0; 5];
    for (target, value) in seconds.iter_mut().zip(values) {
        *target = value.as_f64().ok_or("missing GPU-operation wall counter")?;
        require(
            target.is_finite() && *target >= 0.0,
            "invalid GPU-operation wall counter",
        )?;
    }
    Ok(seconds)
}
fn gpu_operation_timing(before: [f64; 5], after: [f64; 5]) -> Result<Value> {
    let delta = core::array::from_fn::<_, 5, _>(|i| after[i] - before[i]);
    require(
        delta.iter().all(|v| v.is_finite() && *v >= 0.0),
        "GPU-operation wall counter regressed",
    )?;
    Ok(
        json!({"witness_preparation_seconds":delta[0],"native_stark_proving_seconds":delta[1],
        "recursive_stark_proving_seconds":delta[2],"registration_preprocessing_seconds":delta[3],
        "native_private_spend_seconds":delta[4],
        "sum_seconds":delta.iter().sum::<f64>(),"clock":"host_monotonic_wall",
        "scope":"serialized_gpu_required_calls_including_host_setup_and_waits",
        "device_only":false,"throughput_denominator":false}),
    )
}
fn measured_rate(count: usize, seconds: f64) -> Result<f64> {
    require(
        count > 0 && seconds.is_finite() && seconds > 0.0,
        "invalid measurement denominator",
    )?;
    let rate = 3600.0 * count as f64 / seconds;
    require(
        rate.is_finite() && rate > 0.0,
        "invalid measured transaction rate",
    )?;
    Ok(rate)
}

struct Completed {
    key: BatchKey,
    originals: Vec<LeafStatement>,
    artifact: PathBuf,
    result: Value,
}

fn case(worker: &ProvingContext, args: &Arguments, count: u32) -> Result<Completed> {
    let case_started = Instant::now();
    let gpu_before = gpu_operation_seconds(&worker.report())?;
    let mut cpu_input_fixture_seconds = 0.0;
    let mut cpu_input_validation_decode_seconds = 0.0;
    let directory = args.directory.join(format!("n{count}"));
    fs::create_dir(&directory)?;
    // The setup seed is public; native spending keys, commitments and proof
    // entropy are sampled afresh on every invocation by the native generator.
    let context: [u8; 32] = Sha3_256::digest(format!("pq-opencl-opt-fresh-n{count}")).into();
    let setup_seed: [u8; 32] = Sha3_256::digest(b"pq-opencl-opt-public-setup-v1").into();
    let pipeline = SpendPipeline::new_with_policy(
        directory.join("cache"),
        Budgets {
            native_bytes: args.native_bytes,
            outer_bytes: args.limits.host_bytes,
            cache_entry_bytes: FILE_LIMIT,
            crypto_policy: graph_crypto::Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 32,
                child_memory_budget_bytes: args.native_bytes,
                admission: graph_crypto::Admission::Estimated,
            },
            transcripts: TranscriptLayout::Serial,
            aes: AesLayout::Serial,
            composites: CompositeLayout::Branches,
        },
        ProofCachePolicy::FreshOnly,
    )?;
    let mut completed = Vec::new();
    let mut graph_contexts = Vec::new();
    let mut originals = Vec::new();
    let mut source_ids = Vec::new();
    let mut digests = BTreeSet::new();
    let mut label = None;
    for index in 0..count {
        event(
            "fresh_transaction_begin",
            json!({"count":count,"index":index}),
        );
        // Input fixture setup creates ring members and ASK witnesses, then stops.
        // The original private spend proof and output mint execute on the GPU.
        worker.release_prepared()?;
        let fixture_started = Instant::now();
        let inputs = generate_spend_fixture(
            context,
            Some(setup_seed),
            u64::from(index) + 3,
            FixtureAmounts {
                input: [17, 23],
                output: [29, 11],
            },
        )?;
        cpu_input_fixture_seconds += fixture_started.elapsed().as_secs_f64();
        event(
            "cpu_native_input_fixture_created",
            json!({"count":count,"index":index,"proving_stage":false}),
        );
        let request = inputs.into_gpu_request()?;
        let (fixture, native_spend_report, native_spend_evidence) = worker
            .create_matrict_spend_on_gpu(
                request,
                SpendLimits::bounded(usize::try_from(args.native_bytes)?),
            )?;
        event(
            "gpu_native_private_spend_created",
            json!({"count":count,"index":index,"receipt":native_spend_report,
                "execution":native_spend_evidence,"proving_stage":true}),
        );
        // Synthetic recipient keys have no wallet destination; retire the
        // secret result channel before the long public STARK pipeline.
        drop(fixture.output_keys);
        let input_started = Instant::now();
        require(
            native::verify(&context, &fixture.statement, &fixture.proof)?,
            "fresh native transaction rejected",
        )?;
        let statement = Statement::decode(&fixture.statement)?;
        require(statement.seed == setup_seed, "native setup seed differs")?;
        let proof = Proof::decode(&fixture.proof)?;
        cpu_input_validation_decode_seconds += input_started.elapsed().as_secs_f64();
        let graph = committed_backend::lower_unproved_on_gpu(
            setup_seed,
            &context,
            &statement,
            &proof,
            worker,
            usize::try_from(args.native_bytes)?,
        )?;
        let registered = RegisteredGraphShape::from_trusted_graph(&graph)?;
        let algebra = GraphProofPlan::new_with_context(
            &registered,
            &graph,
            ResourceLimits {
                max_batch_count: 64,
                max_ntt_batch_count: 32,
                max_mul_batch_count: 32,
                max_trace_cells: 1 << 27,
                max_estimated_prover_bytes: args.native_bytes,
            },
            Some(worker),
        )?;
        let graph_plan = GraphPlan::from_trusted_graph(&graph, algebra.operation_batches())?;
        if let Some(expected) = label {
            require(
                expected == graph_plan.label(),
                "fresh transactions use different relation labels",
            )?;
        }
        label = Some(graph_plan.label());
        let ((original, node_manifest), _) =
            worker.with_witness_preparation(usize::try_from(args.native_bytes)?, |operations| {
                let original = LeafStatement::from_bytes_on_gpu(
                    graph_plan.label(),
                    context,
                    &fixture.statement,
                    operations,
                )
                .map_err(|e| e.to_string())?;
                let manifest = graph_plan
                    .node_manifest_hint_on_gpu(&graph, operations)
                    .map_err(|e| e.to_string())?;
                Ok((original, manifest))
            })?;
        require(
            digests.insert(original.digest),
            "generated duplicate transaction statement",
        )?;
        let graph_context = GraphContext {
            context,
            statement: original.digest.map(Val::from_u64),
            node_manifest,
        };
        let complete = pipeline.prove_registered_with_context(
            &graph_plan,
            &algebra,
            &graph,
            &graph_context,
            &fixture.statement,
            &fixture.proof,
            worker,
        )?;
        complete
            .key()
            .verify_complete(complete.proof(), &graph_context)?;
        source_ids.push(hex(&algebra.source_fingerprint()));
        completed.push(complete);
        originals.push(original);
        graph_contexts.push(graph_context);
        event(
            "fresh_transaction_verified",
            json!({"count":count,"index":index,"cache":pipeline.cache_statistics()}),
        );
    }
    let statistics = pipeline.cache_statistics();
    check_fresh(&statistics)?;
    let plan = Plan::new(label.ok_or("missing relation label")?, context, count)?;
    require(
        plan.graph_child(
            0,
            completed[0].key(),
            completed[1].proof(),
            &graph_contexts[0],
        )
        .is_err(),
        "substituted graph proof accepted",
    )?;
    let children = completed
        .iter()
        .zip(&graph_contexts)
        .enumerate()
        .map(|(index, (complete, gc))| {
            plan.graph_child(index as u32, complete.key(), complete.proof(), gc)
                .map(Child::from)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (root, merges) = aggregate_with_context_and_witness_checks(
        worker,
        &plan,
        children,
        &originals,
        args.native_bytes,
    )?;
    let Child::Batch(root) = root else {
        return Err("expected recursive aggregate".into());
    };
    let (key, mut proof) = root.into_parts();
    drop(completed);
    drop(graph_contexts);
    drop(pipeline);
    worker.release_prepared()?;
    key.verify_expected(&proof, &originals)?;
    let mut changed = originals.clone();
    changed.swap(0, 1);
    require(
        key.verify_expected(&proof, &changed).is_err(),
        "reordered distinct statements accepted",
    )?;
    changed = originals.clone();
    changed[1] = changed[0].clone();
    require(
        key.verify_expected(&proof, &changed).is_err(),
        "substituted distinct statement accepted",
    )?;
    for index in 0..PUBLIC_VALUES {
        let old = proof.public[index];
        proof.public[index] += Val::ONE;
        let rejected = key.verify(&proof).is_err();
        proof.public[index] = old;
        require(rejected, "changed aggregate public value accepted")?;
    }
    let opening = proof
        .proof
        .opened_values
        .instances
        .first_mut()
        .and_then(|i| i.base_opened_values.trace_local.first_mut())
        .ok_or("aggregate has no trace opening")?;
    let original_opening = *opening;
    *opening += lattica_prover_p3::block_v2::profile::Challenge::ONE;
    let rejected = key.verify(&proof).is_err();
    proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] = original_opening;
    require(rejected, "changed aggregate opening accepted")?;
    key.verify_expected(&proof, &originals)?;
    let bytes = postcard::to_allocvec(&(&proof.public, &proof.proof))?;
    let artifact = directory.join("aggregate.postcard");
    save(&artifact, &bytes)?;
    require(read(&artifact)? == bytes, "persisted artifact changed")?;
    let mut result = json!({"count":count,"fresh_distinct_transactions":digests.len(),"cache":statistics,
        "source_identities":source_ids,"statement_digests":digests,"merges":merges,
        "changed_public_rejected_count":PUBLIC_VALUES,"changed_proof_rejected":true,
        "distinct_reordering_rejected":true,"distinct_substitution_rejected":true,
        "graph_proof_substitution_rejected":true,"complete_graphs_verified":count,
        "artifact":{"path":artifact,"bytes":bytes.len(),"sha3_256":hex(&Sha3_256::digest(&bytes))}});
    if args.benchmark {
        result["timing"] = json!({
            "active_wall_seconds":case_started.elapsed().as_secs_f64(),
            "cpu_input_fixture_setup_seconds":cpu_input_fixture_seconds,
            "cpu_input_validation_decode_seconds":cpu_input_validation_decode_seconds,
            "cpu_post_shutdown_artifact_decode_verify_seconds":0.0,
            "gpu_operation_wall":gpu_operation_timing(gpu_before, gpu_operation_seconds(&worker.report())?)?,
            "scope":"fresh_case_with_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io",
            "excludes":"shared_session_setup_shutdown_and_other_cases",
            "includes_internal_cpu_verification":true,"includes_cpu_correctness_diagnostics":true});
    }
    event("fresh_case_verified", result.clone());
    Ok(Completed {
        key,
        originals,
        artifact,
        result,
    })
}

fn run() -> Result<()> {
    let Some(mut args) = arguments()? else {
        return Ok(());
    };
    let run_started = Instant::now();
    fs::create_dir(&args.directory)?;
    args.directory = fs::canonicalize(&args.directory)?;
    let failures = args.directory.join("failures");
    fs::create_dir(&failures)?;
    let worker = ProvingContext::opencl(args.limits)?;
    worker.set_failure_directory(failures)?;
    let mut cases = Vec::new();
    for &count in &args.counts {
        match case(&worker, &args, count) {
            Ok(completed) => cases.push(completed),
            Err(error) => {
                let report = worker.report();
                let cleanup = worker.close_without_completion();
                let failure = json!({"schema":"pq-opencl-opt-failure-v1", "count":count,
                    "error":error.to_string(), "context":report, "cleanup":cleanup,
                    "retry_attempted":false});
                // Failure before a proof is returned still leaves bounded public
                // metadata. No witness, private fixture or RNG state is saved.
                save(
                    &args.directory.join("failure.json"),
                    &serde_json::to_vec_pretty(&failure)?,
                )?;
                event("failed", failure);
                return Err(error);
            }
        }
    }
    let context_report = worker.finish()?;
    let operations = &context_report["operations"];
    require(
        operations["native_cpu_calls"].as_u64() == Some(0),
        "GPU prover used native CPU work",
    )?;
    let expected_spends = args.counts.iter().map(|&n| u64::from(n)).sum::<u64>();
    require(
        operations["native_spend_calls"].as_u64() == Some(expected_spends)
            && operations["native_spend_succeeded"].as_u64() == Some(expected_spends)
            && operations["native_spend_complete_reports"].as_u64() == Some(expected_spends),
        "fresh GPU native private-spend coverage incomplete",
    )?;
    let native_calls = operations["native_gpu_calls"]
        .as_u64()
        .ok_or("missing native GPU accounting")?;
    require(
        native_calls > 0
            && operations["native_gpu_succeeded"].as_u64() == Some(native_calls)
            && operations["native_gpu_complete_reports"].as_u64() == Some(native_calls),
        "native GPU coverage incomplete",
    )?;

    let mut results = Vec::new();
    for mut case in cases {
        let verify_started = Instant::now();
        let stored = read(&case.artifact)?;
        let ((public, proof), tail): (([Val; PUBLIC_VALUES], RawProof<Config>), &[u8]) =
            postcard::take_from_bytes(&stored)?;
        require(tail.is_empty(), "trailing artifact bytes")?;
        case.key
            .verify_expected(&BatchProof { public, proof }, &case.originals)?;
        let verify_seconds = verify_started.elapsed().as_secs_f64();
        case.result["decoded_verification_after_gpu_shutdown"] = json!(true);
        if args.benchmark {
            let count = case.originals.len();
            let active = case.result["timing"]["active_wall_seconds"]
                .as_f64()
                .ok_or("missing case wall timing")?
                + verify_seconds;
            case.result["timing"]["active_wall_seconds"] = json!(active);
            case.result["timing"]["cpu_post_shutdown_artifact_decode_verify_seconds"] =
                json!(verify_seconds);
            case.result["timing"]["active_workflow_transactions_per_hour"] =
                json!(measured_rate(count, active)?);
        }
        results.push(case.result);
    }
    let mut result = json!({"schema":"pq-opencl-opt-correctness-v2","passed":true,"cases":results,
        "context":context_report,"proving_scope":"native_private_spend_and_native_recursive_stark_proving",
        "fixture_generation":"cpu_ring_ask_inputs_only","native_private_spend_generation":"gpu_required",
        "independent_verification":"cpu",
        "native_gpu_required":true,"witness_preparation":"gpu_required",
        "comparison_baseline":false,"performance_qualified":false,"benchmark_measured":args.benchmark,
        "fixture_pattern":"fresh_distinct","original_profile":true,"num_queries":128,
        "blowup":16,"hiding":true,"extension":"Goldilocks cubic trinomial"});
    if args.benchmark {
        let seconds = run_started.elapsed().as_secs_f64();
        let count = args.counts.iter().map(|&n| n as usize).sum::<usize>();
        result["measurement"] = json!({"schema":"pq-opencl-fresh-workflow-timing-v2",
            "transactions":count,"run_wall_seconds":seconds,
            "fresh_end_to_end_correctness_workflow_transactions_per_hour":measured_rate(count, seconds)?,
            "scope":"single_serial_context_fresh_fixtures_preparation_native_recursive_proving_verification_mutations_artifact_io_shutdown",
            "excludes":"process_launch_and_final_result_serialization",
            "gpu_operation_wall":gpu_operation_timing([0.0; 5], gpu_operation_seconds(&context_report)?)?,
            "clock":"host_monotonic_wall","device_only":false,"production_throughput":false,
            "comparison_baseline":false});
    }
    save(
        &args.directory.join("result.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    println!("OPENCL_OPT_RESULT {}", result);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("pq_opencl_opt_correctness_failed: {error}");
        std::process::exit(1);
    }
}
