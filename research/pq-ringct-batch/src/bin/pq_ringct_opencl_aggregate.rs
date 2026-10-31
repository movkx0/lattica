//! Fresh-process driver for strict GPU recursion. Diagnostic and full MatRiCT
//! scopes are separate and cannot share a success claim.
use lattica_pq_ringct_batch::{
    opencl::{aggregate_with_context, SCHEMA},
    BatchProof, Child, Plan, PUBLIC_VALUES,
};
use lattica_pq_ringct_research::{
    execution::ProvingContext,
    graph_crypto,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{GraphContext, Plan as GraphPlan},
    native,
    opencl::Limits,
    proof_cache_policy::{CacheStatistics, ProofCachePolicy},
    recursive_aggregation::LeafStatement,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
    spend_pipeline::{AesLayout, Budgets, CompositeLayout, SpendPipeline, TranscriptLayout},
};
use lattica_prover_p3::block_v2::{machine::program::Val, profile::Config};
use p3_batch_stark::BatchProof as RawProof;
use p3_field::PrimeCharacteristicRing;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[path = "../opencl_diagnostic.rs"]
mod diagnostic;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FILE_LIMIT: u64 = 64 << 20;

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
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular nonsymlink input required",
    )?;
    require(metadata.len() <= limit, "input exceeds bounded read")?;
    let mut data = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    require(data.len() as u64 <= limit, "input grew beyond bounded read")?;
    Ok(data)
}
fn persist(path: &Path, bytes: &[u8]) -> Result<Value> {
    require(
        bytes.len() as u64 <= FILE_LIMIT,
        "proof exceeds diagnostic artifact allowance",
    )?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    require(
        read(path, FILE_LIMIT)? == bytes,
        "persisted proof bytes changed",
    )?;
    Ok(
        json!({"path":path,"bytes":bytes.len(),"sha3_256":hex(&Sha3_256::digest(bytes)),
        "codec":"diagnostic-postcard-public-and-proof-tuple",
        "includes_trusted_registered_key":false,"includes_original_statements":false,
        "includes_ledger_body":false}),
    )
}
fn event(name: &str, value: Value) {
    eprintln!(
        "OPENCL_AGGREGATION {}",
        json!({"event":name,"details":value})
    );
}

/// Accept only a new empty cache or one explicitly created for this compiled
/// source. Existing CPU evidence caches cannot be adopted by copying entries
/// or changing their filenames. This marker binds the directory to its source;
/// FreshOnly separately forbids reading any cached proof payload.
fn admit_cache(path: &Path, source: &str) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "cache must be a nonsymlink directory",
    )?;
    let marker = path.join(".opencl-compiled-source-identity");
    if marker.try_exists()? {
        require(
            read(&marker, 128)? == source.as_bytes(),
            "cache belongs to a different compiled source",
        )?;
    } else {
        require(
            fs::read_dir(path)?.next().is_none(),
            "unmarked cache must be empty; frozen CPU caches cannot be imported",
        )?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)?;
        file.write_all(source.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

struct Arguments {
    mode: String,
    output: PathBuf,
    limits: Limits,
    fixture: Option<PathBuf>,
    cache: Option<PathBuf>,
    count: Option<u32>,
    native_bytes: Option<u64>,
}
fn arguments() -> Result<Option<Arguments>> {
    let mut values = std::collections::BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" {
            println!("pq-ringct-opencl-aggregate --mode diagnostic|matrict --output NEW_FILE --host-bytes N --device-bytes N --max-rows N\nMatRiCT additionally requires --fixture JSON --cache-dir SOURCE_SPECIFIC_DIRECTORY --count 3|4 --native-bytes N.\nRelease-only, fresh process, externally memory-limited and exclusive GPU admission. MatRiCT uses one strict GPU context and FreshOnly proof caches. One freshly proved complete graph from an existing fixture is repeated across the requested leaves; this is not distinct-transaction qualification. CPU input/endpoint/proof verification remains explicit.");
            return Ok(None);
        }
        if arg == "--allow-cpu-child-preparation" {
            return Err("--allow-cpu-child-preparation is obsolete; remove it. MatRiCT child proving now requires the strict GPU path and cannot switch to CPU.".into());
        }
        require(
            [
                "--mode",
                "--output",
                "--host-bytes",
                "--device-bytes",
                "--max-rows",
                "--fixture",
                "--cache-dir",
                "--count",
                "--native-bytes",
            ]
            .contains(&arg.as_str()),
            "unknown argument",
        )?;
        let value = args.next().ok_or("missing argument value")?;
        require(values.insert(arg, value).is_none(), "duplicate argument")?;
    }
    let mut take = |key: &str| values.remove(key).ok_or_else(|| format!("missing {key}"));
    let mode = take("--mode")?;
    require(
        mode == "diagnostic" || mode == "matrict",
        "mode must be diagnostic or matrict",
    )?;
    let output = PathBuf::from(take("--output")?);
    require(!output.try_exists()?, "output must not already exist")?;
    let limits = Limits {
        host_bytes: take("--host-bytes")?.parse()?,
        device_bytes: take("--device-bytes")?.parse()?,
        max_rows: take("--max-rows")?.parse()?,
    };
    limits.validate()?;
    require(
        !cfg!(debug_assertions),
        "OpenCL aggregation requires a release build",
    )?;
    let fixture = values.remove("--fixture").map(PathBuf::from);
    let cache = values.remove("--cache-dir").map(PathBuf::from);
    let count = values.remove("--count").map(|v| v.parse()).transpose()?;
    let native_bytes = values
        .remove("--native-bytes")
        .map(|v| v.parse())
        .transpose()?;
    if mode == "matrict" {
        require(
            fixture.is_some()
                && cache.is_some()
                && matches!(count, Some(3 | 4))
                && native_bytes.is_some(),
            "full MatRiCT mode requires a fixture, source-specific cache, count 3 or 4 and native allowance",
        )?;
        require(
            (1 << 30..=32_u64 << 30).contains(&native_bytes.unwrap()),
            "native allowance must be 1 to 32 GiB",
        )?;
        require(
            native_bytes.unwrap() <= limits.host_bytes,
            "native allowance must not exceed the host allowance for the shared GPU context; lower --native-bytes or select an admitted --host-bytes allowance",
        )?;
    } else {
        require(
            fixture.is_none() && cache.is_none() && count.is_none() && native_bytes.is_none(),
            "diagnostic mode does not accept MatRiCT preparation arguments",
        )?;
    }
    Ok(Some(Arguments {
        mode,
        output,
        limits,
        fixture,
        cache,
        count,
        native_bytes,
    }))
}

/// FreshOnly applies to every component of the one newly proved graph. Reusing
/// that graph as multiple batch leaves is reported separately below.
fn check_fresh(statistics: &CacheStatistics) -> Result<()> {
    require(
        statistics.policy == ProofCachePolicy::FreshOnly && statistics.families.len() == 5,
        "incorrect proof cache policy",
    )?;
    for family in statistics.families.values() {
        require(
            family.reads == 0 && family.hits == 0,
            "GPU child preparation read cached proof payload",
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
            .any(|family| family.fresh_proofs > 0),
        "no fresh graph proofs produced",
    )
}

fn matrict(args: Arguments) -> Result<Value> {
    require(
        std::env::var_os("LATTICA_WALLET_WORKER_BUDGET").is_none(),
        "assigned wallet workers cannot run standalone aggregation qualification",
    )?;
    let encoded = read(args.fixture.as_ref().unwrap(), 16 << 20)?;
    let fixture: Value = serde_json::from_slice(&encoded)?;
    require(
        fixture["schema"].as_u64() == Some(1),
        "unsupported fixture schema",
    )?;
    let context: [u8; 32] = serde_json::from_value(fixture["context"].clone())?;
    let seed: [u8; 32] = serde_json::from_value(fixture["setup_seed"].clone())?;
    let statement: Vec<u8> = serde_json::from_value(fixture["statement"].clone())?;
    let proof: Vec<u8> = serde_json::from_value(fixture["proof"].clone())?;
    let decoded_statement = Statement::decode(&statement)?;
    let decoded_proof = Proof::decode(&proof)?;
    require(
        decoded_statement.seed == seed && native::verify(&context, &statement, &proof)?,
        "native fixture rejected",
    )?;
    let native_bytes = args.native_bytes.unwrap();
    let started = Instant::now();
    event(
        "gpu_child_preparation_begin",
        json!({"policy":"gpu-required","source_specific_cache":args.cache,
            "proof_cache_policy":"fresh_only","counts_as_gpu_work":true,
            "includes_cpu_verification":true,"device_only_timing":false}),
    );
    let worker = ProvingContext::opencl(args.limits)?;
    let graph = committed_backend::lower_unproved_on_gpu(
        seed,
        &context,
        &decoded_statement,
        &decoded_proof,
        &worker,
        usize::try_from(native_bytes)?,
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
            max_estimated_prover_bytes: native_bytes,
        },
        Some(&worker),
    )?;
    let graph_plan = GraphPlan::from_trusted_graph(&graph, algebra.operation_batches())?;
    let ((original, node_manifest), _) =
        worker.with_witness_preparation(usize::try_from(native_bytes)?, |operations| {
            let original = LeafStatement::from_bytes_on_gpu(
                graph_plan.label(),
                context,
                &statement,
                operations,
            )
            .map_err(|e| e.to_string())?;
            let manifest = graph_plan
                .node_manifest_hint_on_gpu(&graph, operations)
                .map_err(|e| e.to_string())?;
            Ok((original, manifest))
        })?;
    let graph_context = GraphContext {
        context,
        statement: original.digest.map(Val::from_u64),
        node_manifest,
    };
    let source_identity = hex(&algebra.source_fingerprint());
    admit_cache(args.cache.as_ref().unwrap(), &source_identity)?;
    let leaves = graph_plan.leaves().len();
    let pipeline = SpendPipeline::new_with_policy(
        args.cache.as_ref().unwrap(),
        Budgets {
            native_bytes,
            outer_bytes: args.limits.host_bytes,
            cache_entry_bytes: FILE_LIMIT,
            crypto_policy: graph_crypto::Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 32,
                child_memory_budget_bytes: native_bytes,
                admission: graph_crypto::Admission::Estimated,
            },
            transcripts: TranscriptLayout::Serial,
            aes: AesLayout::Serial,
            composites: CompositeLayout::Branches,
        },
        ProofCachePolicy::FreshOnly,
    )?;
    let complete = pipeline.prove_registered_with_context(
        &graph_plan,
        &algebra,
        &graph,
        &graph_context,
        &statement,
        &proof,
        &worker,
    )?;
    complete
        .key()
        .verify_complete(complete.proof(), &graph_context)?;
    let statistics = pipeline.cache_statistics();
    check_fresh(&statistics)?;
    drop(pipeline);
    drop(algebra);
    drop(registered);
    drop(graph);
    worker.release_prepared()?;
    let preparation_seconds = started.elapsed().as_secs_f64();
    event(
        "gpu_child_preparation_end",
        json!({"seconds":preparation_seconds,"registered_leaves":leaves,
            "complete_graph_verified":true,"source_identity":source_identity,
            "policy":"gpu-required","cache":statistics,"fresh_complete_graph_proofs":1}),
    );
    let count = args.count.unwrap();
    let plan = Plan::new(graph_plan.label(), context, count)?;
    let originals = vec![original; count as usize];
    let children = (0..count)
        .map(|index| {
            plan.graph_child(index, complete.key(), complete.proof(), &graph_context)
                .map(Child::from)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (root, merges) = aggregate_with_context(&worker, &plan, children, &originals)?;
    require(
        merges.len() == count as usize - 1,
        "incorrect recursive merge count",
    )?;
    let Child::Batch(root) = root else {
        return Err("expected actual recursive batch".into());
    };
    let (key, mut proof) = root.into_parts();
    drop(complete);
    worker.release_prepared()?;
    key.verify_expected(&proof, &originals)?;
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
        .ok_or("aggregate proof lacks trace opening")?;
    let original_opening = *opening;
    *opening += lattica_prover_p3::block_v2::profile::Challenge::ONE;
    let rejected = key.verify(&proof).is_err();
    *proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local
        .first_mut()
        .unwrap() = original_opening;
    require(rejected, "changed aggregate proof opening accepted")?;
    key.verify_expected(&proof, &originals)?;
    let bytes = postcard::to_allocvec(&(&proof.public, &proof.proof))?;
    let mut artifact = persist(&args.output, &bytes)?;
    let stored = read(&args.output, FILE_LIMIT)?;
    let ((public, raw), tail): (([Val; PUBLIC_VALUES], RawProof<Config>), &[u8]) =
        postcard::take_from_bytes(&stored)?;
    require(tail.is_empty(), "trailing artifact bytes")?;
    let context_report = worker.finish()?;
    let operations = &context_report["operations"];
    require(
        context_report["session_closed"].as_bool() == Some(true)
            && operations["native_cpu_calls"].as_u64() == Some(0),
        "GPU context did not close cleanly or used native CPU proving",
    )?;
    for (calls, succeeded, complete_reports) in [
        (
            "native_gpu_calls",
            "native_gpu_succeeded",
            Some("native_gpu_complete_reports"),
        ),
        (
            "witness_preparation_calls",
            "witness_preparation_succeeded",
            Some("witness_preparation_complete_reports"),
        ),
        ("prove_calls", "prove_succeeded", None),
    ] {
        let count = operations[calls]
            .as_u64()
            .ok_or("missing GPU operation accounting")?;
        require(
            count > 0
                && operations[succeeded].as_u64() == Some(count)
                && complete_reports.is_none_or(|name| operations[name].as_u64() == Some(count)),
            "GPU operation coverage incomplete",
        )?;
    }
    let mut result = json!({
        "schema":SCHEMA,"passed":true,"merge_count":merges.len(),"merges":merges,
        "session":context_report["session_finish"],"context":context_report,
        "strict_stage_reports_required":true,"complete_ledger_transaction_qualified":false,
        "relation_kind":"ordered complete standalone MatRiCT relations",
        "claims":"One freshly proved graph from an existing native fixture, repeated across batch leaves; no fresh distinct-transaction, ledger, transaction-size, total-compute, throughput or cross-vendor performance claim"
    });
    key.verify_expected(&BatchProof { public, proof: raw }, &originals)?;
    artifact["decoded_payload_reverified"] = json!(true);
    result["mode"] = json!("matrict");
    result["count"] = json!(count);
    result["fixture_sha3_256"] = json!(hex(&Sha3_256::digest(&encoded)));
    result["source_identity"] = json!(source_identity);
    result["registered_graph_leaves"] = json!(leaves);
    result["gpu_child_preparation_seconds"] = json!(preparation_seconds);
    result["child_preparation_timing_scope"] = json!(
        "wall time including GPU initialization, host orchestration and independent CPU checks"
    );
    result["child_preparation_backend"] = json!("opencl");
    result["cache"] = json!(statistics);
    result["fresh_complete_graph_proofs"] = json!(1);
    result["unique_fixture_statements"] = json!(1);
    result["repeated_child_proof"] = json!(true);
    result["fresh_distinct_transaction_qualified"] = json!(false);
    result["repeated_standalone_relation"] = json!(true);
    result["fixture_pattern"] = json!("repeated_single_fixture");
    result["complete_matrict_relation_qualified"] = json!(true);
    result["changed_public_rejected_count"] = json!(PUBLIC_VALUES);
    result["cpu_verification"] = json!(true);
    result["changed_public_rejected"] = json!(true);
    result["changed_proof_rejected"] = json!(true);
    result["original_graph_dropped_before_final_verification"] = json!(true);
    result["decoded_verification_after_gpu_shutdown"] = json!(true);
    result["original_profile"] = json!(true);
    result["num_queries"] = json!(128);
    result["blowup"] = json!(16);
    result["extension"] = json!("Goldilocks cubic trinomial");
    result["hiding"] = json!(true);
    result["artifact"] = artifact;
    Ok(result)
}
fn run() -> Result<()> {
    let Some(args) = arguments()? else {
        return Ok(());
    };
    let result = if args.mode == "diagnostic" {
        diagnostic::run(args.limits, &args.output)?
    } else {
        matrict(args)?
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("pq_opencl_recursive_aggregation_failed: {error}");
        std::process::exit(1);
    }
}
