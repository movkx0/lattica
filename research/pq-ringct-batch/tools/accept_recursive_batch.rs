//! Guarded, additive N=3/N=4 recursive acceptance client.
//!
//! This is deliberately outside the frozen child sources. SpendPipeline is a
//! load-or-prove API, not a replay-only API. The coordinating runner must admit
//! a successful complete baseline, exact copied inventories and this binary's
//! build identity, then reject any replay miss/report or inventory change.
//! A/B/A and A/B/A/B are repeated standalone relations, not distinct ledger spends.
use lattica_pq_ringct_batch::{
    compile_merge, BatchKey, BatchNode, BatchProof, Child, Plan as BatchPlan, PUBLIC_VALUES,
};
use lattica_pq_ringct_research::{
    graph_crypto,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{GraphContext, NodeKey as GraphKey, NodeProof as GraphProof, Plan as GraphPlan},
    native,
    recursive_aggregation::LeafStatement,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
    spend_pipeline::{AesLayout, Budgets, CompositeLayout, SpendPipeline, TranscriptLayout},
};
use lattica_prover_p3::block_v2::{
    machine::program::Val,
    profile::{Challenge, Config},
};
use p3_batch_stark::BatchProof as RawProof;
use p3_field::PrimeCharacteristicRing;
use serde_json::{json, Map, Value};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SOURCE_FP: &str = "dcb76008a97d7f98c483134482ec65769d5d1fcc0ca858c8b6f7fd43939150a2";
const GRAPH_PROFILE: &str = "4bc6d06ac109a269904637b564628cb5c9542a9c70e685f06276747295ba24aa";
const BATCH_SOURCE: &str = env!("LATTICA_BATCH_SOURCE_IDENTITY");
const NATIVE_BUDGET: u64 = 32 << 30;
const OUTER_BUDGET: u64 = 48 << 30;
// Principal temporary evaluation buffers only; the existing process cap also
// covers the resident program/witness and allocator overhead.
const WITNESS_CHECK_BUDGET: u64 = 1 << 30;
const CACHE_LIMIT: u64 = 64 << 20;
const FIXTURE_LIMIT: u64 = 16 << 20;
const SETTINGS: [(&str, &str); 8] = [
    ("LATTICA_SPEND_ALGEBRA_BATCH", "64"),
    ("LATTICA_SPEND_NTT_BATCH", "32"),
    ("LATTICA_SPEND_MUL_BATCH", "32"),
    ("LATTICA_SPEND_NATIVE_GIB", "32"),
    ("LATTICA_SPEND_OUTER_GIB", "48"),
    ("LATTICA_SPEND_AES_SERIAL_BATCH", "64"),
    ("LATTICA_SPEND_SHAKE_SERIAL_BATCH", "32"),
    ("LATTICA_SPEND_COMPOSITE_LAYOUT", "branches"),
];

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::other(message).into())
    }
}
fn emit(event: &str, mut value: Value) {
    value["event"] = Value::String(event.into());
    eprintln!("BATCH_ACCEPTANCE {value}");
}
fn emit_case(case: u32, event: &str, mut value: Value) {
    value["case"] = Value::from(case);
    emit(event, value);
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(text: &str) -> Result<[u8; 32]> {
    require(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid canonical lowercase 32-byte digest",
    )?;
    let mut value = [0; 32];
    for (index, item) in value.iter_mut().enumerate() {
        *item = u8::from_str_radix(&text[2 * index..2 * index + 2], 16)?;
    }
    Ok(value)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}").into())
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular nonsymlink file required",
    )?;
    require(metadata.len() <= limit, "file exceeds bounded read")?;
    let mut data = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    require(data.len() as u64 <= limit, "file grew beyond bounded read")?;
    Ok(data)
}
fn audit_file(path: &Path, expected: &Value, limit: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "inventory file must not be a symlink",
    )?;
    let bytes = expected["bytes"]
        .as_u64()
        .ok_or("missing inventory length")?;
    require(
        bytes > 0 && bytes <= limit && metadata.len() == bytes,
        "inventory file length mismatch",
    )?;
    // SHA256 is independently checked by the runner. This process verifies
    // exact copied bytes with the already-linked SHA3 implementation.
    digest(string(expected, "sha256")?)?;
    let expected_hash = string(expected, "sha3_256")?;
    digest(expected_hash)?;
    let mut file = File::open(path)?;
    let mut hash = Sha3_256::new();
    let mut buffer = [0u8; 64 << 10];
    let mut read_bytes = 0u64;
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(length as u64)
            .ok_or("inventory size overflow")?;
        require(read_bytes <= bytes, "inventory file changed during hashing")?;
        hash.update(&buffer[..length]);
    }
    require(
        read_bytes == bytes && hex(&hash.finalize()) == expected_hash,
        "inventory content hash mismatch",
    )
}
fn inventory_paths(directory: &Path, root: &Path, found: &mut BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        require(!kind.is_symlink(), "cache inventory contains symlink")?;
        if kind.is_dir() {
            inventory_paths(&entry.path(), root, found)?;
        } else {
            require(kind.is_file(), "cache inventory contains nonregular file")?;
            let relative = entry.path().strip_prefix(root)?.to_path_buf();
            let name = relative.to_str().ok_or("non-UTF8 cache path")?.to_owned();
            require(found.insert(name), "duplicate cache inventory path")?;
        }
    }
    Ok(())
}
fn audit_cache(directory: &Path, entries: &Map<String, Value>) -> Result<()> {
    require(!entries.is_empty(), "complete replay inventory is empty")?;
    let metadata = fs::symlink_metadata(directory)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "cache root is not a nonsymlink directory",
    )?;
    let mut found = BTreeSet::new();
    inventory_paths(directory, directory, &mut found)?;
    let expected: BTreeSet<_> = entries.keys().cloned().collect();
    require(
        found == expected,
        "cache inventory membership changed or is incomplete",
    )?;
    for (name, metadata) in entries {
        let relative = Path::new(name);
        require(
            relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "unsafe relative cache inventory path",
        )?;
        let first = relative.components().next().ok_or("empty cache path")?;
        require(
            ["sources", "algebra", "crypto", "auxiliary", "outer"]
                .iter()
                .any(|name| first.as_os_str() == *name),
            "unknown copied cache family",
        )?;
        require(
            relative
                .extension()
                .is_some_and(|extension| extension == "json"),
            "unexpected cache file extension",
        )?;
        audit_file(&directory.join(relative), metadata, CACHE_LIMIT)?;
    }
    Ok(())
}

struct Fixture {
    statement: Vec<u8>,
    proof: Vec<u8>,
}
fn load_fixture(path: &Path, metadata: &Value, index: usize) -> Result<Fixture> {
    audit_file(path, metadata, FIXTURE_LIMIT)?;
    let encoded = bounded_read(path, FIXTURE_LIMIT)?;
    let object: Value = serde_json::from_slice(&encoded)?;
    let fields = object.as_object().ok_or("fixture object required")?;
    require(
        fields.len() == 5
            && ["schema", "context", "setup_seed", "statement", "proof"]
                .iter()
                .all(|key| fields.contains_key(*key))
            && object["schema"].as_u64() == Some(1),
        "unexpected fixture schema",
    )?;
    let context: [u8; 32] = serde_json::from_value(object["context"].clone())?;
    let setup_seed: [u8; 32] = serde_json::from_value(object["setup_seed"].clone())?;
    let statement: Vec<u8> = serde_json::from_value(object["statement"].clone())?;
    let proof: Vec<u8> = serde_json::from_value(object["proof"].clone())?;
    require(
        context == [71; 32] && setup_seed == [29; 32],
        "fixture setup/context mismatch",
    )?;
    let decoded = Statement::decode(&statement)?;
    Proof::decode(&proof)?;
    require(
        decoded.seed == setup_seed,
        "fixture statement seed mismatch",
    )?;
    require(
        native::verify(&context, &statement, &proof)?,
        "native fixture verification failed",
    )?;
    emit(
        "fixture_verified",
        json!({"fixture_index": index, "native_verified": true,
        "statement_bytes": statement.len(), "native_relation_proof_bytes": proof.len()}),
    );
    Ok(Fixture { statement, proof })
}

struct Admission {
    document: Value,
    cache: PathBuf,
    output: PathBuf,
    fixtures: [Fixture; 2],
}
impl Admission {
    fn entries(&self) -> Result<&Map<String, Value>> {
        self.document["cache_entries"]
            .as_object()
            .ok_or("missing cache entries".into())
    }
    fn audit(&self) -> Result<()> {
        audit_cache(&self.cache, self.entries()?)?;
        for fixture in self.document["fixtures"]
            .as_array()
            .ok_or("missing fixture inventory")?
        {
            audit_file(Path::new(string(fixture, "path")?), fixture, FIXTURE_LIMIT)?;
        }
        Ok(())
    }
    fn load(path: &Path, output: &Path) -> Result<Self> {
        let document: Value = serde_json::from_slice(&bounded_read(path, FIXTURE_LIMIT)?)?;
        require(
            string(&document, "schema")? == "pq-ringct-batch-replay-admission-v1",
            "admission schema mismatch",
        )?;
        let cases: Vec<u32> = serde_json::from_value(document["cases"].clone())?;
        require(
            cases == [3, 4],
            "both N3 and N4 cases are required in order",
        )?;
        let schedules = document["ordered_fixture_indices"]
            .as_object()
            .ok_or("missing schedules")?;
        require(
            schedules.len() == 2,
            "exactly two repeated relation schedules required",
        )?;
        for case in cases {
            let ordered: Vec<usize> = serde_json::from_value(
                schedules
                    .get(&case.to_string())
                    .ok_or("missing case schedule")?
                    .clone(),
            )?;
            require(
                ordered == (0..case as usize).map(|i| i % 2).collect::<Vec<_>>(),
                "unexpected repeated relation schedule",
            )?;
        }
        require(
            string(&document, "source_fingerprint")? == SOURCE_FP,
            "admitted child source mismatch",
        )?;
        // The linked child source is checked through the public
        // GraphProofPlan::source_fingerprint accessor in replay(), before its
        // replay_begin event and any call to the load-or-prove pipeline.
        require(
            string(&document, "graph_plan_label")? == GRAPH_PROFILE,
            "admitted graph profile mismatch",
        )?;
        require(
            string(&document, "batch_source_identity")? == BATCH_SOURCE,
            "client build/source identity mismatch",
        )?;
        digest(BATCH_SOURCE)?;
        let settings = document["settings"].as_object().ok_or("missing settings")?;
        require(
            settings.len() == SETTINGS.len(),
            "unexpected replay settings",
        )?;
        for (name, expected) in SETTINGS {
            require(
                settings.get(name).and_then(Value::as_str) == Some(expected),
                "replay setting differs from frozen baseline",
            )?;
        }
        require(
            std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1"),
            "proving reports must be enabled",
        )?;
        require(
            std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("8"),
            "eight-thread runner admission required",
        )?;
        let baseline = &document["baseline"];
        let baseline_path = Path::new(string(baseline, "path")?);
        audit_file(baseline_path, baseline, FIXTURE_LIMIT)?;
        let baseline_record: Value =
            serde_json::from_slice(&bounded_read(baseline_path, FIXTURE_LIMIT)?)?;
        require(
            baseline_record["status"].as_str() == Some("passed")
                && baseline_record["two_complete_graphs_and_actual_ordered_pair_accepted"]
                    .as_bool()
                    == Some(true)
                && baseline_record["all_subprocesses_terminal_and_reaped"].as_bool() == Some(true)
                && baseline_record["measurement"]["exit_code"].as_i64() == Some(0)
                && baseline_record["compiled_source_identity"].as_str() == Some(SOURCE_FP),
            "complete successful terminal baseline required",
        )?;
        require(
            output.is_absolute() && output.file_name().is_some_and(|name| name == "artifacts"),
            "absolute case/artifacts output required",
        )?;
        require(
            Path::new(string(&document, "output_directory")?) == output,
            "output admission differs from CLI",
        )?;
        let parent = output.parent().ok_or("missing case directory")?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        require(
            parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
            "case directory must not be a symlink",
        )?;
        require(
            parent.canonicalize()? == parent,
            "case directory must be canonical",
        )?;
        require(
            path.canonicalize()?.parent() == Some(parent),
            "admission must belong to case directory",
        )?;
        let cache = PathBuf::from(string(&document, "cache_directory")?);
        require(
            cache == parent.join("cache") && cache.canonicalize()? == cache,
            "only isolated case/cache replay is permitted",
        )?;
        require(!output.exists(), "artifact directory must be new")?;
        let entries = document["cache_entries"]
            .as_object()
            .ok_or("missing cache inventory")?;
        audit_cache(&cache, entries)?;
        let metadata = document["fixtures"].as_array().ok_or("missing fixtures")?;
        require(
            metadata.len() == 2,
            "exactly two admitted fixtures required",
        )?;
        for (index, item) in metadata.iter().enumerate() {
            require(
                item["index"].as_u64() == Some(index as u64),
                "fixture inventory order/index mismatch",
            )?;
            let expected = parent.join(format!("fixture-{index}.json"));
            require(
                Path::new(string(item, "path")?) == expected
                    && expected.canonicalize()? == expected,
                "fixture must be a canonical copied case file",
            )?;
        }
        // Both fixtures are native-verified before either graph replay begins.
        let a = load_fixture(Path::new(string(&metadata[0], "path")?), &metadata[0], 0)?;
        let b = load_fixture(Path::new(string(&metadata[1], "path")?), &metadata[1], 1)?;
        require(
            a.statement != b.statement,
            "A and B must be different original statements",
        )?;
        Ok(Self {
            document,
            cache,
            output: output.to_path_buf(),
            fixtures: [a, b],
        })
    }
}

struct Recovered {
    key: GraphKey,
    proof: GraphProof,
    context: GraphContext,
    statement: LeafStatement,
}
fn replay(admission: &Admission, index: usize, pipeline: &SpendPipeline) -> Result<Recovered> {
    let fixture = &admission.fixtures[index];
    let decoded_statement = Statement::decode(&fixture.statement)?;
    let decoded_proof = Proof::decode(&fixture.proof)?;
    let graph =
        committed_backend::lower_unproved([29; 32], &[71; 32], &decoded_statement, &decoded_proof)?;
    let registered = RegisteredGraphShape::from_trusted_graph(&graph)?;
    let algebra = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: 32,
            max_mul_batch_count: 32,
            max_trace_cells: 1 << 27,
            max_estimated_prover_bytes: NATIVE_BUDGET,
        },
    )?;
    let plan = GraphPlan::from_trusted_graph(&graph, algebra.operation_batches())?;
    require(
        hex(&algebra.source_fingerprint()) == SOURCE_FP,
        "replayed source mismatch",
    )?;
    require(
        hex(&plan.label()) == GRAPH_PROFILE && plan.leaves().len() == 91,
        "replayed chosen91 graph mismatch",
    )?;
    let statement = LeafStatement::from_bytes(plan.label(), [71; 32], &fixture.statement)?;
    let context = GraphContext {
        context: [71; 32],
        statement: statement.digest.map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph)?,
    };
    admission.audit()?;
    emit(
        "replay_begin",
        json!({"fixture_index": index, "registered_leaves": 91,
        "load_or_prove_api": true, "strict_replay_only_api": false}),
    );
    let started = Instant::now();
    let complete = pipeline.prove_registered(
        &plan,
        &algebra,
        &graph,
        &context,
        &fixture.statement,
        &fixture.proof,
    )?;
    complete.key().verify_complete(complete.proof(), &context)?;
    admission.audit()?;
    emit(
        "replay_end",
        json!({"fixture_index": index, "complete_graph_verified": true,
        "cache_unchanged": true, "seconds": started.elapsed().as_secs_f64(),
        "registered_leaves": 91, "ledger_binding": false}),
    );
    let (key, proof) = complete.into_parts();
    Ok(Recovered {
        key,
        proof,
        context,
        statement,
    })
}
fn graph_child<'a>(plan: &BatchPlan, index: u32, graph: &'a Recovered) -> Result<Child<'a>> {
    Ok(plan
        .graph_child(index, &graph.key, &graph.proof, &graph.context)?
        .into())
}
fn copy_proof(proof: &BatchProof) -> Result<BatchProof> {
    decode_proof(&postcard::to_allocvec(&(&proof.public, &proof.proof))?)
}
fn decode_proof(bytes: &[u8]) -> Result<BatchProof> {
    let ((public, proof), remaining): (([Val; PUBLIC_VALUES], RawProof<Config>), &[u8]) =
        postcard::take_from_bytes(bytes)?;
    require(remaining.is_empty(), "trailing proof artifact bytes")?;
    Ok(BatchProof { public, proof })
}
struct CaseJob {
    case: u32,
    output: PathBuf,
}
fn artifact(job: &CaseJob, phase: &str, key: &BatchKey, proof: &BatchProof) -> Result<Value> {
    let bytes = postcard::to_allocvec(&(&proof.public, &proof.proof))?;
    require(
        bytes.len() as u64 <= CACHE_LIMIT,
        "batch artifact exceeds diagnostic limit",
    )?;
    let identity = hex(&Sha3_256::digest(&bytes));
    let path = job.output.join(format!("{phase}-{identity}.postcard"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let stored = bounded_read(&path, CACHE_LIMIT)?;
    require(stored == bytes, "persisted batch artifact differs")?;
    let decoded = decode_proof(&stored)?;
    key.verify(&decoded)?;
    let report = json!({"phase": phase, "path": path, "codec": "diagnostic-postcard-public-and-proof-tuple",
        "bytes": bytes.len(), "sha3_256": identity, "decoded_payload_reverified": true,
        "includes_trusted_registered_key": false, "includes_original_statements": false,
        "includes_ledger_body": false, "batch_source_identity": BATCH_SOURCE});
    emit_case(job.case, "artifact", report.clone());
    Ok(report)
}
fn prove_node(
    job: &CaseJob,
    phase: &str,
    children: [Child<'_>; 2],
) -> Result<(BatchNode, Vec<Value>)> {
    let aggregate_children = children
        .iter()
        .filter(|child| matches!(child, Child::Batch(_)))
        .count();
    let child_spans: Vec<_> = children.iter().map(Child::span).collect();
    let aggregate_child_indices: Vec<_> = children
        .iter()
        .enumerate()
        .filter_map(|(index, child)| matches!(child, Child::Batch(_)).then_some(index))
        .collect();
    let started = Instant::now();
    let compiled = compile_merge(children)?;
    let geometry = compiled.geometry()?;
    emit_case(
        job.case,
        "batch_node_compiled",
        json!({"phase": phase, "child_spans": child_spans,
        "aggregate_children": aggregate_children, "active_rows": geometry.active_rows,
        "padded_rows": geometry.padded_rows, "retained_lde_bytes": geometry.retained_lde_bytes,
        "main_width": geometry.main_width, "preprocessed_width": geometry.preprocessed_width,
        "permutation_width_base": geometry.permutation_width_base, "quotient_chunks": geometry.quotient_chunks,
        "seconds": started.elapsed().as_secs_f64()}),
    );
    let (prepared, checks) = if aggregate_children == 0 {
        (compiled.prepare(OUTER_BUDGET)?, Vec::new())
    } else {
        require(
            phase == format!("complete-n{}", job.case),
            "recursive witness checks must belong to the final case merge",
        )?;
        compiled.prepare_with_recursive_witness_checks(OUTER_BUDGET, WITNESS_CHECK_BUDGET)?
    };
    require(
        checks.len() == aggregate_children
            && checks
                .iter()
                .zip(&aggregate_child_indices)
                .all(|(check, &index)| {
                    check.child_index == index
                        && (check.child_first, check.child_count) == child_spans[index]
                }),
        "recursive witness check coverage differs from actual aggregate children",
    )?;
    let cache_identity = hex(&prepared.cache_identity(digest(BATCH_SOURCE)?));
    let node = prepared.prove()?;
    node.key().verify(node.proof())?;
    artifact(job, phase, node.key(), node.proof())?;
    // Emit diagnostic success only after the restored witness has produced a
    // valid parent proof and its persisted payload has been decoded/reverified.
    let checks: Vec<_> = checks
        .iter()
        .map(|check| {
            json!({"child_index": check.child_index,
                "child_span": [check.child_first, check.child_count],
                "mutated_field": "trace_local[0].basis[0]",
                "execution_error": "Unsatisfied",
                "same_compiled_program": true, "public_values_unchanged": true,
                "original_witness_restored": true, "valid_parent_positive_control": true,
                "negative_stark_proof_generated": false,
                "principal_buffer_bound_bytes": check.principal_buffer_bound_bytes,
                "evaluation_budget_bytes": WITNESS_CHECK_BUDGET,
                "evaluation_seconds": check.evaluation_seconds})
        })
        .collect();
    if !checks.is_empty() {
        emit_case(
            job.case,
            "recursive_child_witness_checks",
            json!({"phase": phase, "checks": checks,
                "scope": "emitted aggregate-child verifier assertion rejection"}),
        );
    }
    emit_case(
        job.case,
        "batch_node_proved",
        json!({"phase": phase, "span": node.key().span(),
        "level": node.key().level(), "total": node.key().total(), "aggregate_children": aggregate_children,
        "actual_stark_proof": true, "cache_hit": false, "cache_identity": cache_identity,
        "cache_namespace": "lattica/matrict/ordered-batch/registered-node-cache/v1",
        "prepared_proving_state_dropped": true, "seconds": started.elapsed().as_secs_f64()}),
    );
    Ok((node, checks))
}

fn reject_premerge(case: u32, plan: &BatchPlan, graphs: &[Recovered; 2]) -> Result<()> {
    for (name, indices) in [
        ("reordered_positions", [1, 0]),
        ("omitted_position", [0, 2]),
        ("duplicated_position", [0, 0]),
    ] {
        require(
            compile_merge([
                graph_child(plan, indices[0], &graphs[0])?,
                graph_child(plan, indices[1], &graphs[1])?,
            ])
            .is_err(),
            "invalid original positions admitted",
        )?;
        emit_case(case, "negative", json!({"name": name, "rejected": true}));
    }
    let other_scope = BatchPlan::new(plan.graph_profile(), plan.context(), plan.total())?;
    require(
        compile_merge([
            graph_child(plan, 0, &graphs[0])?,
            graph_child(&other_scope, 1, &graphs[1])?,
        ])
        .is_err(),
        "separately registered batch scopes mixed",
    )?;
    require(
        plan.graph_child(0, &graphs[0].key, &graphs[1].proof, &graphs[0].context)
            .is_err(),
        "swapped graph proof admitted",
    )?;
    let mut wrong_context = graphs[0].context.clone();
    wrong_context.statement[0] += Val::ONE;
    require(
        plan.graph_child(0, &graphs[0].key, &graphs[0].proof, &wrong_context)
            .is_err(),
        "wrong graph statement admitted",
    )?;
    let wrong_profile = BatchPlan::new([0; 32], plan.context(), plan.total())?;
    require(
        graph_child(&wrong_profile, 0, &graphs[0]).is_err(),
        "wrong graph profile admitted",
    )?;
    emit_case(
        case,
        "negative",
        json!({"name": "scope_and_graph_bindings", "rejected": true,
        "separate_scope": true, "swapped_graph_proof": true, "wrong_graph_statement": true,
        "wrong_graph_profile": true}),
    );
    Ok(())
}
fn reject_final(
    case: u32,
    key: &BatchKey,
    proof: &BatchProof,
    originals: &[LeafStatement],
) -> Result<Value> {
    let mut changed = copy_proof(proof)?;
    for index in 0..PUBLIC_VALUES {
        changed.public = proof.public;
        changed.public[index] += Val::ONE;
        require(
            key.verify(&changed).is_err(),
            "mutated public field accepted by actual verifier",
        )?;
    }
    changed.public = proof.public;
    let opening = changed
        .proof
        .opened_values
        .instances
        .get_mut(0)
        .and_then(|instance| instance.base_opened_values.trace_local.get_mut(0))
        .ok_or("missing mutable opening for negative check")?;
    *opening += Challenge::ONE;
    require(
        key.verify(&changed).is_err(),
        "mutated actual proof opening accepted",
    )?;
    let mut reordered = originals.to_vec();
    require(
        reordered[0].digest != reordered[1].digest,
        "order negative requires A/B, not identical repeated entries",
    )?;
    reordered.swap(0, 1);
    require(
        key.verify_expected(proof, &reordered).is_err(),
        "reordered A/B originals accepted",
    )?;
    require(
        key.verify_expected(proof, &originals[..originals.len() - 1])
            .is_err(),
        "omitted original accepted",
    )?;
    let mut duplicated = originals.to_vec();
    duplicated[1] = originals[0].clone();
    require(
        key.verify_expected(proof, &duplicated).is_err(),
        "changed duplicated original accepted",
    )?;
    let mut extra = originals.to_vec();
    extra.push(originals[0].clone());
    require(
        key.verify_expected(proof, &extra).is_err(),
        "extra original accepted",
    )?;
    let mut wrong_context = originals.to_vec();
    wrong_context[0].context[0] ^= 1;
    require(
        key.verify_expected(proof, &wrong_context).is_err(),
        "wrong expected context accepted",
    )?;
    let mut wrong_profile = originals.to_vec();
    wrong_profile[0].profile[0] ^= 1;
    require(
        key.verify_expected(proof, &wrong_profile).is_err(),
        "wrong expected graph profile accepted",
    )?;
    for index in 0..4 {
        let mut alias = originals.to_vec();
        alias[0].digest[index] = lattica_prover_p3::block_v2::commitment::MODULUS;
        require(
            key.verify_expected(proof, &alias).is_err(),
            "noncanonical expected digest accepted",
        )?;
    }
    let mut trailing = postcard::to_allocvec(&(&proof.public, &proof.proof))?;
    trailing.push(0);
    require(
        decode_proof(&trailing).is_err(),
        "trailing artifact bytes accepted",
    )?;
    let report = json!({"all_public_fields_rejected": PUBLIC_VALUES, "opening_mutation_rejected": true,
        "reordered_a_b_rejected": true, "omitted_original_rejected": true,
        "changed_duplicated_original_rejected": true, "extra_original_rejected": true,
        "wrong_context_rejected": true, "wrong_profile_rejected": true,
        "noncanonical_digest_words_rejected": 4, "trailing_artifact_bytes_rejected": true});
    emit_case(case, "negative_results", report.clone());
    Ok(report)
}
struct PreparedCase {
    job: CaseJob,
    plan: BatchPlan,
    originals: Vec<LeafStatement>,
    ordered: Vec<usize>,
    node: BatchNode,
    proving_seconds: f64,
    recursive_witness_checks: Vec<Value>,
    recursive_witness_check_seconds: f64,
    original_bytes: usize,
}
fn prove_case(admission: &Admission, case: u32, graphs: &[Recovered; 2]) -> Result<PreparedCase> {
    let started = Instant::now();
    let job = CaseJob {
        case,
        output: admission.output.join(format!("case-{case}")),
    };
    let ordered: Vec<usize> = serde_json::from_value(
        admission.document["ordered_fixture_indices"][case.to_string()].clone(),
    )?;
    // A distinct Plan registration is constructed for each total. No prepared
    // prover or partial batch key is reused between the two cases.
    let plan = BatchPlan::new(graphs[0].statement.profile, [71; 32], case)?;
    let originals: Vec<_> = ordered
        .iter()
        .map(|&index| graphs[index].statement.clone())
        .collect();
    reject_premerge(case, &plan, graphs)?;
    fs::create_dir(&job.output)?;
    emit_case(
        case,
        "case_begin",
        json!({"ordered_fixture_indices": ordered}),
    );
    let (first, first_checks) = prove_node(
        &job,
        "first-pair",
        [
            graph_child(&plan, 0, &graphs[0])?,
            graph_child(&plan, 1, &graphs[1])?,
        ],
    )?;
    require(
        first_checks.is_empty(),
        "graph-only pair reported recursive witness checks",
    )?;
    first.key().verify(first.proof())?;
    require(
        first
            .key()
            .verify_expected(first.proof(), &originals)
            .is_err(),
        "valid partial pair accepted as complete batch",
    )?;
    emit_case(
        case,
        "partial_coverage",
        json!({"span": first.key().span(),
        "registered_partial_verified": true, "complete_original_coverage_rejected": true}),
    );
    let (node, recursive_witness_checks) = if case == 3 {
        prove_node(
            &job,
            "complete-n3",
            [first.into(), graph_child(&plan, 2, &graphs[0])?],
        )?
    } else {
        let (second, second_checks) = prove_node(
            &job,
            "second-pair",
            [
                graph_child(&plan, 2, &graphs[0])?,
                graph_child(&plan, 3, &graphs[1])?,
            ],
        )?;
        require(
            second_checks.is_empty(),
            "graph-only pair reported recursive witness checks",
        )?;
        require(
            second
                .key()
                .verify_expected(second.proof(), &originals)
                .is_err(),
            "valid final-interval pair accepted as complete batch",
        )?;
        emit_case(
            case,
            "partial_coverage",
            json!({"span": second.key().span(),
            "registered_partial_verified": true, "complete_original_coverage_rejected": true}),
        );
        prove_node(&job, "complete-n4", [first.into(), second.into()])?
    };
    require(
        recursive_witness_checks.len() == (case - 2) as usize,
        "final merge lacks its actual aggregate-child witness checks",
    )?;
    let recursive_witness_check_seconds =
        recursive_witness_checks
            .iter()
            .try_fold(0.0, |sum, check| -> Result<f64> {
                Ok(sum
                    + check["evaluation_seconds"]
                        .as_f64()
                        .ok_or("missing recursive witness evaluation timing")?)
            })?;
    node.key().verify_expected(node.proof(), &originals)?;
    let original_bytes = ordered
        .iter()
        .map(|&index| admission.fixtures[index].statement.len())
        .sum();
    let proving_seconds = started.elapsed().as_secs_f64();
    emit_case(
        case,
        "case_proving_complete",
        json!({"case_proving_seconds": proving_seconds,
        "recursive_witness_check_count": recursive_witness_checks.len(),
        "recursive_witness_check_seconds": recursive_witness_check_seconds,
        "case_proving_seconds_includes_recursive_witness_checks": true,
        "retains_only_compact_batch_key_and_proof": true,
        "final_reverification_after_shared_graph_drop_pending": true}),
    );
    Ok(PreparedCase {
        job,
        plan,
        originals,
        ordered,
        node,
        proving_seconds,
        recursive_witness_checks,
        recursive_witness_check_seconds,
        original_bytes,
    })
}
fn finish_case(prepared: PreparedCase) -> Result<Value> {
    let started = Instant::now();
    let PreparedCase {
        job,
        plan,
        originals,
        ordered,
        node,
        proving_seconds,
        recursive_witness_checks,
        recursive_witness_check_seconds,
        original_bytes,
    } = prepared;
    let case = job.case;
    let root = Child::Batch(node);
    let verification_started = Instant::now();
    plan.verify_expected(&root, &originals)?;
    let single_plan_verification_seconds = verification_started.elapsed().as_secs_f64();
    let Child::Batch(node) = root else {
        return Err("unexpected graph singleton".into());
    };
    node.key().verify_expected(node.proof(), &originals)?;
    let encoded = postcard::to_allocvec(&(&node.proof().public, &node.proof().proof))?;
    let final_hash = hex(&Sha3_256::digest(&encoded));
    let final_path = job
        .output
        .join(format!("complete-n{case}-{final_hash}.postcard"));
    let stored = bounded_read(&final_path, CACHE_LIMIT)?;
    require(stored == encoded, "final stored proof artifact differs")?;
    let decoded = decode_proof(&stored)?;
    node.key().verify_expected(&decoded, &originals)?;
    let negative_results = reject_final(case, node.key(), &decoded, &originals)?;
    let expected_contract: Vec<_> = originals
        .iter()
        .map(|s| (s.profile, s.context, s.digest))
        .collect();
    let expected_bytes = postcard::to_allocvec(&expected_contract)?.len();
    let report = json!({"case": case, "ordered_fixture_indices": ordered,
        "source_fingerprint": SOURCE_FP, "graph_plan_label": GRAPH_PROFILE,
        "batch_source_identity": BATCH_SOURCE,
        "complete_batch_verified": true, "original_children_dropped_before_final_verification": true,
        "original_complete_graph_children_dropped_before_final_verification": true,
        "decoded_complete_payload_reverified": true,
        "actual_merge_count": case - 1, "aggregate_child_count": if case == 3 { 1 } else { 2 },
        "aggregate_plus_graph_verified": case == 3, "aggregate_plus_aggregate_verified": case == 4,
        "canonical_odd_tail_verified": case == 3, "partial_coverage_rejection_verified": true,
        "final_artifact_bytes": encoded.len(), "final_artifact_sha3_256": final_hash,
        "final_artifact_path": final_path, "expected_statement_reference_count": originals.len(),
        "expected_statement_contract_postcard_bytes": expected_bytes,
        "original_relation_statement_bytes_sum": original_bytes,
        "full_public_statements_ring_data_and_ledger_availability_external": true,
        "artifact_size_is_not_transaction_or_block_size": true, "ledger_binding": false,
        "relation_kind": "repeated standalone MatRiCT relations", "negative_results": negative_results,
        "case_proving_seconds": proving_seconds,
    "recursive_witness_checks": recursive_witness_checks,
    "recursive_witness_check_count": recursive_witness_checks.len(),
    "recursive_witness_check_seconds": recursive_witness_check_seconds,
    "recursive_witness_check_scope": "emitted aggregate-child verifier assertion rejection",
    "case_proving_seconds_includes_recursive_witness_checks": true,
    "negative_stark_proofs_generated": 0,
        "case_final_verification_seconds": started.elapsed().as_secs_f64(),
        "single_plan_verification_seconds": single_plan_verification_seconds,
        "single_plan_verification_scope": {
            "method": "Plan::verify_expected", "call_count": 1,
            "cryptographic_verification_calls": 1,
            "includes_expected_ordered_root_computation": true,
            "prebuilt_trusted_key_and_plan": true,
            "precomputed_original_statement_digests": true,
            "proof_already_decoded": true,
            "process_state": "previously exercised; caches not reset",
            "measurement": "wall_clock_seconds", "cpu_seconds_measured": false,
            "cold_start_measured": false, "production_latency_qualified": false
        },
        "isolated_case_rss_measured": false});
    emit("result", report.clone());
    Ok(report)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    require(
        args.len() == 3,
        "usage: accept_recursive_batch ADMISSION_JSON OUTPUT_DIRECTORY both",
    )?;
    require(
        args[2] == "both",
        "both N3/N4 cases must share one graph replay",
    )?;
    let started = Instant::now();
    let admission = Admission::load(Path::new(&args[0]), Path::new(&args[1]))?;
    emit(
        "admitted",
        json!({"cases": [3, 4], "source_fingerprint": SOURCE_FP,
        "graph_plan_label": GRAPH_PROFILE, "batch_source_identity": BATCH_SOURCE,
        "ordered_fixture_indices": admission.document["ordered_fixture_indices"],
        "native_bytes": NATIVE_BUDGET, "outer_bytes": OUTER_BUDGET,
        "relation_kind": "repeated standalone MatRiCT relations", "ledger_binding": false}),
    );
    let pipeline = SpendPipeline::new(
        &admission.cache,
        Budgets {
            native_bytes: NATIVE_BUDGET,
            outer_bytes: OUTER_BUDGET,
            cache_entry_bytes: CACHE_LIMIT,
            crypto_policy: graph_crypto::Policy {
                maximum_aes_blocks: 64,
                maximum_shake_permutations: 32,
                child_memory_budget_bytes: NATIVE_BUDGET,
                admission: graph_crypto::Admission::Estimated,
            },
            transcripts: TranscriptLayout::Serial,
            aes: AesLayout::Serial,
            composites: CompositeLayout::Branches,
        },
    )?;
    // Reconstruct each expensive complete graph key exactly once. These compact
    // keys/proofs can be borrowed by independent N3/N4 plans without retaining
    // their registered LDEs or recompiling the complete graph a second time.
    let graphs = [
        replay(&admission, 0, &pipeline)?,
        replay(&admission, 1, &pipeline)?,
    ];
    drop(pipeline);
    require(
        graphs[0].statement.digest != graphs[1].statement.digest,
        "A/B statement digest collision",
    )?;
    fs::create_dir(&admission.output)?;
    let prepared = [
        prove_case(&admission, 3, &graphs)?,
        prove_case(&admission, 4, &graphs)?,
    ];
    drop(graphs);
    emit(
        "original_graph_children_dropped",
        json!({"actual_complete_graph_children": 2,
        "pending_final_cases": [3, 4], "prepared_proving_state_retained": false}),
    );
    let mut results = Vec::new();
    for case in prepared {
        results.push(finish_case(case)?);
    }
    admission.audit()?;
    emit(
        "run_result",
        json!({"cases": [3, 4], "both_complete_batches_verified": true,
        "actual_complete_graph_replays": 2, "actual_merge_count": 5,
        "recursive_witness_check_count": 3, "negative_stark_proofs_generated": 0,
        "source_fingerprint": SOURCE_FP, "graph_plan_label": GRAPH_PROFILE,
        "batch_source_identity": BATCH_SOURCE, "original_children_dropped_before_final_verification": true,
        "copied_cache_and_fixtures_unchanged": true, "ledger_binding": false,
        "relation_kind": "repeated standalone MatRiCT relations", "case_results": results,
        "isolated_case_rss_measured": false, "seconds": started.elapsed().as_secs_f64()}),
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        emit(
            "error",
            json!({"error": error.to_string(), "complete_batch_verified": false}),
        );
        std::process::exit(1);
    }
}
