use super::*;
use crate::{
    graph_auxiliary::{self, AuxiliaryArtifact, Role},
    graph_proofs, graph_sources,
    graph_tree::{self, AesProof, LeafArtifact, LeafKind, OperationFamily, ShakeProof},
    producer_branch,
    proof_cache_policy::ProofCachePolicy,
};
use std::collections::BTreeMap;
type Roots = Vec<graph_crypto::CompleteRequestProof>;
type Branches = BTreeMap<(usize, u8), producer_branch::ProvenBranch>;
fn missing<T>(value: Option<T>) -> Result<T> {
    value.ok_or("missing native component; run prepare-inputs separately".into())
}
fn request_index(case: &inputs::Case, operation: usize, subrequest: usize) -> Result<usize> {
    case.plan
        .requests()
        .iter()
        .position(|r| r.operation_index() == operation && r.subrequest() as usize == subrequest)
        .ok_or("missing trusted crypto request".into())
}
fn sha(root: &graph_crypto::CompleteRequestProof) -> ShakeProof<'_> {
    ShakeProof::Tree {
        key: &root.key,
        proof: &root.proof,
    }
}
fn aes(root: &graph_crypto::CompleteRequestProof) -> AesProof<'_> {
    AesProof::Tree {
        key: &root.key,
        proof: &root.proof,
    }
}
fn branch(value: &producer_branch::ProvenBranch) -> producer_branch::Artifact<'_> {
    producer_branch::Artifact {
        key: &value.key,
        proof: &value.proof,
    }
}
pub(super) enum Loaded {
    Fixed,
    Equality,
    Statement(crate::statement_air::bundle::StatementProof),
    Private(crate::proof_air::join::ProofArtifact),
    Algebra(graph_proofs::ComponentArtifact),
    Parameters(usize),
    Sample(usize, AuxiliaryArtifact),
    Alpha(usize),
    HashAlpha(usize, AuxiliaryArtifact),
    HashX(usize, AuxiliaryArtifact),
}
impl Loaded {
    pub(super) fn artifact<'a>(
        &'a self,
        roots: &'a Roots,
        branches: &'a Branches,
    ) -> Result<LeafArtifact<'a>> {
        Ok(match self {
            Self::Fixed => LeafArtifact::FixedSources,
            Self::Equality => LeafArtifact::Equality,
            Self::Statement(p) => LeafArtifact::Statement(p),
            Self::Private(p) => LeafArtifact::PrivateProof(p),
            Self::Algebra(p) => p.as_leaf_artifact(),
            Self::Parameters(i) => LeafArtifact::ParametersPp(sha(&roots[*i])),
            Self::Sample(i, p) => LeafArtifact::SampleG {
                aes: aes(&roots[*i]),
                sampler: p.uniform().map_err(error)?,
            },
            Self::Alpha(op) => LeafArtifact::ExpandAlphaBranches {
                uniform: branch(branches.get(&(*op, 0)).ok_or("missing uniform branch")?),
                sparse: branch(branches.get(&(*op, 1)).ok_or("missing sparse branch")?),
            },
            Self::HashAlpha(i, p) => LeafArtifact::HashAlpha {
                shake: sha(&roots[*i]),
                transcript: p.transcript().map_err(error)?,
            },
            Self::HashX(op, p) => LeafArtifact::HashXBranch {
                branch: branch(branches.get(&(*op, 2)).ok_or("missing HashX branch")?),
                sampler: p.sparse().map_err(error)?,
            },
        })
    }
}
pub(super) fn load_leaf(
    case: &inputs::Case,
    index: usize,
    caches: &bundle::Caches,
    sources: &graph_sources::SourceFactory<'_>,
    auxiliary: &graph_auxiliary::AuxiliaryFactory,
    algebra: &graph_proofs::GraphProofPlan<'_>,
) -> Result<Loaded> {
    let leaf = &case.tree.leaves()[index];
    let op = || {
        leaf.operation_indices()
            .first()
            .copied()
            .ok_or("empty operation leaf")
    };
    let aux = |operation, role| {
        missing(
            caches
                .auxiliary
                .load(auxiliary.request(operation, role).map_err(error)?)
                .map_err(error)?,
        )
    };
    Ok(match leaf.kind() {
        LeafKind::FixedSources => Loaded::Fixed,
        LeafKind::Statement => Loaded::Statement(missing(
            sources.load_statement(&caches.sources).map_err(error)?,
        )?),
        LeafKind::PrivateProof => Loaded::Private(missing(
            sources.load_private(&caches.sources).map_err(error)?,
        )?),
        LeafKind::Operations(family) => match family {
            OperationFamily::Equality => Loaded::Equality,
            OperationFamily::ParametersPp => Loaded::Parameters(request_index(case, op()?, 0)?),
            OperationFamily::SampleG => Loaded::Sample(
                request_index(case, op()?, 0)?,
                aux(op()?, Role::SampleGUniform)?,
            ),
            OperationFamily::ExpandAlpha => Loaded::Alpha(op()?),
            OperationFamily::HashAlpha => Loaded::HashAlpha(
                request_index(case, op()?, 0)?,
                aux(op()?, Role::HashAlphaTranscript)?,
            ),
            OperationFamily::HashX => Loaded::HashX(op()?, aux(op()?, Role::HashXSparse)?),
            _ => {
                let batch = algebra
                    .batches()
                    .iter()
                    .position(|b| b.operation_indices() == leaf.operation_indices())
                    .ok_or("unregistered algebra leaf")?;
                Loaded::Algebra(missing(
                    caches.algebra.load(algebra, batch).map_err(error)?,
                )?)
            }
        },
    })
}
fn validate_native(
    cases: &[Arc<inputs::Case>],
    caches: &bundle::Caches,
    deadline: &Deadline,
) -> Result<usize> {
    let mut total = 0;
    for case in cases {
        let sources = graph_sources::SourceFactory::new(
            &case.tree,
            &case.graph,
            &case.context,
            &case.statement,
            &case.private_proof,
            24 << 30,
        )
        .map_err(error)?;
        let aux = graph_auxiliary::AuxiliaryFactory::new(
            &case.tree,
            &case.graph,
            &case.context,
            24 << 30,
        )
        .map_err(error)?;
        let algebra = case.algebra()?;
        missing(sources.load_statement(&caches.sources).map_err(error)?)?;
        total += 1;
        missing(sources.load_private(&caches.sources).map_err(error)?)?;
        total += 1;
        for (i, batch) in algebra.batches().iter().enumerate() {
            if batch.resource_estimate().is_some() {
                deadline.check()?;
                missing(caches.algebra.load(&algebra, i).map_err(error)?)?;
                total += 1;
            }
        }
        for request in aux.requests() {
            deadline.check()?;
            missing(caches.auxiliary.load(request).map_err(error)?)?;
            total += 1;
        }
        for request in case.plan.requests() {
            for index in 0..request.segments().len() {
                deadline.check()?;
                missing(caches.crypto.load(request, index).map_err(error)?)?;
                total += 1;
            }
        }
    }
    Ok(total)
}
pub(crate) fn plan(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    let (cases, digest) = inputs::load(options)?;
    let (shake_width, graph_width) = selection::widths(options)?;
    let mut rows = Vec::new();
    let mut native = 0;
    let mut outer = 0;
    for (transaction, case) in cases.iter().enumerate() {
        deadline.check()?;
        for (index, request) in case.plan.requests().iter().enumerate() {
            let spans =
                graph_crypto::imported_group_spans(request, shake_width, options.max_rows())
                    .map_err(error)?;
            let leaves = if spans.is_empty() {
                request.segments().len()
            } else {
                spans.len()
            };
            native += request.segments().len();
            outer += 2 * leaves - 1;
            rows.push(serde_json::json!({"transaction":transaction,"request":index,"native":request.segments().len(),"outer":2*leaves-1,"maximum_group":spans.iter().map(|s|s.segment_count).max().unwrap_or(1)}));
        }
        let leaves = case.tree.leaves().len().div_ceil(graph_width);
        outer += 2 * leaves - 1;
    }
    Ok(
        serde_json::json!({"scope":"descriptor-planning","input_sha3":digest,"source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),
        "crypto_native_instances":native,"planned_outer_without_auxiliary_branches":outer+options.transactions-1,
        "shake_width":shake_width,"graph_width":graph_width,"requests":rows,
            "leaf_catalog":cases[0].tree.leaves().iter().enumerate().map(|(i,l)|serde_json::json!({"first":i,"kind":format!("{:?}",l.kind()),"operations":l.operation_indices()})).collect::<Vec<_>>(),"graph_height_admission_complete":false,"proofs_generated":0}),
    )
}
fn branches(
    case: &inputs::Case,
    roots: &Roots,
    caches: &bundle::Caches,
    execution: &crate::execution::ProvingContext,
    outer: &graph_crypto::OuterProofCache,
    deadline: &Deadline,
) -> Result<Branches> {
    let factory =
        producer_branch::Factory::new(&case.tree, &case.graph, &case.context).map_err(error)?;
    let auxiliary =
        graph_auxiliary::AuxiliaryFactory::new(&case.tree, &case.graph, &case.context, 24 << 30)
            .map_err(error)?;
    let load = |op, role| {
        missing(
            caches
                .auxiliary
                .load(auxiliary.request(op, role).map_err(error)?)
                .map_err(error)?,
        )
    };
    let mut output = Branches::new();
    let mut prove = |op, role, compiled: producer_branch::CompiledNode| -> Result<()> {
        deadline.check()?;
        execution.release_prepared()?;
        ensure(
            compiled.geometry().map_err(error)?.padded_rows <= execution.aggregation_row_limit(),
            "branch exceeds recursive row ceiling",
        )?;
        let proof = compiled
            .prove_imported_with_context(execution, outer)
            .map_err(error)?;
        output.insert((op, role), proof);
        Ok(())
    };
    for leaf in case.tree.leaves() {
        let Some(&op) = leaf.operation_indices().first() else {
            continue;
        };
        match leaf.kind() {
            LeafKind::Operations(OperationFamily::ExpandAlpha) => {
                let u = &roots[request_index(case, op, 0)?];
                let s = &roots[request_index(case, op, 1)?];
                let uniform = load(op, Role::AlphaUniform)?;
                let sparse = load(op, Role::AlphaSparse)?;
                prove(
                    op,
                    0,
                    factory
                        .compile_alpha_uniform(
                            op,
                            &u.key,
                            &u.proof,
                            uniform.uniform().map_err(error)?,
                        )
                        .map_err(error)?,
                )?;
                prove(
                    op,
                    1,
                    factory
                        .compile_alpha_sparse(op, &s.key, &s.proof, sparse.sparse().map_err(error)?)
                        .map_err(error)?,
                )?;
            }
            LeafKind::Operations(OperationFamily::HashX) => {
                let root = &roots[request_index(case, op, 0)?];
                let transcript = load(op, Role::HashXTranscript)?;
                prove(
                    op,
                    2,
                    factory
                        .compile_hash_x(
                            op,
                            &root.key,
                            &root.proof,
                            transcript.transcript().map_err(error)?,
                        )
                        .map_err(error)?,
                )?;
            }
            _ => (),
        }
    }
    Ok(output)
}
fn prove_graph(
    case: &inputs::Case,
    roots: &Roots,
    branches: &Branches,
    caches: &bundle::Caches,
    execution: &crate::execution::ProvingContext,
    outer: &graph_crypto::OuterProofCache,
    options: &Options,
    width: usize,
    deadline: &Deadline,
) -> Result<(graph_tree::ProvenNode, Vec<serde_json::Value>)> {
    let sources = graph_sources::SourceFactory::new(
        &case.tree,
        &case.graph,
        &case.context,
        &case.statement,
        &case.private_proof,
        24 << 30,
    )
    .map_err(error)?;
    let auxiliary =
        graph_auxiliary::AuxiliaryFactory::new(&case.tree, &case.graph, &case.context, 24 << 30)
            .map_err(error)?;
    let algebra = case.algebra()?;
    execution.release_prepared()?;
    let groups = if width == 1 {
        (0..case.tree.leaves().len())
            .map(|i| (i, 1))
            .collect::<Vec<_>>()
    } else {
        // A source-only pass freezes legal heterogeneous contractions before
        // graph proving starts. No failed proof triggers regrouping or retry.
        let mut facts = Vec::new();
        pipeline::ordered(
            case.tree.leaves().len(),
            options.parallel,
            |index| {
                deadline.check()?;
                let leaf = load_leaf(case, index, caches, &sources, &auxiliary, &algebra)?;
                let compiled = graph_tree::compile_group_bounded(
                    &case.tree,
                    &case.graph,
                    index,
                    &case.context,
                    vec![leaf.artifact(roots, branches)?],
                    construction(),
                )
                .map_err(error)?;
                Ok(layout::Facts {
                    rows: compiled.geometry().map_err(error)?.padded_rows,
                    program_bytes: compiled.program().construction_host_bytes(),
                })
            },
            |_, fact| {
                facts.push(fact);
                Ok(())
            },
        )?;
        layout::partition_bounded(
            &facts,
            &selection::graph_costs(options, width)?,
            options.max_rows(),
            if options.profile == "grouped-v3" {
                2
            } else {
                1
            },
        )?
    };
    let count = groups.len();
    let prover = graph_tree::GraphProver::new_with_context(
        &case.tree,
        &case.context,
        outer,
        execution.host_bytes(),
        execution,
    )
    .map_err(error)?;
    let prepare = |index| {
        deadline.check()?;
        let start = Instant::now();
        let (first, count) = groups[index];
        let end = first + count;
        let leaves = (first..end)
            .map(|i| load_leaf(case, i, caches, &sources, &auxiliary, &algebra))
            .collect::<Result<Vec<_>>>()?;
        let artifacts = leaves
            .iter()
            .map(|leaf| leaf.artifact(roots, branches))
            .collect::<Result<Vec<_>>>()?;
        let compiled = graph_tree::compile_group_bounded(
            &case.tree,
            &case.graph,
            first,
            &case.context,
            artifacts,
            construction(),
        )
        .map_err(error)?;
        let geometry = compiled.geometry().map_err(error)?;
        ensure(
            geometry.padded_rows <= options.max_rows()
                && compiled.program().construction_host_bytes() <= 2 << 30,
            "graph grouping exceeds admitted height/compiler ceiling",
        )?;
        Ok((first, end - first, compiled, start.elapsed().as_nanos()))
    };
    if execution.consuming_aggregation() {
        let rows = std::sync::Mutex::new(Vec::new());
        let root = prover.prove_imported_tree(count, |i| {
            let (first, count, compiled, compile_ns) = prepare(i)?;
            let geometry = compiled.geometry().map_err(error)?;
            rows.lock().map_err(|_| "graph compiler telemetry poisoned")?.push(
                serde_json::json!({"first":first,"count":count,"compile_ns":compile_ns,"padded_rows":geometry.padded_rows}));
            Ok(compiled)
        }, deadline).map_err(error)?;
        root.verify_complete(&case.context).map_err(error)?;
        let mut rows = rows.into_inner().map_err(|_| "graph telemetry poisoned")?;
        rows.sort_by_key(|row| row["first"].as_u64());
        return Ok((root, rows));
    }
    let mut nodes = Vec::new();
    let mut rows = Vec::new();
    pipeline::programs(
        count,
        options.parallel,
        options.identity == "gpu-batched",
        execution,
        prepare,
        |(_, _, node, _)| node.shared_program(),
        |cohort| {
            for (_, (first, count, compiled, compile_ns)) in cohort {
                deadline.check()?;
                let geometry = compiled.geometry().map_err(error)?;
                let started = Instant::now();
                let node = prover.prove_imported_node(compiled).map_err(error)?;
                rows.push(serde_json::json!({"first":first,"count":count,"compile_ns":compile_ns,"proof_seconds":started.elapsed().as_secs_f64(),"padded_rows":geometry.padded_rows}));
                nodes.push(node);
            }
            Ok(())
        },
    )?;
    deadline.check()?;
    let root = prover
        .aggregate_imported(
            nodes,
            options.parallel,
            options.identity == "gpu-batched",
            deadline,
        )
        .map_err(error)?;
    root.verify_complete(&case.context).map_err(error)?;
    Ok((root, rows))
}
pub(crate) fn run(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    bundle::validate(options, true)?;
    let (cases, input_sha3) = inputs::load(options)?;
    let caches = bundle::Caches::new(&options.bundle, false)?;
    let native_count = validate_native(&cases, &caches, deadline)?;
    let (shake_width, graph_width) = selection::widths(options)?;
    let selection_sha3 = options
        .selection
        .as_ref()
        .map(|path| {
            std::fs::read(path)
                .map(|bytes| hex(&Sha3_256::digest(bytes)))
                .map_err(error)
        })
        .transpose()?;
    let layouts = cases
        .iter()
        .map(|case| {
            case.plan
                .requests()
                .iter()
                .map(|request| {
                    graph_crypto::imported_group_spans(request, shake_width, options.max_rows())
                        .map_err(error)
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let import_seconds = deadline.seconds();
    let execution = context(options)?;
    let control = crate::proof_cache_policy::Control::new(ProofCachePolicy::FreshOnly);
    let outer = graph_crypto::OuterProofCache::fresh_without_storage(&control);
    let mut artifact = None;
    let outcome: Result<serde_json::Value> = (|| {
        let mut graphs = Vec::new();
        let mut reports = Vec::new();
        let mut recursive_proofs = 0;
        for (index, case) in cases.iter().enumerate() {
            let requests = graph_crypto::RequestProver::new_with_context(
                &caches.crypto,
                &outer,
                execution.host_bytes(),
                &execution,
            )
            .map_err(error)?;
            let mut roots = Vec::new();
            for (request, spans) in case.plan.requests().iter().zip(&layouts[index]) {
                deadline.check()?;
                let start = Instant::now();
                let proof = requests
                    .prove_imported(
                        request,
                        &case.context,
                        spans,
                        options.parallel,
                        options.identity == "gpu-batched",
                        deadline,
                    )
                    .map_err(error)?;
                recursive_proofs += proof.report.outer_leaves + proof.report.outer_parents;
                reports.push(serde_json::json!({"transaction":index,"family":"crypto","seconds":start.elapsed().as_secs_f64(),"native_imports":proof.report.native_cache_hits,"outer_leaves":proof.report.outer_leaves,"outer_parents":proof.report.outer_parents}));
                roots.push(proof);
            }
            let branch_roots = branches(case, &roots, &caches, &execution, &outer, deadline)?;
            recursive_proofs += branch_roots.len();
            let (root, rows) = prove_graph(
                case,
                &roots,
                &branch_roots,
                &caches,
                &execution,
                &outer,
                options,
                graph_width,
                deadline,
            )?;
            recursive_proofs += 2 * rows.len() - 1;
            reports.push(serde_json::json!({"transaction":index,"family":"graph","leaves":rows}));
            graphs.push(root);
        }
        deadline.check()?;
        let plan = crate::ordered_aggregation::Plan::new(
            cases[0].tree.label(),
            cases[0].context.context,
            options.transactions as u32,
        )
        .map_err(error)?;
        let statements = cases
            .iter()
            .map(|case| {
                crate::recursive_aggregation::LeafStatement::from_bytes(
                    case.tree.label(),
                    case.context.context,
                    &case.statement,
                )
                .map_err(error)
            })
            .collect::<Result<Vec<_>>>()?;
        let children = graphs
            .iter()
            .zip(&cases)
            .enumerate()
            .map(|(i, (node, case))| {
                plan.graph_child(i as u32, node.key(), node.proof(), &case.context)
                    .map(Into::into)
                    .map_err(error)
            })
            .collect::<Result<Vec<_>>>()?;
        let (root, final_rows) =
            crate::ordered_aggregation::opencl::aggregate_imported_with_context(
                &execution,
                &plan,
                children,
                &statements,
            )
            .map_err(error)?;
        recursive_proofs += final_rows.len();
        let crate::ordered_aggregation::Child::Batch(root) = root else {
            return Err("missing final aggregate".into());
        };
        let started = Instant::now();
        root.key()
            .verify_expected(root.proof(), &statements)
            .map_err(error)?;
        let encoded = postcard::to_allocvec(&(root.proof().public.as_slice(), &root.proof().proof))
            .map_err(error)?;
        ensure(
            encoded.len() <= 16 << 20,
            "final aggregate artifact ceiling",
        )?;
        let (public, proof): (
            Vec<Val>,
            p3_batch_stark::BatchProof<lattica_prover_p3::block_v2::profile::Config>,
        ) = postcard::from_bytes(&encoded).map_err(error)?;
        let mut decoded = crate::ordered_aggregation::BatchProof {
            public: public.try_into().map_err(|_| "aggregate public width")?,
            proof,
        };
        root.key()
            .verify_expected(&decoded, &statements)
            .map_err(error)?;
        use p3_field::PrimeCharacteristicRing;
        decoded.public[0] += Val::ONE;
        ensure(
            root.key().verify_expected(&decoded, &statements).is_err(),
            "mutated aggregate public accepted",
        )?;
        decoded.public[0] -= Val::ONE;
        root.key()
            .verify_expected(&decoded, &statements)
            .map_err(error)?;
        decoded.proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
        ensure(
            root.key().verify_expected(&decoded, &statements).is_err(),
            "mutated aggregate proof accepted",
        )?;
        let mut wrong_order = statements.clone();
        wrong_order.swap(0, 1);
        ensure(
            root.key()
                .verify_expected(root.proof(), &wrong_order)
                .is_err(),
            "reordered statements accepted",
        )?;
        ensure(
            root.key()
                .verify_expected(root.proof(), &statements[..statements.len() - 1])
                .is_err(),
            "missing statement accepted",
        )?;
        let final_verification_seconds = started.elapsed().as_secs_f64();
        let artifact_sha3 = hex(&Sha3_256::digest(&encoded));
        artifact = Some(encoded);
        Ok(
            serde_json::json!({"scope":"aggregation-from-native-components","complete":true,"input_sha3":input_sha3,
"source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"selection_sha3":selection_sha3,"native_proofs_created":0,"native_components_verified":native_count,
            "recursive_proofs":recursive_proofs,"import_and_planning_seconds":import_seconds,"stages":reports,"final":final_rows,
            "final_cpu_verified":true,"artifact_round_trip":true,"public_mutation_rejected":true,"final_verification_seconds":final_verification_seconds,
            "artifact_sha3":artifact_sha3,"proof_mutation_rejected":true,"order_mutation_rejected":true,"identity":execution.aggregation_identity_report()?}),
        )
    })();
    let cleanup = match &outcome {
        Ok(_) => execution.finish(),
        Err(_) => execution.close_without_completion(),
    }?;
    let mut report = outcome?;
    deadline.check()?;
    report["session"] = cleanup;
    report["aggregation_seconds"] = serde_json::json!(deadline.seconds());
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&options.output)
        .map_err(error)?;
    let publication = (|| -> Result<()> {
        file.write_all(&artifact.ok_or("missing final artifact")?)
            .map_err(error)?;
        file.sync_all().map_err(error)?;
        deadline.check()?;
        Ok(())
    })();
    if let Err(reason) = publication {
        drop(file);
        let _ = std::fs::remove_file(&options.output);
        return Err(reason);
    }
    report["aggregation_seconds"] = serde_json::json!(deadline.seconds());
    report["under_ten_minutes"] = serde_json::json!(deadline.seconds() < 600.0);
    Ok(report)
}
pub(crate) fn screen(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    bundle::validate(options, false)?;
    let (cases, input_sha3) = inputs::load(options)?;
    let case = &cases[0];
    let index = options
        .request
        .ok_or("screen requires a SHAKE request index")?;
    let request = case
        .plan
        .requests()
        .get(index)
        .ok_or("request index outside case")?;
    ensure(
        matches!(
            request.descriptor(),
            graph_crypto::RequestDescriptor::Shake(_)
        ),
        "screen requires SHAKE request",
    )?;
    let spans =
        graph_crypto::imported_group_spans(request, options.group_width, options.max_rows())
            .map_err(error)?;
    let caches = bundle::Caches::new(&options.bundle, false)?;
    for i in 0..request.segments().len() {
        deadline.check()?;
        missing(caches.crypto.load(request, i).map_err(error)?)?;
    }
    let execution = context(options)?;
    let control = crate::proof_cache_policy::Control::new(ProofCachePolicy::FreshOnly);
    let outer = graph_crypto::OuterProofCache::fresh_without_storage(&control);
    let outcome: Result<serde_json::Value> = (|| {
        let prover = graph_crypto::RequestProver::new_with_context(
            &caches.crypto,
            &outer,
            execution.host_bytes(),
            &execution,
        )
        .map_err(error)?;
        let mut samples = Vec::new();
        let mut recursive_proofs = 0;
        for repetition in 0..options.repetitions {
            deadline.check()?;
            let start = Instant::now();
            let root = prover
                .prove_imported(
                    request,
                    &case.context,
                    &spans,
                    options.parallel,
                    options.identity == "gpu-batched",
                    deadline,
                )
                .map_err(error)?;
            recursive_proofs = root.report.outer_leaves + root.report.outer_parents;
            samples.push(serde_json::json!({"repetition":repetition,"process_state":if repetition==0 {"first-request"}else{"warm-request"},
                "seconds":start.elapsed().as_secs_f64(),"recursive_proofs":recursive_proofs,"verified":true}));
            eprintln!("GPU_AGGREGATION_SAMPLE {}", samples.last().unwrap());
            execution.release_prepared()?;
        }
        Ok(
            serde_json::json!({"scope":"complete-shake-request-screen","complete_aggregation":false,"request":index,"native_components":request.segments().len(),
            "width":options.group_width,"admitted_maximum_group":spans.iter().map(|s|s.segment_count).max().unwrap_or(1),"recursive_proofs":recursive_proofs,"samples":samples,
            "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"input_sha3":input_sha3,
            "verified":true,"identity":execution.aggregation_identity_report()?}),
        )
    })();
    let cleanup = match &outcome {
        Ok(_) => execution.finish(),
        Err(_) => execution.close_without_completion(),
    }?;
    let mut report = outcome?;
    report["session"] = cleanup;
    Ok(report)
}
