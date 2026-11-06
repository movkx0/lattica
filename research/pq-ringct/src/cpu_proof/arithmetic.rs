//! Actual registered arithmetic batches and adjacent graph-leaf slices.
use super::*;
use crate::graph_proofs::{ComponentArtifact, ComponentKind};
use jobs::{Kind, Observation, Output, Spec};
use p3_field::PrimeCharacteristicRing;

pub fn build(options: &Options, cases: &[Arc<inputs::Case>]) -> Result<Vec<Spec>> {
    let mut jobs = Vec::new();
    for case in cases {
        let plan = case.algebra()?;
        let mut frontier = Vec::new();
        for index in options.request
            ..options
                .request
                .checked_add(options.segments)
                .ok_or("slice overflow")?
        {
            let (batch, ordinal) = if options.mode == "arithmetic" {
                (index, None)
            } else {
                let leaf = case
                    .tree
                    .leaves()
                    .get(index)
                    .ok_or("graph leaf outside real graph")?;
                ensure(
                    !leaf.operation_indices().is_empty(),
                    "graph slice requires arithmetic operation leaves",
                )?;
                let batch = plan
                    .batches()
                    .iter()
                    .position(|b| b.operation_indices() == leaf.operation_indices())
                    .ok_or("graph leaf does not match one registered arithmetic batch")?;
                (batch, Some(index))
            };
            let spec = plan
                .batches()
                .get(batch)
                .ok_or("arithmetic batch outside real graph")?;
            ensure(
                !matches!(spec.kind(), ComponentKind::External),
                "external batch requires crypto/source proof",
            )?;
            let estimate = spec
                .resource_estimate()
                .ok_or("arithmetic batch has no estimate")?;
            let native = jobs.len();
            jobs.push(Spec {
                kind: Kind::Arithmetic {
                    case: Arc::clone(case),
                    batch,
                    bytes: estimate.estimated_prover_bytes,
                },
                deps: vec![],
                cost: estimate.estimated_prover_bytes.saturating_mul(2),
            });
            if let Some(ordinal) = ordinal {
                let compile = jobs.len();
                jobs.push(Spec {
                    kind: Kind::GraphLeaf {
                        case: Arc::clone(case),
                        ordinal,
                    },
                    deps: vec![native],
                    cost: 500_000_000,
                });
                frontier.push(jobs.len());
                jobs.push(Spec {
                    kind: Kind::GraphProve,
                    deps: vec![compile],
                    cost: 33_000_000_000,
                });
            }
        }
        if options.mode == "graph-parent" {
            ensure(
                frontier.len() > 1,
                "graph parent requires at least two adjacent leaves",
            )?;
            while frontier.len() > 1 {
                let mut next = Vec::new();
                for pair in frontier.chunks(2) {
                    if pair.len() == 1 {
                        next.push(pair[0]);
                        continue;
                    }
                    let compile = jobs.len();
                    jobs.push(Spec {
                        kind: Kind::GraphMerge,
                        deps: pair.to_vec(),
                        cost: 500_000_000,
                    });
                    next.push(jobs.len());
                    jobs.push(Spec {
                        kind: Kind::GraphProve,
                        deps: vec![compile],
                        cost: 33_000_000_000,
                    });
                }
                frontier = next;
            }
        }
    }
    Ok(jobs)
}

fn parts(
    artifact: &mut ComponentArtifact,
) -> (
    &mut [Val],
    &mut p3_uni_stark::Proof<lattica_prover_p3::block_v2::profile::Config>,
) {
    match artifact {
        ComponentArtifact::Affine(p) => (&mut p.public_values, &mut p.proof),
        ComponentArtifact::Ntt(p) => (&mut p.public_values, &mut p.proof),
        ComponentArtifact::Mul(p) => (&mut p.public_values, &mut p.proof),
        ComponentArtifact::GBound(p) => (&mut p.public_values, &mut p.proof),
        ComponentArtifact::Permutation(p) => (&mut p.public_values, &mut p.proof),
        ComponentArtifact::LinearMap(p) => (&mut p.public_values, &mut p.proof),
    }
}
pub fn prove(
    case: &inputs::Case,
    batch: usize,
    retain: bool,
    context: &crate::execution::ProvingContext,
    report: &mut Observation,
) -> Result<Output> {
    let started = Instant::now();
    let plan = case.algebra()?;
    report.compile_ns = started.elapsed().as_nanos();
    let start = Instant::now();
    let work = || plan.prove_batch(batch).map_err(error);
    let mut artifact = if retain {
        context.with_retained_native_cpu(work)?
    } else {
        context.with_native_cpu(work)?
    };
    // This API includes witness generation and its first verification. The
    // explicit second verification below is reported separately.
    report.proving_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    plan.verify_batch(batch, &artifact).map_err(error)?;
    report.verification_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    parts(&mut artifact).0[0] += Val::ONE;
    ensure(
        plan.verify_batch(batch, &artifact).is_err(),
        "arithmetic public mutation accepted",
    )?;
    parts(&mut artifact).0[0] -= Val::ONE;
    parts(&mut artifact).1.opened_values.trace_local[0] +=
        lattica_prover_p3::block_v2::profile::Challenge::ONE;
    ensure(
        plan.verify_batch(batch, &artifact).is_err(),
        "arithmetic proof mutation accepted",
    )?;
    parts(&mut artifact).1.opened_values.trace_local[0] -=
        lattica_prover_p3::block_v2::profile::Challenge::ONE;
    report.mutation_ns = start.elapsed().as_nanos();
    report.mutation_checks = 2;
    let bytes = postcard::to_allocvec(parts(&mut artifact).1).map_err(error)?;
    ensure(bytes.len() <= 16 << 20, "arithmetic proof output capacity")?;
    report.proof_digest = Some(hex(&sha3::Sha3_256::digest(&bytes)));
    Ok(Output::Arithmetic(artifact))
}

pub fn inventory(case: &inputs::Case) -> Result<Vec<serde_json::Value>> {
    let plan = case.algebra()?;
    Ok(plan.batches().iter().enumerate().map(|(batch,b)| serde_json::json!({
        "batch":batch, "kind":family(b.kind()), "operations":b.operation_indices().len(),
        "height":b.resource_estimate().map(|e|e.height),
        "estimated_prover_bytes":b.resource_estimate().map(|e|e.estimated_prover_bytes),
        "graph_leaf":case.tree.leaves().iter().position(|l| !l.operation_indices().is_empty()
            && l.operation_indices()==b.operation_indices())
    })).collect())
}

fn family(kind: &ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Affine { .. } => "Affine",
        ComponentKind::Ntt { .. } => "Ntt",
        ComponentKind::Mul { .. } => "Mul",
        ComponentKind::GBound { .. } => "GBound",
        ComponentKind::Permutation { .. } => "Permutation",
        ComponentKind::LinearMap { .. } => "LinearMap",
        ComponentKind::External => "External",
    }
}
