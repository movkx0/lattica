use super::*;
use crate::execution::ProvingContext;
use p3_field::PrimeCharacteristicRing;

pub enum Kind {
    Arithmetic {
        case: Arc<inputs::Case>,
        batch: usize,
        bytes: u64,
    },
    GraphLeaf {
        case: Arc<inputs::Case>,
        ordinal: usize,
    },
    GraphMerge,
    GraphProve,
    Native {
        case: Arc<inputs::Case>,
        request: usize,
        segment: usize,
    },
    Group {
        case: Arc<inputs::Case>,
        request: usize,
        first: usize,
    },
    Merge,
    Prove,
    #[cfg(test)]
    Probe {
        panic: bool,
        tag: Option<[u8; 32]>,
        completed: Arc<std::sync::atomic::AtomicUsize>,
        thread_exit: bool,
    },
}
pub struct Spec {
    pub kind: Kind,
    pub deps: Vec<usize>,
    pub cost: u64,
}
pub enum Output {
    Arithmetic(crate::graph_proofs::ComponentArtifact),
    GraphCompiled(crate::graph_tree::CompiledNode, u64, [u8; 32]),
    GraphProven(crate::graph_tree::NodeKey, crate::graph_tree::NodeProof),
    Native(graph_crypto::SegmentArtifact),
    Compiled(component_tree::CompiledNode, u64, [u8; 32]),
    Proven(component_tree::NodeKey, component_tree::NodeProof),
    #[cfg(test)]
    Probe,
}
impl Output {
    pub fn compiled_output_bytes(&self) -> Result<Option<u64>> {
        match self {
            Self::Compiled(node, ..) => node.cpu_output_bytes().map(Some).map_err(error),
            Self::GraphCompiled(node, ..) => node.cpu_output_bytes().map(Some).map_err(error),
            _ => Ok(None),
        }
    }
}
pub struct Task {
    pub id: usize,
    pub kind: Kind,
    pub inputs: Vec<Output>,
    pub retain_native: bool,
}
#[derive(Default, serde::Serialize)]
pub struct Observation {
    pub id: usize,
    pub kind: &'static str,
    pub elapsed_ns: u128,
    pub compile_ns: u128,
    pub witness_ns: u128,
    pub registration_ns: u128,
    pub proving_ns: u128,
    pub verification_ns: u128,
    pub mutation_ns: u128,
    pub mutation_checks: usize,
    pub proof_digest: Option<String>,
    pub prepared_hit: bool,
}
pub fn build(options: &Options, cases: &[Arc<inputs::Case>]) -> Result<Vec<Spec>> {
    if options.mode == "native-mix" {
        return native_mix(options, cases);
    }
    if matches!(
        options.mode.as_str(),
        "arithmetic" | "graph-leaf" | "graph-parent"
    ) {
        return super::arithmetic::build(options, cases);
    }
    let mut jobs = Vec::new();
    for case in cases {
        let request = case
            .plan
            .requests()
            .get(options.request)
            .ok_or("request outside real graph")?;
        let count = options.segments.min(request.segments().len());
        let mut native = Vec::new();
        for segment in 0..count {
            native.push(jobs.len());
            jobs.push(Spec {
                kind: Kind::Native {
                    case: Arc::clone(case),
                    request: options.request,
                    segment,
                },
                deps: vec![],
                cost: request.segments()[segment]
                    .estimated_peak_bytes
                    .saturating_mul(2),
            });
        }
        if options.mode == "native" {
            continue;
        }
        let groups = request
            .shake_wrapper_schedule(graph_crypto::ShakeWrapperLayout::PairedV1)
            .map_err(error)?;
        let mut frontier = Vec::new();
        let mut covered = 0;
        for span in groups
            .groups()
            .take_while(|s| s.first_segment + s.segment_count <= count)
        {
            let compile = jobs.len();
            jobs.push(Spec {
                kind: Kind::Group {
                    case: Arc::clone(case),
                    request: options.request,
                    first: span.first_segment,
                },
                deps: native[span.first_segment..span.first_segment + span.segment_count].to_vec(),
                cost: 500_000_000,
            });
            frontier.push(jobs.len());
            jobs.push(Spec {
                kind: Kind::Prove,
                deps: vec![compile],
                cost: 33_000_000_000,
            });
            covered += span.segment_count;
        }
        ensure(
            covered == count,
            "slice ends inside a canonical paired group",
        )?;
        if options.mode == "merge" {
            while frontier.len() > 1 {
                let mut next = Vec::new();
                for pair in frontier.chunks(2) {
                    if pair.len() == 1 {
                        next.push(pair[0]);
                        continue;
                    }
                    let compile = jobs.len();
                    jobs.push(Spec {
                        kind: Kind::Merge,
                        deps: pair.to_vec(),
                        cost: 500_000_000,
                    });
                    next.push(jobs.len());
                    jobs.push(Spec {
                        kind: Kind::Prove,
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

/// One actual batch from every arithmetic family and the first real PP,
/// HashAlpha, and AES children. This is a representative slice, not a weighted
/// model of the complete workflow's much larger transcript coverage.
fn native_mix(options: &Options, cases: &[Arc<inputs::Case>]) -> Result<Vec<Spec>> {
    ensure(
        options.request == 0 && options.segments == 1,
        "native-mix has fixed selection: request 0, segments 1",
    )?;
    let mut jobs = Vec::new();
    for case in cases {
        let plan = case.algebra()?;
        let mut families = std::collections::HashSet::new();
        for (batch, b) in plan.batches().iter().enumerate() {
            if matches!(b.kind(), crate::graph_proofs::ComponentKind::External)
                || !families.insert(std::mem::discriminant(b.kind()))
            {
                continue;
            }
            let estimate = b.resource_estimate().ok_or("missing arithmetic estimate")?;
            jobs.push(Spec {
                kind: Kind::Arithmetic {
                    case: Arc::clone(case),
                    batch,
                    bytes: estimate.estimated_prover_bytes,
                },
                deps: vec![],
                cost: estimate.estimated_prover_bytes.saturating_mul(2),
            });
        }
        ensure(
            families.len() == 6,
            "native-mix requires all six real arithmetic families",
        )?;
        for request in [0, 1, 2] {
            let r = case
                .plan
                .requests()
                .get(request)
                .ok_or("native-mix request absent")?;
            ensure(
                matches!(r.descriptor(), graph_crypto::RequestDescriptor::Shake(_))
                    == (request < 2),
                "native-mix crypto inventory changed",
            )?;
            let segment = r.segments().first().ok_or("empty native-mix request")?;
            jobs.push(Spec {
                kind: Kind::Native {
                    case: Arc::clone(case),
                    request,
                    segment: 0,
                },
                deps: vec![],
                cost: segment.estimated_peak_bytes.saturating_mul(2),
            });
        }
    }
    Ok(jobs)
}
impl Spec {
    pub fn admission(&self, outputs: &[Option<Output>]) -> Result<(u64, u64, Option<[u8; 32]>)> {
        match &self.kind {
            Kind::Arithmetic { bytes, .. } => Ok((*bytes, 32 << 20, None)),
            Kind::GraphLeaf { .. } | Kind::GraphMerge => {
                Ok((4 << 30, (2 << 30) + (32 << 20), None))
            }
            Kind::GraphProve => match outputs[self.deps[0]]
                .as_ref()
                .ok_or("missing compiled graph predecessor")?
            {
                Output::GraphCompiled(_, bytes, identity) => {
                    Ok((*bytes, 32 << 20, Some(*identity)))
                }
                _ => Err("CPU graph prove predecessor type".into()),
            },
            #[cfg(test)]
            Kind::Probe { tag, .. } => Ok((1 << 20, 1 << 20, *tag)),
            Kind::Native {
                case,
                request,
                segment,
            } => {
                // Existing native estimate accounts for the CPU trace and its
                // expanded prover matrices; process limits remain mandatory.
                let info = &case.plan.requests()[*request].segments()[*segment];
                Ok((info.estimated_peak_bytes, 32 << 20, None))
            }
            Kind::Group { .. } | Kind::Merge => Ok((4 << 30, (2 << 30) + (32 << 20), None)),
            Kind::Prove => match outputs[self.deps[0]]
                .as_ref()
                .ok_or("missing compiled predecessor")?
            {
                Output::Compiled(_, bytes, identity) => Ok((*bytes, 32 << 20, Some(*identity))),
                _ => Err("CPU prove predecessor type".into()),
            },
        }
    }
}
pub fn execute(
    task: Task,
    context: &ProvingContext,
    prior_identity: Option<[u8; 32]>,
) -> Result<(Output, Observation, Option<[u8; 32]>)> {
    let started = Instant::now();
    let mut report = Observation {
        id: task.id,
        ..Default::default()
    };
    let mut cache = prior_identity;
    let output = match task.kind {
        Kind::Arithmetic { case, batch, .. } => {
            report.kind = "arithmetic";
            if !task.retain_native {
                cache = None;
            }
            super::arithmetic::prove(&case, batch, task.retain_native, context, &mut report)?
        }
        Kind::GraphLeaf { case, ordinal } => {
            report.kind = "graph_compile";
            let Some(Output::Arithmetic(artifact)) = task.inputs.into_iter().next() else {
                return Err("graph leaf predecessor type".into());
            };
            let node = crate::graph_tree::compile_leaf(
                &case.tree,
                &case.graph,
                ordinal,
                &case.context,
                artifact.as_leaf_artifact(),
            )
            .map_err(error)?;
            let bytes = node.cpu_admission_bytes().map_err(error)?;
            let identity = node.cpu_identity().map_err(error)?;
            report.compile_ns = started.elapsed().as_nanos();
            Output::GraphCompiled(node, bytes, identity)
        }
        Kind::GraphMerge => {
            report.kind = "graph_parent_compile";
            let mut children = task.inputs.into_iter();
            let Some(Output::GraphProven(left, lp)) = children.next() else {
                return Err("left graph parent predecessor".into());
            };
            let Some(Output::GraphProven(right, rp)) = children.next() else {
                return Err("right graph parent predecessor".into());
            };
            let node =
                crate::graph_tree::compile_merge(&left, &right, [&lp, &rp]).map_err(error)?;
            let bytes = node.cpu_admission_bytes().map_err(error)?;
            let identity = node.cpu_identity().map_err(error)?;
            report.compile_ns = started.elapsed().as_nanos();
            Output::GraphCompiled(node, bytes, identity)
        }
        Kind::GraphProve => {
            report.kind = "graph_proof";
            let Some(Output::GraphCompiled(node, _, identity)) = task.inputs.into_iter().next()
            else {
                return Err("graph proof predecessor".into());
            };
            report.prepared_hit = prior_identity == Some(identity);
            let (key, mut proof, times) = node.prove_cpu(context).map_err(error)?;
            report.registration_ns = times.registration_ns;
            report.proving_ns = times.proving_ns;
            report.verification_ns = times.verification_ns;
            let mutation = Instant::now();
            proof.public[0] += Val::ONE;
            ensure(
                key.verify(&proof).is_err(),
                "graph public mutation accepted",
            )?;
            proof.public[0] -= Val::ONE;
            proof.proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
            ensure(key.verify(&proof).is_err(), "graph proof mutation accepted")?;
            proof.proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] -= lattica_prover_p3::block_v2::profile::Challenge::ONE;
            report.mutation_ns = mutation.elapsed().as_nanos();
            report.mutation_checks = 2;
            let bytes = postcard::to_allocvec(&proof.proof).map_err(error)?;
            ensure(bytes.len() <= 16 << 20, "graph proof output capacity")?;
            report.proof_digest = Some(hex(&sha3::Sha3_256::digest(&bytes)));
            cache = Some(identity);
            Output::GraphProven(key, proof)
        }
        #[cfg(test)]
        Kind::Probe {
            panic,
            completed,
            tag,
            thread_exit,
        } => {
            if thread_exit {
                PROBE_THREAD_EXITS.with(|exits| {
                    exits
                        .borrow_mut()
                        .push(ProbeThreadExit(Arc::clone(&completed)))
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(!panic, "injected worker failure");
            report.kind = "scheduler_test";
            if let Some(tag) = tag {
                report.prepared_hit = prior_identity == Some(tag);
                cache = Some(tag);
            }
            Output::Probe
        }
        Kind::Native {
            case,
            request,
            segment,
        } => {
            report.kind = "native";
            let request = &case.plan.requests()[request];
            let work = || request.prove_segment_profiled(segment).map_err(error);
            let (mut artifact, times) = if task.retain_native {
                context.with_retained_native_cpu(work)?
            } else {
                cache = None;
                context.with_native_cpu(work)?
            };
            // Native generation already independently verifies the STARK.
            report.witness_ns = times.witness_ns;
            report.proving_ns = times.proving_ns;
            report.verification_ns = times.verification_ns;
            let mutation = Instant::now();
            match &mut artifact {
                graph_crypto::SegmentArtifact::Shake(a) => a.public_values[0] += Val::ONE,
                graph_crypto::SegmentArtifact::Aes(a) => a.public_values[0] += Val::ONE,
            }
            ensure(
                request.verify_segment(segment, &artifact).is_err(),
                "native public mutation accepted",
            )?;
            match &mut artifact {
                graph_crypto::SegmentArtifact::Shake(a) => {
                    a.public_values[0] -= Val::ONE;
                    a.proof.opened_values.trace_local[0] +=
                        lattica_prover_p3::block_v2::profile::Challenge::ONE;
                }
                graph_crypto::SegmentArtifact::Aes(a) => {
                    a.public_values[0] -= Val::ONE;
                    a.proof.opened_values.trace_local[0] +=
                        lattica_prover_p3::block_v2::profile::Challenge::ONE;
                }
            }
            ensure(
                request.verify_segment(segment, &artifact).is_err(),
                "native proof mutation accepted",
            )?;
            match &mut artifact {
                graph_crypto::SegmentArtifact::Shake(a) => {
                    a.proof.opened_values.trace_local[0] -=
                        lattica_prover_p3::block_v2::profile::Challenge::ONE
                }
                graph_crypto::SegmentArtifact::Aes(a) => {
                    a.proof.opened_values.trace_local[0] -=
                        lattica_prover_p3::block_v2::profile::Challenge::ONE
                }
            }
            report.mutation_ns = mutation.elapsed().as_nanos();
            report.mutation_checks = 2;
            let bytes = match &artifact {
                graph_crypto::SegmentArtifact::Shake(a) => postcard::to_allocvec(&a.proof),
                graph_crypto::SegmentArtifact::Aes(a) => postcard::to_allocvec(&a.proof),
            }
            .map_err(error)?;
            ensure(bytes.len() <= 16 << 20, "native proof output capacity")?;
            report.proof_digest = Some(hex(&sha3::Sha3_256::digest(&bytes)));
            Output::Native(artifact)
        }
        Kind::Group {
            case,
            request,
            first,
        } => {
            report.kind = "paired_compile";
            let children = task
                .inputs
                .into_iter()
                .map(|x| match x {
                    Output::Native(p) => Ok(p),
                    _ => Err("paired predecessor type".into()),
                })
                .collect::<Result<Vec<_>>>()?;
            let node = component_tree::cpu::compile_pair(
                &case.plan.requests()[request],
                &case.context,
                first,
                &children,
            )
            .map_err(error)?;
            let bytes = node.cpu_admission_bytes().map_err(error)?;
            let identity = node.cpu_identity().map_err(error)?;
            report.compile_ns = started.elapsed().as_nanos();
            Output::Compiled(node, bytes, identity)
        }
        Kind::Merge => {
            report.kind = "parent_compile";
            let mut children = task.inputs.into_iter();
            let Some(Output::Proven(left, lp)) = children.next() else {
                return Err("left CPU parent predecessor".into());
            };
            let Some(Output::Proven(right, rp)) = children.next() else {
                return Err("right CPU parent predecessor".into());
            };
            let node = component_tree::compile_merge(&left, &right, [&lp, &rp]).map_err(error)?;
            let bytes = node.cpu_admission_bytes().map_err(error)?;
            let identity = node.cpu_identity().map_err(error)?;
            report.compile_ns = started.elapsed().as_nanos();
            Output::Compiled(node, bytes, identity)
        }
        Kind::Prove => {
            report.kind = "recursive_proof";
            let Some(Output::Compiled(node, _, identity)) = task.inputs.into_iter().next() else {
                return Err("CPU proof predecessor".into());
            };
            report.prepared_hit = prior_identity == Some(identity);
            let (key, mut proof, timing) = node.prove_cpu(context).map_err(error)?;
            report.registration_ns = timing.registration_ns;
            report.proving_ns = timing.proving_ns;
            report.verification_ns = timing.verification_ns;
            let mutation = Instant::now();
            proof.public[0] += Val::ONE;
            ensure(
                key.verify(&proof).is_err(),
                "recursive public mutation accepted",
            )?;
            proof.public[0] -= Val::ONE;
            proof.proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
            ensure(
                key.verify(&proof).is_err(),
                "recursive proof mutation accepted",
            )?;
            proof.proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] -= lattica_prover_p3::block_v2::profile::Challenge::ONE;
            report.mutation_ns = mutation.elapsed().as_nanos();
            report.mutation_checks = 2;
            let bytes = postcard::to_allocvec(&proof.proof).map_err(error)?;
            ensure(bytes.len() <= 16 << 20, "recursive proof output capacity")?;
            report.proof_digest = Some(hex(&sha3::Sha3_256::digest(&bytes)));
            cache = Some(identity);
            Output::Proven(key, proof)
        }
    };
    report.elapsed_ns = started.elapsed().as_nanos();
    Ok((output, report, cache))
}

#[cfg(test)]
struct ProbeThreadExit(Arc<std::sync::atomic::AtomicUsize>);
#[cfg(test)]
impl Drop for ProbeThreadExit {
    fn drop(&mut self) {
        // Make delayed compute-thread cleanup observable to the coordinator.
        std::thread::sleep(std::time::Duration::from_millis(50));
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(test)]
std::thread_local! {
    static PROBE_THREAD_EXITS: std::cell::RefCell<Vec<ProbeThreadExit>> = const { std::cell::RefCell::new(Vec::new()) };
}
