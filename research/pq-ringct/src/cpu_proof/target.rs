//! Cold parent comparisons sharing only already-verified public child proofs.
//! Each arm compiles and registers anew, and drops its owner before the next arm.
use super::*;
use crate::execution::ProvingContext;
use jobs::{Kind, Observation, Output, Task};
use lattica_prover_p3::block_v2::cpu_commitment::{CommitmentPath, HashKernel, Variant};

pub struct Selection {
    pub original: Box<Kind>,
    pub profile: crate::host_memory_profile::HostMemoryProfile,
    pub kernel: HashKernel,
    pub path: CommitmentPath,
    pub baseline_overlap: bool,
    pub overlap: bool,
    pub candidate_first: bool,
}
enum Inputs {
    Crypto {
        case: Arc<inputs::Case>,
        request: usize,
        first: usize,
        children: Vec<graph_crypto::SegmentArtifact>,
    },
    Graph {
        left: crate::graph_tree::NodeKey,
        lp: crate::graph_tree::NodeProof,
        right: crate::graph_tree::NodeKey,
        rp: crate::graph_tree::NodeProof,
    },
}
pub struct Prepared {
    inputs: Inputs,
    first: Option<Output>,
    start: Instant,
    compile_ns: u128,
    work_bytes: u64,
    original_bytes: u64,
    dependency_bytes: u64,
    selection: Selection,
}
#[derive(serde::Serialize)]
pub struct Comparison {
    pub candidate: bool,
    pub hash_kernel: HashKernel,
    pub identity_overlap: bool,
    pub commitment_path: CommitmentPath,
    pub observation: Observation,
}

impl Inputs {
    fn retained_bytes(&self) -> Result<u64> {
        use lattica_prover_p3::block_v2::machine::backend::{
            retained_native_proof_capacity_bytes, retained_proof_capacity_bytes,
        };
        let mut bytes = (std::mem::size_of::<Self>() + 4096) as u64;
        let mut add = |n: u64| -> Result<()> {
            bytes = bytes
                .checked_add(n)
                .ok_or("target dependency capacity overflow")?;
            Ok(())
        };
        match self {
            Self::Crypto { children, .. } => {
                add(
                    (children.capacity() * std::mem::size_of::<graph_crypto::SegmentArtifact>())
                        as u64,
                )?;
                for child in children {
                    let proof = match child {
                        graph_crypto::SegmentArtifact::Shake(p) => &p.proof,
                        graph_crypto::SegmentArtifact::Aes(p) => &p.proof,
                    };
                    add(retained_native_proof_capacity_bytes(proof, 64 << 20)
                        .map_err(|e| format!("{e:?}"))? as u64)?;
                }
            }
            Self::Graph {
                left,
                lp,
                right,
                rp,
            } => {
                for (key, proof) in [(left, lp), (right, rp)] {
                    add(key.cpu_retained_key_bytes().map_err(error)?)?;
                    add((proof.public.capacity() * std::mem::size_of::<Val>()) as u64)?;
                    add(retained_proof_capacity_bytes(&proof.proof, 64 << 20)
                        .map_err(|e| format!("{e:?}"))? as u64)?;
                }
            }
        }
        ensure(
            bytes <= 64 << 20,
            "retained children exceed their original combined reservations",
        )?;
        Ok(bytes)
    }
    fn compile(&self) -> Result<Output> {
        match self {
            Self::Crypto {
                case,
                request,
                first,
                children,
            } => {
                let node = component_tree::cpu::compile_pair(
                    &case.plan.requests()[*request],
                    &case.context,
                    *first,
                    children,
                )
                .map_err(error)?;
                let bytes = node
                    .cpu_admission_bytes_with_variant(Variant::Combined)
                    .map_err(error)?;
                let identity = node.cpu_identity().map_err(error)?;
                Ok(Output::Compiled(node, bytes, identity))
            }
            Self::Graph {
                left,
                lp,
                right,
                rp,
            } => {
                let node =
                    crate::graph_tree::compile_merge(left, right, [lp, rp]).map_err(error)?;
                let bytes = node
                    .cpu_admission_bytes_with_variant(Variant::Combined)
                    .map_err(error)?;
                let identity = node.cpu_identity().map_err(error)?;
                Ok(Output::GraphCompiled(node, bytes, identity))
            }
        }
    }
}
fn work_bytes(output: &Output) -> Result<u64> {
    match output {
        Output::Compiled(_, bytes, _) | Output::GraphCompiled(_, bytes, _) => Ok(*bytes),
        _ => Err("target compiler output type".into()),
    }
}

pub fn prepare(mut selection: Selection, inputs: Vec<Output>) -> Result<Prepared> {
    // Preserve exactly two authenticated child artifacts, under the same 32 MiB
    // output reservations used by the ordinary scheduler. No proving state.
    ensure(
        inputs.len() == 2,
        "target requires two genuine child proofs",
    )?;
    let kind = std::mem::replace(&mut selection.original, Box::new(Kind::Prove));
    let inputs = match *kind {
        Kind::Group {
            case,
            request,
            first,
        } => Inputs::Crypto {
            case,
            request,
            first,
            children: inputs
                .into_iter()
                .map(|x| match x {
                    Output::Native(p) => Ok(p),
                    _ => Err("target native child type".into()),
                })
                .collect::<Result<_>>()?,
        },
        Kind::GraphMerge => {
            let mut inputs = inputs.into_iter();
            let Some(Output::GraphProven(left, lp)) = inputs.next() else {
                return Err("target left graph child type".into());
            };
            let Some(Output::GraphProven(right, rp)) = inputs.next() else {
                return Err("target right graph child type".into());
            };
            Inputs::Graph {
                left,
                lp,
                right,
                rp,
            }
        }
        _ => return Err("unsupported target compiler".into()),
    };
    let start = Instant::now();
    let first = inputs.compile()?;
    let compile_ns = start.elapsed().as_nanos();
    let work_bytes = work_bytes(&first)?;
    let dependency_bytes = inputs.retained_bytes()?;
    let original_bytes = first
        .compiled_output_bytes()?
        .ok_or("target original size")?
        .checked_add(dependency_bytes)
        .ok_or("target original overflow")?;
    Ok(Prepared {
        inputs,
        first: Some(first),
        start,
        compile_ns,
        work_bytes,
        original_bytes,
        dependency_bytes,
        selection,
    })
}

impl Prepared {
    pub fn original_bytes(&self) -> u64 {
        self.original_bytes
    }
    pub fn work_bytes(&self) -> u64 {
        self.work_bytes
    }
    pub fn compile_ns(&self) -> u128 {
        self.compile_ns
    }
    pub fn dependency_bytes(&self) -> u64 {
        self.dependency_bytes
    }
    pub fn prove(mut self, id: usize) -> Result<Vec<Comparison>> {
        let mut comparisons = Vec::new();
        for candidate in [
            self.selection.candidate_first,
            !self.selection.candidate_first,
        ] {
            let (start, compiled, compile_ns) = if let Some(first) = self.first.take() {
                (self.start, first, self.compile_ns)
            } else {
                let start = Instant::now();
                let compiled = self.inputs.compile()?;
                (start, compiled, start.elapsed().as_nanos())
            };
            ensure(
                work_bytes(&compiled)? <= self.work_bytes,
                "target work geometry changed",
            )?;
            ensure(
                compiled
                    .compiled_output_bytes()?
                    .ok_or("target original size")?
                    + self.dependency_bytes
                    <= self.original_bytes,
                "target original capacity changed",
            )?;
            let kernel = if candidate {
                self.selection.kernel
            } else {
                HashKernel::Existing
            };
            let overlap = if candidate {
                self.selection.overlap
            } else {
                self.selection.baseline_overlap
            };
            let path = if candidate {
                self.selection.path
            } else {
                CommitmentPath::Existing
            };
            let context = ProvingContext::cpu_research_with_commitment_path(
                self.selection.profile,
                Variant::Combined,
                kernel,
                overlap,
                path,
            )?;
            let kind = match &compiled {
                Output::Compiled(..) => Kind::Prove,
                Output::GraphCompiled(..) => Kind::GraphProve,
                _ => unreachable!(),
            };
            let (output, mut observation, _) = jobs::execute(
                Task {
                    id,
                    kind,
                    inputs: vec![compiled],
                    retain_native: false,
                    service_started: None,
                    preceding_compile_ns: 0,
                },
                &context,
                None,
            )?;
            observation.compile_ns = compile_ns;
            observation.service_ns = start
                .elapsed()
                .as_nanos()
                .saturating_sub(observation.mutation_ns);
            ensure(
                !observation.prepared_hit,
                "target comparison unexpectedly reused preparation",
            )?;
            drop(output);
            context.release_prepared()?;
            drop(context);
            comparisons.push(Comparison {
                candidate,
                hash_kernel: kernel,
                identity_overlap: overlap,
                commitment_path: path,
                observation,
            });
        }
        ensure(
            comparisons[0].observation.proof_digest != comparisons[1].observation.proof_digest,
            "target comparison reused a proof",
        )?;
        Ok(comparisons)
    }
}
