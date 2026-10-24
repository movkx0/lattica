//! Native sampler/transcript child provisioning for an exact registered graph.
//! These artifacts do not discharge graph obligations. Composite graph leaves
//! must still verify the crypto producer, auxiliary STARK, and all root joins.

use crate::{
    graph_crypto, graph_tree,
    rust_verify::{
        committed_backend::{Operation, PolynomialKind, Source, UnprovedRelationGraph},
        Q,
    },
    shake_air::{commit_bytes, SHAKE_INPUT_DOMAIN, SHAKE_OUTPUT_DOMAIN},
    sparse_air::{self, join::SparseArtifact, SparseAir},
    transcript_air::{self, join::TranscriptArtifact, PartValues, TranscriptAir},
    uniform_air::{self, join::UniformArtifact, UniformAir},
};
use lattica_prover_p3::block_v2::{machine::program::Val, profile};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

mod cache;
#[cfg(feature = "opencl")]
mod preparation;
pub use cache::{ArchivedReverification, AuxiliaryCache, CacheOutcome};
#[cfg(all(test, feature = "native-matrict"))]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(e: impl std::fmt::Debug) -> Error {
    Error(format!("{e:?}"))
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(message.into()))
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    SampleGUniform = 1,
    AlphaUniform = 2,
    AlphaSparse = 3,
    HashAlphaTranscript = 4,
    HashXTranscript = 5,
    HashXSparse = 6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Uniform(uniform_air::Kind),
    Sparse(sparse_air::Kind),
    Transcript,
}
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub width: usize,
    pub height: usize,
    pub raw_trace_bytes: u64,
    /// Heuristic admission only; external process guards remain necessary.
    pub estimated_prover_bytes: u64,
}
enum Payload {
    Uniform(uniform_air::Kind, Vec<u8>),
    Sparse(sparse_air::Kind, Vec<u8>),
    Transcript(TranscriptAir, Vec<PartValues>),
}
pub struct AuxiliaryRequest {
    operation: usize,
    role: Role,
    payload: Payload,
    expected: [Val; 8],
    key: [u8; 32],
    geometry: Geometry,
    memory_budget: u64,
}
pub struct AuxiliaryFactory {
    requests: Vec<AuxiliaryRequest>,
}
pub enum AuxiliaryArtifact {
    Uniform(UniformArtifact),
    Sparse(SparseArtifact),
    Transcript(TranscriptArtifact),
}
impl AuxiliaryArtifact {
    pub fn uniform(&self) -> Result<&UniformArtifact> {
        match self {
            Self::Uniform(a) => Ok(a),
            _ => Err(Error("not a uniform artifact".into())),
        }
    }
    pub fn sparse(&self) -> Result<&SparseArtifact> {
        match self {
            Self::Sparse(a) => Ok(a),
            _ => Err(Error("not a sparse artifact".into())),
        }
    }
    pub fn transcript(&self) -> Result<&TranscriptArtifact> {
        match self {
            Self::Transcript(a) => Ok(a),
            _ => Err(Error("not a transcript artifact".into())),
        }
    }
    pub fn public_values(&self) -> &[Val; 8] {
        match self {
            Self::Uniform(a) => &a.public_values,
            Self::Sparse(a) => &a.public_values,
            Self::Transcript(a) => &a.public_values,
        }
    }
    fn proof(&self) -> &p3_uni_stark::Proof<profile::Config> {
        match self {
            Self::Uniform(a) => &a.proof,
            Self::Sparse(a) => &a.proof,
            Self::Transcript(a) => &a.proof,
        }
    }
}

fn geometry(width: usize, height: usize) -> Result<Geometry> {
    let raw = (width as u64)
        .checked_mul(height as u64)
        .and_then(|n| n.checked_mul(8))
        .ok_or_else(|| Error("auxiliary trace size overflow".into()))?;
    let estimated = raw
        .checked_mul(48)
        .and_then(|n| n.checked_add(512 << 20))
        .ok_or_else(|| Error("auxiliary memory estimate overflow".into()))?;
    Ok(Geometry {
        width,
        height,
        raw_trace_bytes: raw,
        estimated_prover_bytes: estimated,
    })
}
fn combined(a: [Val; 4], b: [Val; 4]) -> [Val; 8] {
    core::array::from_fn(|i| if i < 4 { a[i] } else { b[i - 4] })
}

impl AuxiliaryFactory {
    /// Prepare raw auxiliary streams and endpoint commitments with the worker's
    /// explicit policy. GPU-required work never calls CPU hint generators.
    pub fn new_with_context(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        context: &graph_tree::GraphContext,
        memory_budget: u64,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<Self> {
        if let Some(execution) = execution {
            if execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
                #[cfg(feature = "opencl")]
                {
                    let host_bytes =
                        usize::try_from(memory_budget.min(execution.host_bytes())).map_err(err)?;
                    let (factory, _) = execution
                        .with_witness_preparation(host_bytes, |operations| {
                            Self::new_on_gpu(tree, graph, context, memory_budget, operations)
                                .map_err(|e| e.to_string())
                        })
                        .map_err(err)?;
                    return Ok(factory);
                }
                #[cfg(not(feature = "opencl"))]
                return Err(Error("GPU auxiliary preparation unavailable".into()));
            }
        }
        Self::new(tree, graph, context, memory_budget)
    }

    /// `tree` must come from the trusted relation compiler. Registration of an
    /// arbitrary caller-supplied graph would not authenticate its relation.
    pub fn new(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        context: &graph_tree::GraphContext,
        memory_budget: u64,
    ) -> Result<Self> {
        require(memory_budget > 0, "zero auxiliary memory budget")?;
        require(
            tree.node_manifest_hint(graph).map_err(err)? == context.node_manifest,
            "auxiliary graph manifest mismatch",
        )?;
        for node in graph.bytes() {
            match node.source {
                Source::Context => require(
                    node.values == context.context,
                    "auxiliary graph context mismatch",
                )?,
                Source::StatementSeed => require(
                    node.values == graph.setup_seed(),
                    "auxiliary setup seed mismatch",
                )?,
                _ => {}
            }
        }
        // Reconstruct requests from the exact trusted graph. Their segmentation
        // is irrelevant here: output_bytes_hint is witness material only, and
        // no AES/SHAKE proof or acceptance flag is generated by this factory.
        let crypto =
            graph_crypto::Plan::new(tree, graph, graph_crypto::Policy::default()).map_err(err)?;
        let stream = |operation: usize, subrequest: u32| -> Result<Vec<u8>> {
            let request = crypto
                .requests()
                .iter()
                .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
                .ok_or_else(|| Error("missing exact graph crypto request".into()))?;
            Ok(request.output_bytes_hint())
        };
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/matrict/graph-auxiliary-factory/v1");
        identity.update(crate::graph_proofs::compiled_source_fingerprint());
        identity.update(tree.label());
        identity.update(context.context);
        for value in context.statement.iter().chain(&context.node_manifest) {
            identity.update(value.as_canonical_u64().to_le_bytes());
        }
        let identity: [u8; 32] = identity.finalize().into();
        let root = |operation: usize, id, kind| -> Result<[Val; 4]> {
            let node = graph.polynomial(id);
            require(
                node.source == Source::Derived { operation } && node.kind == kind,
                "auxiliary polynomial producer/kind mismatch",
            )?;
            Ok(node.commitment)
        };
        let mut requests = Vec::new();
        let mut push = |operation, role, payload, expected| -> Result<()> {
            requests.push(AuxiliaryRequest::new(
                identity,
                operation,
                role,
                payload,
                expected,
                memory_budget,
            )?);
            Ok(())
        };
        for (index, operation) in graph.operations().iter().enumerate() {
            match operation {
                Operation::SampleG { output, .. } => {
                    let kind = uniform_air::Kind::SampleG4;
                    let bytes = stream(index, 0)?;
                    let roots = output
                        .iter()
                        .map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q }))
                        .collect::<Result<Vec<_>>>()?;
                    let expected = combined(
                        commit_bytes(crate::aes_lane_air::AES_OUTPUT_DOMAIN, &bytes),
                        UniformAir::new(kind).bundle(&roots).map_err(err)?,
                    );
                    push(
                        index,
                        Role::SampleGUniform,
                        Payload::Uniform(kind, bytes),
                        expected,
                    )?;
                }
                Operation::ExpandAlpha {
                    canonical, signed, ..
                } => {
                    let kind = uniform_air::Kind::ExpandAlpha2;
                    let bytes = stream(index, 0)?;
                    let roots = canonical
                        .iter()
                        .map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q }))
                        .collect::<Result<Vec<_>>>()?;
                    let expected = combined(
                        commit_bytes(crate::aes_lane_air::AES_OUTPUT_DOMAIN, &bytes),
                        UniformAir::new(kind).bundle(&roots).map_err(err)?,
                    );
                    push(
                        index,
                        Role::AlphaUniform,
                        Payload::Uniform(kind, bytes),
                        expected,
                    )?;
                    let bytes = stream(index, 1)?;
                    let expected = combined(
                        commit_bytes(crate::aes_lane_air::AES_OUTPUT_DOMAIN, &bytes),
                        root(index, *signed, PolynomialKind::Signed { bound: 1 })?,
                    );
                    push(
                        index,
                        Role::AlphaSparse,
                        Payload::Sparse(sparse_air::Kind::AlphaPrime39, bytes),
                        expected,
                    )?;
                }
                Operation::HashAlpha { .. } | Operation::HashX { .. } => {
                    let (air, values, roots) =
                        TranscriptAir::from_graph_operation(graph, operation).map_err(err)?;
                    let input = air.serialize(&values).map_err(err)?;
                    let expected = combined(
                        air.bundle(&roots).map_err(err)?,
                        commit_bytes(SHAKE_INPUT_DOMAIN, &input),
                    );
                    let role = if matches!(operation, Operation::HashAlpha { .. }) {
                        Role::HashAlphaTranscript
                    } else {
                        Role::HashXTranscript
                    };
                    push(index, role, Payload::Transcript(air, values), expected)?;
                    if let Operation::HashX { output, .. } = operation {
                        let bytes = stream(index, 0)?;
                        let expected = combined(
                            commit_bytes(SHAKE_OUTPUT_DOMAIN, &bytes),
                            root(index, *output, PolynomialKind::Signed { bound: 1 })?,
                        );
                        push(
                            index,
                            Role::HashXSparse,
                            Payload::Sparse(sparse_air::Kind::ChallengeX44, bytes),
                            expected,
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(Self { requests })
    }
    pub fn requests(&self) -> &[AuxiliaryRequest] {
        &self.requests
    }
    pub fn request(&self, operation: usize, role: Role) -> Result<&AuxiliaryRequest> {
        self.requests
            .iter()
            .find(|r| r.operation == operation && r.role == role)
            .ok_or_else(|| Error("auxiliary role does not belong to registered operation".into()))
    }
}

impl AuxiliaryRequest {
    fn new(
        identity: [u8; 32],
        operation: usize,
        role: Role,
        payload: Payload,
        expected: [Val; 8],
        memory_budget: u64,
    ) -> Result<Self> {
        let shape = match &payload {
            Payload::Uniform(kind, bytes) => {
                require(bytes.len() == kind.draws() * 4, "uniform stream length")?;
                geometry(uniform_air::WIDTH, UniformAir::new(*kind).height())?
            }
            Payload::Sparse(kind, bytes) => {
                require(bytes.len() == kind.input_len(), "sparse stream length")?;
                geometry(sparse_air::WIDTH, sparse_air::HEIGHT)?
            }
            Payload::Transcript(air, _) => geometry(air.width(), air.height())?,
        };
        let mut hash = Sha3_256::new();
        hash.update(identity);
        hash.update((operation as u64).to_le_bytes());
        hash.update([role as u8]);
        hash.update((shape.width as u64).to_le_bytes());
        hash.update((shape.height as u64).to_le_bytes());
        for value in expected {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        Ok(Self {
            operation,
            role,
            payload,
            expected,
            key: hash.finalize().into(),
            geometry: shape,
            memory_budget,
        })
    }
    pub fn operation_index(&self) -> usize {
        self.operation
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn kind(&self) -> Kind {
        match &self.payload {
            Payload::Uniform(k, _) => Kind::Uniform(*k),
            Payload::Sparse(k, _) => Kind::Sparse(*k),
            Payload::Transcript(..) => Kind::Transcript,
        }
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn cache_key(&self) -> [u8; 32] {
        self.key
    }
    pub fn expected_public_values(&self) -> [Val; 8] {
        self.expected
    }
    pub fn transcript_air(&self) -> Option<&TranscriptAir> {
        match &self.payload {
            Payload::Transcript(air, _) => Some(air),
            _ => None,
        }
    }
    pub fn verify(&self, artifact: &AuxiliaryArtifact) -> Result<()> {
        require(
            artifact.public_values() == &self.expected,
            "auxiliary exact ordered public roots",
        )?;
        require(
            artifact.proof().degree_bits == self.geometry.height.ilog2() as usize + 1,
            "auxiliary logical trace height",
        )?;
        match (&self.payload, artifact) {
            (Payload::Uniform(kind, _), AuxiliaryArtifact::Uniform(a)) => {
                uniform_air::join::verify_native(*kind, a).map_err(err)
            }
            (Payload::Sparse(kind, _), AuxiliaryArtifact::Sparse(a)) => {
                sparse_air::join::verify_native(*kind, a).map_err(err)
            }
            (Payload::Transcript(air, _), AuxiliaryArtifact::Transcript(a)) => {
                transcript_air::join::verify_native(air, a).map_err(err)
            }
            _ => Err(Error("auxiliary artifact family mismatch".into())),
        }
    }
    pub fn prove_with_context(
        &self,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<AuxiliaryArtifact> {
        let Some(context) = execution else {
            return self.prove();
        };
        if context.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
            #[cfg(feature = "opencl")]
            {
                let host_bytes = usize::try_from(self.memory_budget).map_err(err)?;
                let artifact = match &self.payload {
                    Payload::Uniform(kind, bytes) => AuxiliaryArtifact::Uniform(
                        UniformAir::new(*kind)
                            .prove_gpu(context, bytes, host_bytes)
                            .map_err(err)?,
                    ),
                    Payload::Sparse(kind, bytes) => AuxiliaryArtifact::Sparse(
                        SparseAir::new(*kind)
                            .prove_gpu(context, bytes, host_bytes)
                            .map_err(err)?,
                    ),
                    Payload::Transcript(air, values) => AuxiliaryArtifact::Transcript(
                        air.prove_gpu(context, values, host_bytes).map_err(err)?,
                    ),
                };
                self.verify(&artifact)?;
                return Ok(artifact);
            }
            #[cfg(not(feature = "opencl"))]
            return Err(Error("native GPU proving unavailable".into()));
        }
        context
            .with_native_cpu(|| self.prove().map_err(|e| e.to_string()))
            .map_err(err)
    }
    pub fn prove(&self) -> Result<AuxiliaryArtifact> {
        require(
            self.geometry.estimated_prover_bytes <= self.memory_budget,
            "auxiliary child exceeds heuristic memory budget",
        )?;
        let config = profile::make_cpu_config();
        let artifact = match &self.payload {
            Payload::Uniform(kind, bytes) => {
                let air = UniformAir::new(*kind);
                let w = air.generate(bytes).map_err(err)?;
                require(
                    w.public_values == self.expected,
                    "uniform witness/graph roots mismatch",
                )?;
                let proof = p3_uni_stark::prove(&config, &air, w.trace, &w.public_values);
                AuxiliaryArtifact::Uniform(UniformArtifact {
                    public_values: w.public_values,
                    proof,
                })
            }
            Payload::Sparse(kind, bytes) => {
                let air = SparseAir::new(*kind);
                let w = air.generate(bytes).map_err(err)?;
                require(
                    w.public_values == self.expected,
                    "sparse witness/graph roots mismatch",
                )?;
                let proof = p3_uni_stark::prove(&config, &air, w.trace, &w.public_values);
                AuxiliaryArtifact::Sparse(SparseArtifact {
                    public_values: w.public_values,
                    proof,
                })
            }
            Payload::Transcript(air, values) => {
                let w = air.generate(values).map_err(err)?;
                require(
                    w.public_values == self.expected,
                    "transcript witness/graph roots mismatch",
                )?;
                let proof = p3_uni_stark::prove(&config, air, w.trace, &w.public_values);
                AuxiliaryArtifact::Transcript(TranscriptArtifact {
                    public_values: w.public_values,
                    proof,
                })
            }
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
}
