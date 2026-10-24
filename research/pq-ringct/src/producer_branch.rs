//! Typed internal producer branches; they never discharge graph coverage.
//! Complete atomic graph leaves consume these actual recursive proofs, check
//! exact graph input/output joins, and only then mark the operation covered.
use crate::{
    component_tree, graph_tree,
    obligation_manifest::ContextWires,
    request_bridge::{self, AesRequest, ShakeRequest, TreeArtifacts},
    rust_verify::{
        committed_backend::{
            Operation, PolynomialKind, Source, TranscriptPart, UnprovedRelationGraph,
        },
        Q, QHAT,
    },
    sparse_air::{self, join::SparseArtifact, SparseAir},
    transcript_air::{join::TranscriptArtifact, PartKind, TranscriptAir},
    uniform_air::{self, join::UniformArtifact, UniformAir},
};
use lattica_prover_p3::block_v2::{
    commitment,
    machine::{
        analysis,
        backend::{RegisteredProgram, RegisteredVerifier},
        program::{ScopedProgramBuilder, Val, Wire},
        verifier::{self, ProofInputs},
        MachineAir, Program, ProgramBuilder,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::sync::Arc;

mod preparation;

pub use crate::component_tree::Geometry;
pub use crate::outer_cache::ProofCache as OuterProofCache;

const CONTEXT: usize = 8;
const STATEMENT: usize = 16;
const NODE_MANIFEST: usize = 20;
const OPERATION: usize = 24;
const ROLE: usize = 25;
const DESCRIPTOR: usize = 26;
const INPUT: usize = 30;
const OUTPUT: usize = 34;
const PUBLIC_VALUES: usize = 38;
const DESCRIPTOR_DOMAIN: u64 = 0x50524f445f425231;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    AlphaUniform,
    AlphaSparse,
    HashXTranscriptShake,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Descriptor {
    AlphaUniform,
    AlphaSparse,
    HashX(Vec<PartKind>),
}
impl Descriptor {
    fn role(&self) -> Role {
        match self {
            Self::AlphaUniform => Role::AlphaUniform,
            Self::AlphaSparse => Role::AlphaSparse,
            Self::HashX(_) => Role::HashXTranscriptShake,
        }
    }
    fn tag(&self) -> u64 {
        match self {
            Self::AlphaUniform => 1,
            Self::AlphaSparse => 2,
            Self::HashX(_) => 3,
        }
    }
    fn aes(&self) -> Result<crate::aes_air::Descriptor> {
        match self {
            Self::AlphaUniform => Ok(crate::aes_air::Descriptor {
                domain: 0x4368,
                start_counter: 0,
                output_len: 2572,
            }),
            Self::AlphaSparse => Ok(crate::aes_air::Descriptor {
                domain: 0x4368,
                start_counter: 161,
                output_len: 127,
            }),
            Self::HashX(_) => Err(Error("HashX branch has no AES descriptor".into())),
        }
    }
}
#[derive(Clone, Debug)]
struct Spec {
    profile: [u8; 32],
    operation: u32,
    descriptor: Descriptor,
}
impl Spec {
    fn request_index(&self) -> Result<u32> {
        self.operation
            .checked_mul(2)
            .and_then(|n| n.checked_add(u32::from(self.descriptor == Descriptor::AlphaSparse)))
            .ok_or_else(|| Error("producer request index overflow".into()))
    }
    fn descriptor_root(&self) -> Result<[Val; 4]> {
        let mut fields = vec![self.descriptor.tag(), u64::from(self.request_index()?)];
        match &self.descriptor {
            Descriptor::AlphaUniform | Descriptor::AlphaSparse => {
                let d = self.descriptor.aes()?;
                fields.extend([d.domain, u64::from(d.start_counter), d.output_len as u64]);
            }
            Descriptor::HashX(parts) => {
                let air = TranscriptAir::new(parts.clone()).map_err(err)?;
                fields.extend([air.byte_len() as u64, 137, parts.len() as u64]);
                fields.extend(parts.iter().map(|part| match part {
                    PartKind::Bytes32 => 1,
                    PartKind::PolynomialQ => 2,
                    PartKind::PolynomialQhat => 3,
                }));
            }
        }
        Ok(commitment::hash_fields(DESCRIPTOR_DOMAIN, &fields)
            .map_err(err)?
            .map(Val::from_u64))
    }
}
fn words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[i * 4..i * 4 + 4].try_into().unwrap(),
        ))
    })
}
fn header(
    spec: &Spec,
    context: &graph_tree::GraphContext,
    roots: [[Val; 4]; 2],
) -> Result<Vec<Val>> {
    let mut public = vec![Val::ZERO; PUBLIC_VALUES];
    public[..8].copy_from_slice(&words(&spec.profile));
    public[CONTEXT..STATEMENT].copy_from_slice(&words(&context.context));
    public[STATEMENT..NODE_MANIFEST].copy_from_slice(&context.statement);
    public[NODE_MANIFEST..OPERATION].copy_from_slice(&context.node_manifest);
    public[OPERATION] = Val::from_u32(spec.operation);
    public[ROLE] = Val::from_u64(spec.descriptor.tag());
    public[DESCRIPTOR..INPUT].copy_from_slice(&spec.descriptor_root()?);
    public[INPUT..OUTPUT].copy_from_slice(&roots[0]);
    public[OUTPUT..].copy_from_slice(&roots[1]);
    Ok(public)
}
fn constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let expected = b.constant(value);
    b.assert_equal(wire, expected);
}
fn public_wires(b: &mut ProgramBuilder, spec: &Spec) -> Result<Vec<Wire>> {
    let public = (0..PUBLIC_VALUES)
        .map(|i| b.public(i).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    for (wire, value) in public[..8].iter().zip(words(&spec.profile)) {
        constant(b, *wire, value);
    }
    for &wire in &public[CONTEXT..STATEMENT] {
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(b, wire, 32).map_err(err)?;
    }
    constant(b, public[OPERATION], Val::from_u32(spec.operation));
    constant(b, public[ROLE], Val::from_u64(spec.descriptor.tag()));
    for (wire, value) in public[DESCRIPTOR..INPUT]
        .iter()
        .zip(spec.descriptor_root()?)
    {
        constant(b, *wire, value);
    }
    Ok(public)
}
fn bind_context(
    b: &mut ScopedProgramBuilder<'_>,
    public: &[Wire],
    context: &ContextWires,
    manifest: &[Wire; 4],
) {
    for (wire, expected) in public[..OPERATION].iter().zip(
        context
            .profile
            .iter()
            .chain(&context.context)
            .chain(&context.statement)
            .chain(manifest),
    ) {
        b.assert_equal(*wire, *expected);
    }
}

pub struct Factory<'a> {
    graph: &'a UnprovedRelationGraph,
    execution: Option<&'a crate::execution::ProvingContext>,
    profile: [u8; 32],
    context: graph_tree::GraphContext,
}
impl<'a> Factory<'a> {
    pub fn new(
        plan: &graph_tree::Plan,
        graph: &'a UnprovedRelationGraph,
        context: &graph_tree::GraphContext,
    ) -> Result<Self> {
        Self::new_with_context(plan, graph, context, None)
    }
    pub fn new_with_context(
        plan: &graph_tree::Plan,
        graph: &'a UnprovedRelationGraph,
        context: &graph_tree::GraphContext,
        execution: Option<&'a crate::execution::ProvingContext>,
    ) -> Result<Self> {
        preparation::validate_manifest(plan, graph, context, execution)?;
        for node in graph.bytes() {
            if node.source == Source::Context {
                require(
                    node.values == context.context,
                    "producer graph context mismatch",
                )?;
            }
        }
        Ok(Self {
            graph,
            execution,
            profile: plan.label(),
            context: context.clone(),
        })
    }
    fn spec(&self, operation: usize, descriptor: Descriptor) -> Result<Spec> {
        let spec = Spec {
            profile: self.profile,
            operation: u32::try_from(operation).map_err(err)?,
            descriptor,
        };
        spec.request_index()?;
        Ok(spec)
    }
    fn polynomial_root(
        &self,
        operation: usize,
        id: crate::rust_verify::committed_backend::PolyId,
        kind: PolynomialKind,
    ) -> Result<[Val; 4]> {
        let node = self.graph.polynomial(id);
        require(
            node.source == Source::Derived { operation } && node.kind == kind,
            "producer output provenance or kind mismatch",
        )?;
        Ok(node.commitment)
    }
    fn alpha_roots(&self, operation: usize, descriptor: &Descriptor) -> Result<[[Val; 4]; 2]> {
        if self.gpu_required() {
            return self.alpha_roots_with_gpu(operation, descriptor);
        }
        let Some(Operation::ExpandAlpha {
            seed,
            canonical,
            signed,
        }) = self.graph.operations().get(operation)
        else {
            return Err(Error("producer operation is not ExpandAlpha".into()));
        };
        let input = crate::shake_air::commit_bytes(
            crate::aes_air::AES_INPUT_DOMAIN,
            &descriptor
                .aes()?
                .input_bytes(&self.graph.byte_string(*seed).values),
        );
        let output = match descriptor {
            Descriptor::AlphaUniform => UniformAir::new(uniform_air::Kind::ExpandAlpha2)
                .bundle(&[
                    self.polynomial_root(
                        operation,
                        canonical[0],
                        PolynomialKind::Canonical { modulus: Q },
                    )?,
                    self.polynomial_root(
                        operation,
                        canonical[1],
                        PolynomialKind::Canonical { modulus: Q },
                    )?,
                ])
                .map_err(err)?,
            Descriptor::AlphaSparse => {
                self.polynomial_root(operation, *signed, PolynomialKind::Signed { bound: 1 })?
            }
            _ => return Err(Error("wrong Alpha branch descriptor".into())),
        };
        Ok([input, output])
    }
    pub fn compile_alpha_uniform(
        &self,
        operation: usize,
        aes_key: &component_tree::NodeKey,
        aes_proof: &component_tree::NodeProof,
        sampler: &UniformArtifact,
    ) -> Result<CompiledNode> {
        let descriptor = Descriptor::AlphaUniform;
        let roots = self.alpha_roots(operation, &descriptor)?;
        let spec = self.spec(operation, descriptor)?;
        compile_alpha(
            spec,
            &self.context,
            roots,
            aes_key,
            aes_proof,
            &sampler.public_values,
            &sampler.proof,
        )
    }
    pub fn compile_alpha_sparse(
        &self,
        operation: usize,
        aes_key: &component_tree::NodeKey,
        aes_proof: &component_tree::NodeProof,
        sampler: &SparseArtifact,
    ) -> Result<CompiledNode> {
        let descriptor = Descriptor::AlphaSparse;
        let roots = self.alpha_roots(operation, &descriptor)?;
        let spec = self.spec(operation, descriptor)?;
        compile_alpha(
            spec,
            &self.context,
            roots,
            aes_key,
            aes_proof,
            &sampler.public_values,
            &sampler.proof,
        )
    }
    pub fn compile_hash_x(
        &self,
        operation: usize,
        shake_key: &component_tree::NodeKey,
        shake_proof: &component_tree::NodeProof,
        transcript: &TranscriptArtifact,
    ) -> Result<CompiledNode> {
        let Some(Operation::HashX { parts, .. }) = self.graph.operations().get(operation) else {
            return Err(Error("producer operation is not HashX".into()));
        };
        let mut kinds = Vec::with_capacity(parts.len());
        let mut roots = Vec::with_capacity(parts.len());
        for part in parts {
            match part {
                TranscriptPart::Bytes(id) => {
                    kinds.push(PartKind::Bytes32);
                    roots.push(self.graph.byte_string(*id).commitment);
                }
                TranscriptPart::Polynomial(id) => {
                    let node = self.graph.polynomial(*id);
                    kinds.push(match node.kind {
                        PolynomialKind::Canonical { modulus: Q } => PartKind::PolynomialQ,
                        PolynomialKind::Canonical { modulus: QHAT } => PartKind::PolynomialQhat,
                        _ => return Err(Error("noncanonical producer transcript input".into())),
                    });
                    roots.push(node.commitment);
                }
            }
        }
        let air = TranscriptAir::new(kinds.clone()).map_err(err)?;
        let input = self.transcript_bundle(&air, &roots)?;
        let output = shake_proof
            .public
            .get(component_tree::EXPECTED_OUTPUT..component_tree::EXPECTED_OUTPUT + 4)
            .ok_or_else(|| Error("SHAKE producer public width".into()))?
            .try_into()
            .map_err(err)?;
        let spec = self.spec(operation, Descriptor::HashX(kinds))?;
        let public = header(&spec, &self.context, [input, output])?;
        let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
        let wires = public_wires(&mut b, &spec)?;
        let context = context_wires(&wires);
        let mut inputs = ProofInputs::default();
        let child = inputs
            .bases(&mut b, &transcript.public_values)
            .map_err(err)?;
        verifier::uni::verify(
            &mut b,
            &mut inputs,
            &air,
            air.height(),
            &child,
            &transcript.proof,
        )
        .map_err(err)?;
        for i in 0..4 {
            b.assert_equal(child[i], wires[INPUT + i]);
        }
        request_bridge::verify_shake_request(
            &mut b,
            &mut inputs,
            crate::shake_air::Descriptor {
                input_len: air.byte_len(),
                output_len: 137,
            },
            &child[4..8].try_into().map_err(err)?,
            &wires[OUTPUT..].try_into().map_err(err)?,
            ShakeRequest::Tree(TreeArtifacts {
                key: shake_key,
                proof: shake_proof,
                context: &context,
                index: spec.request_index()?,
            }),
        )
        .map_err(err)?;
        Ok(CompiledNode {
            spec,
            program: Arc::new(b.finish(None).map_err(err)?),
            public,
            witness: inputs.values,
        })
    }
}
fn context_wires(public: &[Wire]) -> ContextWires {
    ContextWires {
        profile: public[..8].try_into().unwrap(),
        context: public[CONTEXT..STATEMENT].try_into().unwrap(),
        statement: public[STATEMENT..NODE_MANIFEST].try_into().unwrap(),
    }
}
fn compile_alpha(
    spec: Spec,
    context: &graph_tree::GraphContext,
    roots: [[Val; 4]; 2],
    aes_key: &component_tree::NodeKey,
    aes_proof: &component_tree::NodeProof,
    sampler_public: &[Val; 8],
    sampler_proof: &p3_uni_stark::Proof<Config>,
) -> Result<CompiledNode> {
    let public = header(&spec, context, roots)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
    let wires = public_wires(&mut b, &spec)?;
    let context = context_wires(&wires);
    let mut inputs = ProofInputs::default();
    let child = inputs.bases(&mut b, sampler_public).map_err(err)?;
    match spec.descriptor {
        Descriptor::AlphaUniform => {
            let air = UniformAir::new(uniform_air::Kind::ExpandAlpha2);
            verifier::uni::verify(
                &mut b,
                &mut inputs,
                &air,
                air.height(),
                &child,
                sampler_proof,
            )
            .map_err(err)?;
        }
        Descriptor::AlphaSparse => {
            let air = SparseAir::new(sparse_air::Kind::AlphaPrime39);
            verifier::uni::verify(
                &mut b,
                &mut inputs,
                &air,
                sparse_air::HEIGHT,
                &child,
                sampler_proof,
            )
            .map_err(err)?;
        }
        _ => return Err(Error("wrong Alpha producer role".into())),
    }
    for i in 0..4 {
        b.assert_equal(child[4 + i], wires[OUTPUT + i]);
    }
    request_bridge::verify_aes_request(
        &mut b,
        &mut inputs,
        spec.descriptor.aes()?,
        &wires[INPUT..OUTPUT].try_into().map_err(err)?,
        &child[..4].try_into().map_err(err)?,
        AesRequest::Tree(TreeArtifacts {
            key: aes_key,
            proof: aes_proof,
            context: &context,
            index: spec.request_index()?,
        }),
    )
    .map_err(err)?;
    Ok(CompiledNode {
        spec,
        program: Arc::new(b.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}

pub struct CompiledNode {
    spec: Spec,
    program: Arc<Program>,
    public: Vec<Val>,
    witness: Vec<Val>,
}
impl CompiledNode {
    pub fn geometry(&self) -> Result<Geometry> {
        let g = analysis::analyze(&MachineAir::from_shared_program(Arc::clone(&self.program))).map_err(err)?;
        Ok(Geometry {
            active_rows: self.program.active_rows(),
            padded_rows: self.program.height(),
            wires: self.program.wire_count(),
            main_width: g.main_width,
            preprocessed_width: g.preprocessed_width,
            permutation_width_base: g.permutation_width_base,
            quotient_chunks: g.quotient_chunks,
            constraints: g.constraints,
            max_constraint_degree: g.max_constraint_degree,
            fri_ali_bits: g.fri_ali_bits,
            retained_lde_bytes: g.retained_lde_bytes,
        })
    }
    pub fn evaluate(&self) -> Result<()> {
        MachineAir::from_shared_program(Arc::clone(&self.program))
            .trace(&self.public, &self.witness)
            .map_err(err)?;
        Ok(())
    }
    pub fn prepare(self, memory_budget: u64) -> Result<PreparedNode> {
        require(
            self.geometry()?.retained_lde_bytes <= memory_budget,
            "producer branch exceeds retained-LDE budget before registration",
        )?;
        let registered =
            RegisteredProgram::new_with_memory_budget(MachineAir::from_shared_program(self.program), memory_budget)
                .map_err(err)?;
        Ok(PreparedNode {
            registered,
            spec: self.spec,
            public: self.public,
            witness: self.witness,
        })
    }
}
pub struct PreparedNode {
    registered: RegisteredProgram,
    spec: Spec,
    public: Vec<Val>,
    witness: Vec<Val>,
}
impl PreparedNode {
    pub fn key(&self) -> NodeKey {
        NodeKey {
            spec: self.spec.clone(),
            height: self.registered.air().program().height(),
            cap: self.registered.preprocessing_cap().roots().to_vec(),
            verifier: Arc::new(self.registered.verifier()),
        }
    }
    pub fn prove(&self) -> Result<NodeProof> {
        let proof = self
            .registered
            .prove(&self.public, &self.witness)
            .map_err(err)?;
        self.registered.verify(&proof, &self.public).map_err(err)?;
        Ok(NodeProof {
            public: self.public.clone(),
            proof,
        })
    }
}
pub struct NodeProof {
    pub public: Vec<Val>,
    pub proof: BatchProof<Config>,
}
#[derive(Clone)]
pub struct NodeKey {
    spec: Spec,
    height: usize,
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
}
impl NodeKey {
    pub fn role(&self) -> Role {
        self.spec.descriptor.role()
    }
    pub fn operation_index(&self) -> usize {
        self.spec.operation as usize
    }
    fn air(&self) -> Result<MachineAir> {
        Ok(MachineAir::new(
            ProgramBuilder::new(PUBLIC_VALUES)
                .map_err(err)?
                .finish(Some(self.height))
                .map_err(err)?,
        ))
    }
    pub fn verify(&self, proof: &NodeProof) -> Result<()> {
        require(
            proof.public.len() == PUBLIC_VALUES,
            "producer proof public width",
        )?;
        self.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(err)
    }
}
#[derive(Clone, Copy)]
pub struct Artifact<'a> {
    pub key: &'a NodeKey,
    pub proof: &'a NodeProof,
}
impl Artifact<'_> {
    pub(crate) fn compile_roots(
        self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        operation: usize,
        role: Role,
        transcript: Option<&TranscriptAir>,
        context: &ContextWires,
        node_manifest: &[Wire; 4],
    ) -> Result<[[Wire; 4]; 2]> {
        let expected = match role {
            Role::AlphaUniform => Descriptor::AlphaUniform,
            Role::AlphaSparse => Descriptor::AlphaSparse,
            Role::HashXTranscriptShake => Descriptor::HashX(
                transcript
                    .ok_or_else(|| Error("missing trusted HashX descriptor".into()))?
                    .parts()
                    .to_vec(),
            ),
        };
        require(
            self.key.operation_index() == operation && self.key.spec.descriptor == expected,
            "substituted producer operation/role/descriptor",
        )?;
        require(
            self.proof.public.len() == PUBLIC_VALUES,
            "producer proof public width",
        )?;
        let public = inputs.bases(b, &self.proof.public).map_err(err)?;
        let cap: Vec<_> = self
            .key
            .cap
            .iter()
            .map(|root| root.map(|value| b.constant(value)))
            .collect();
        verifier::batch::verify(
            b,
            inputs,
            &self.key.air()?,
            &public,
            &cap,
            &self.proof.proof,
        )
        .map_err(err)?;
        bind_context(b, &public, context, node_manifest);
        Ok([
            public[INPUT..OUTPUT].try_into().map_err(err)?,
            public[OUTPUT..].try_into().map_err(err)?,
        ])
    }
}
pub struct ProvenBranch {
    pub key: NodeKey,
    pub proof: NodeProof,
    pub cache_hit: bool,
}

mod cache;
#[cfg(test)]
mod tests;
