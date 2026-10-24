use super::*;
use lattica_prover_p3::block_v2::{
    machine::{
        analysis,
        backend::{RegisteredProgram, RegisteredVerifier},
        verifier::{self, ProofInputs},
        MachineAir, Program,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;

mod cache;
mod prover;
pub use prover::{GraphProver, ProofCache, ProvenNode};

/// Private construction guarantees that a leaf consumed its exact same-scope
/// coverage check, or a parent emitted both actual registered child verifiers.
pub struct CompiledNode {
    pub(super) spec: Spec,
    pub(super) program: Arc<Program>,
    pub(super) public: Vec<Val>,
    pub(super) witness: Vec<Val>,
}
impl CompiledNode {
    pub fn program(&self) -> &Program {
        &self.program
    }
    pub fn public_values(&self) -> &[Val] {
        &self.public
    }
    pub fn geometry(&self) -> Result<Geometry> {
        let report = analysis::analyze(&MachineAir::from_shared_program(Arc::clone(&self.program))).map_err(err)?;
        Ok(Geometry {
            active_rows: self.program.active_rows(),
            padded_rows: self.program.height(),
            wires: self.program.wire_count(),
            main_width: report.main_width,
            preprocessed_width: report.preprocessed_width,
            permutation_width_base: report.permutation_width_base,
            quotient_chunks: report.quotient_chunks,
            constraints: report.constraints,
            max_constraint_degree: report.max_constraint_degree,
            fri_ali_bits: report.fri_ali_bits,
            retained_lde_bytes: report.retained_lde_bytes,
        })
    }
    /// Diagnostic witness evaluation; does not produce a proof or verified key.
    pub fn evaluate(&self) -> Result<()> {
        MachineAir::from_shared_program(Arc::clone(&self.program))
            .trace(&self.public, &self.witness)
            .map_err(err)?;
        Ok(())
    }
    pub fn prepare(self, memory_budget: u64) -> Result<PreparedNode> {
        require(
            self.geometry()?.retained_lde_bytes <= memory_budget,
            "graph node exceeds retained-LDE budget before registration",
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
/// Only a registered compiled leaf/parent can construct a key. An arbitrary
/// program or preprocessing cap cannot be wrapped as a graph coverage key.
#[derive(Clone)]
pub struct NodeKey {
    spec: Spec,
    height: usize,
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
}
impl NodeKey {
    /// Domain label fixed by the caller's trusted graph plan registration.
    pub fn profile_label(&self) -> [u8; 32] {
        self.spec.plan.label
    }

    fn air(&self) -> Result<MachineAir> {
        Ok(MachineAir::new(
            ProgramBuilder::new(PUBLIC_VALUES)
                .map_err(err)?
                .finish(Some(self.height))
                .map_err(err)?,
        ))
    }
    pub fn span(&self) -> (usize, usize) {
        (self.spec.first as usize, self.spec.count as usize)
    }
    pub fn verify(&self, proof: &NodeProof) -> Result<()> {
        require(
            proof.public.len() == PUBLIC_VALUES,
            "graph proof public width",
        )?;
        self.verifier
            .verify(&proof.proof, &proof.public)
            .map_err(err)
    }
    /// Accepts only a full [0, leaf_count) proof under this trusted plan and
    /// caller-provided context, statement and global node-root manifest.
    pub fn verify_complete(&self, proof: &NodeProof, context: &GraphContext) -> Result<()> {
        require(self.spec.complete(), "incomplete graph coverage")?;
        require(
            proof.public == header(&self.spec, context),
            "unexpected graph context, statement or node manifest",
        )?;
        self.verify(proof)
    }
    /// Emit the actual complete graph-root verifier in an outer coordinator.
    /// The private registered spec must cover every leaf; all expected roots
    /// are constrained against that same verified child's public values.
    pub fn compile_complete(
        &self,
        b: &mut lattica_prover_p3::block_v2::machine::program::ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        proof: &NodeProof,
        expected: &ContextWires,
    ) -> Result<()> {
        require(self.spec.complete(), "incomplete graph coverage")?;
        let public = self.emit(b, inputs, proof)?;
        bind_context(b, &public, expected);
        Ok(())
    }
    fn emit(
        &self,
        b: &mut lattica_prover_p3::block_v2::machine::program::ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        proof: &NodeProof,
    ) -> Result<Vec<Wire>> {
        require(
            proof.public.len() == PUBLIC_VALUES,
            "graph child public width",
        )?;
        let public = inputs.bases(b, &proof.public).map_err(err)?;
        let cap: Vec<_> = self
            .cap
            .iter()
            .map(|root| root.map(|v| b.constant(v)))
            .collect();
        verifier::batch::verify(b, inputs, &self.air()?, &public, &cap, &proof.proof)
            .map_err(err)?;
        Ok(public)
    }
}
pub(super) fn bind_context(
    b: &mut lattica_prover_p3::block_v2::machine::program::ScopedProgramBuilder<'_>,
    public: &[Wire],
    expected: &ContextWires,
) {
    for (actual, expected) in public[CONTEXT..CONTEXT + 8]
        .iter()
        .chain(&public[STATEMENT..STATEMENT + 4])
        .chain(&public[NODE_MANIFEST..NODE_MANIFEST + 4])
        .zip(
            expected
                .context
                .iter()
                .chain(&expected.statement)
                .chain(&expected.node_manifest),
        )
    {
        b.assert_equal(*actual, *expected);
    }
}
pub(super) fn bind_merge(b: &mut ProgramBuilder, outer: &[Wire], left: &[Wire], right: &[Wire]) {
    for i in 0..PUBLIC_VALUES {
        if ![FIRST, COUNT, LEVEL].contains(&i) {
            b.assert_equal(left[i], outer[i]);
            b.assert_equal(right[i], outer[i]);
        }
    }
    b.assert_equal(left[FIRST], outer[FIRST]);
    let adjacent = b.add(left[FIRST], left[COUNT]);
    b.assert_equal(adjacent, right[FIRST]);
    let count = b.add(left[COUNT], right[COUNT]);
    b.assert_equal(count, outer[COUNT]);
}
fn merge_impl(left: &NodeKey, right: &NodeKey, children: [&NodeProof; 2]) -> Result<CompiledNode> {
    let spec = Spec::merge(&left.spec, &right.spec)?;
    require(
        children.iter().all(|p| p.public.len() == PUBLIC_VALUES),
        "graph child public width",
    )?;
    let mut public = children[0].public.clone();
    public[FIRST] = Val::from_u32(spec.first);
    public[COUNT] = Val::from_u32(spec.count);
    public[LEVEL] = Val::from_u32(spec.level);
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
    let outer = public_wires(&mut b, &spec)?;
    let mut inputs = ProofInputs::default();
    let a = left.emit(&mut b, &mut inputs, children[0])?;
    let z = right.emit(&mut b, &mut inputs, children[1])?;
    bind_merge(&mut b, &outer, &a, &z);
    Ok(CompiledNode {
        spec,
        program: Arc::new(b.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}
/// Native checks are early diagnostics only. Both full child STARK verifiers
/// and every shared-root/interval equality are emitted into the parent circuit.
pub fn compile_merge(
    left: &NodeKey,
    right: &NodeKey,
    children: [&NodeProof; 2],
) -> Result<CompiledNode> {
    Spec::merge(&left.spec, &right.spec)?;
    left.verify(children[0])?;
    right.verify(children[1])?;
    merge_impl(left, right, children)
}

#[cfg(all(test, feature = "recursive-wide", feature = "native-matrict"))]
mod closure_tests;
