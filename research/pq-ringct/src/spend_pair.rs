//! Ordered aggregation of two complete registered MatRiCT graph proofs.
//! Both complete graph verifiers are emitted in the same parent program.
//! This proves the standalone relation; ledger membership and spent-state
//! rules must still be supplied by the eventual transaction protocol.
use crate::{
    graph_tree::{ContextWires, GraphContext, NodeKey, NodeProof},
    recursive_aggregation::{self as aggregation, LeafStatement, PUBLIC_VALUES, ROOT},
};
use lattica_prover_p3::block_v2::{
    machine::{
        analysis,
        backend::{RegisteredProgram, RegisteredVerifier},
        program::{Val, Wire},
        verifier::ProofInputs,
        MachineAir, Program, ProgramBuilder,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

#[derive(Debug)]
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

pub struct Child<'a> {
    pub key: &'a NodeKey,
    pub proof: &'a NodeProof,
    pub context: &'a GraphContext,
}
pub struct CompiledPair {
    profile: [u8; 32],
    program: std::sync::Arc<Program>,
    public: [Val; PUBLIC_VALUES],
    witness: Vec<Val>,
}
fn statement(child: &Child<'_>) -> LeafStatement {
    LeafStatement {
        profile: child.key.profile_label(),
        context: child.context.context,
        digest: child.context.statement.map(|v| v.as_canonical_u64()),
    }
}
fn assert_constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let constant = b.constant(value);
    b.assert_equal(wire, constant);
}

pub fn compile(children: [Child<'_>; 2]) -> Result<CompiledPair> {
    // Early actual verification is diagnostic/admission. The full recursive
    // verifiers below are mandatory even after this native check succeeds.
    for child in &children {
        child
            .key
            .verify_complete(child.proof, child.context)
            .map_err(err)?;
    }
    let statements = children.each_ref().map(statement);
    let profile = statements[0].profile;
    let public = aggregation::expected_pair(&statements[0], &statements[1]).map_err(err)?;
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(err)?;
    let outer: [Wire; PUBLIC_VALUES] = (0..PUBLIC_VALUES)
        .map(|i| b.public(i).map_err(err))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(err)?;
    for (i, chunk) in profile.chunks_exact(4).enumerate() {
        assert_constant(
            &mut b,
            outer[i],
            Val::from_u32(u32::from_le_bytes(chunk.try_into().unwrap())),
        );
    }
    for &wire in &outer[8..16] {
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(&mut b, wire, 32)
            .map_err(err)?;
    }
    for (index, value) in [
        (aggregation::MODE, aggregation::PAIR_MODE),
        (aggregation::LEVEL, 1),
        (aggregation::COUNT, 2),
    ] {
        assert_constant(&mut b, outer[index], Val::from_u64(value));
    }
    let mut inputs = ProofInputs::default();
    let mut roots = Vec::with_capacity(8);
    for child in &children {
        let digest: [Wire; 4] = inputs
            .bases(&mut b, &child.context.statement)
            .map_err(err)?
            .try_into()
            .map_err(err)?;
        let node_manifest = inputs
            .bases(&mut b, &child.context.node_manifest)
            .map_err(err)?
            .try_into()
            .map_err(err)?;
        let expected = ContextWires {
            context: outer[8..16].try_into().unwrap(),
            statement: digest,
            node_manifest,
        };
        // NodeKey's trusted registration pins its profile. expected_pair above
        // checked that both registered profiles equal the parent's constant.
        child
            .key
            .compile_complete(&mut b, &mut inputs, child.proof, &expected)
            .map_err(err)?;
        roots.extend(digest);
    }
    let mut fields = vec![b.constant(Val::ONE), b.constant(Val::TWO)];
    fields.extend(roots);
    let digest = b.hash_fields(aggregation::PAIR_DOMAIN, &fields);
    for i in 0..4 {
        b.assert_equal(digest[i], outer[ROOT + i]);
    }
    Ok(CompiledPair {
        profile,
        program: std::sync::Arc::new(b.finish(None).map_err(err)?),
        public,
        witness: inputs.values,
    })
}
impl CompiledPair {
    pub fn geometry(&self) -> Result<crate::component_tree::Geometry> {
        let report = analysis::analyze(&MachineAir::from_shared_program(std::sync::Arc::clone(&self.program))).map_err(err)?;
        Ok(crate::component_tree::Geometry {
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
    pub fn evaluate(&self) -> Result<()> {
        MachineAir::from_shared_program(std::sync::Arc::clone(&self.program))
            .trace(&self.public, &self.witness)
            .map_err(err)?;
        Ok(())
    }
    pub fn prepare(self, memory_budget: u64) -> Result<PreparedPair> {
        let registered =
            RegisteredProgram::new_with_memory_budget(MachineAir::from_shared_program(self.program), memory_budget)
                .map_err(err)?;
        Ok(PreparedPair {
            profile: self.profile,
            registered,
            public: self.public,
            witness: self.witness,
        })
    }
}
pub struct PairProof {
    pub public: [Val; PUBLIC_VALUES],
    pub proof: BatchProof<Config>,
}
pub struct PairKey {
    profile: [u8; 32],
    verifier: RegisteredVerifier,
}
impl PairKey {
    pub fn verify_expected(
        &self,
        artifact: &PairProof,
        statements: [&LeafStatement; 2],
    ) -> Result<()> {
        if statements[0].profile != self.profile
            || artifact.public
                != aggregation::expected_pair(statements[0], statements[1]).map_err(err)?
        {
            return Err(Error("unexpected pair profile/context/order/root".into()));
        }
        self.verifier
            .verify(&artifact.proof, &artifact.public)
            .map_err(err)
    }
}
pub struct PreparedPair {
    profile: [u8; 32],
    registered: RegisteredProgram,
    public: [Val; PUBLIC_VALUES],
    witness: Vec<Val>,
}
impl PreparedPair {
    pub fn key(&self) -> PairKey {
        PairKey {
            profile: self.profile,
            verifier: self.registered.verifier(),
        }
    }
    pub fn prove(&self) -> Result<PairProof> {
        let proof = self
            .registered
            .prove(&self.public, &self.witness)
            .map_err(err)?;
        self.registered.verify(&proof, &self.public).map_err(err)?;
        Ok(PairProof {
            public: self.public,
            proof,
        })
    }
}
