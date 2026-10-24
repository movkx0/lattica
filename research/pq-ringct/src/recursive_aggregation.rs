//! Actual recursive aggregation of a *trusted, supplied* machine predicate.
//!
//! This is generic proof plumbing, not a MatRiCT verifier. A caller must register
//! the complete constrained verifier; a native acceptance flag, hash receipt, or
//! unconstrained statement is not a substitute. Parent proofs execute the full
//! P3 batch verifier twice, using preprocessing caps pinned by local registration.

use lattica_prover_p3::block_v2::{
    commitment,
    machine::{
        backend::{RegisteredProgram, RegisteredVerifier},
        program::{ProofInputs, Val},
        verifier, MachineAir, Program, ProgramBuilder, Wire,
    },
    profile::Config,
};
use p3_batch_stark::BatchProof;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use std::fmt;

pub const PUBLIC_VALUES: usize = 23;
pub const MODE: usize = 16;
pub const LEVEL: usize = 17;
pub const COUNT: usize = 18;
pub const ROOT: usize = 19;
pub const LEAF_MODE: u64 = 1;
pub const PAIR_MODE: u64 = 3;
pub const STATEMENT_DOMAIN: u64 = 0x4d525143_53544d31;
pub const PAIR_DOMAIN: u64 = 0x4d525143_50414931;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationError(pub String);
impl fmt::Display for AggregationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AggregationError {}
type Result<T> = std::result::Result<T, AggregationError>;
fn error(value: impl fmt::Debug) -> AggregationError {
    AggregationError(format!("{value:?}"))
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(AggregationError(message.into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafStatement {
    pub profile: [u8; 32],
    pub context: [u8; 32],
    pub digest: [u64; 4],
}

fn identifier_words(bytes: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        Val::from_u32(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}

/// Canonical little-endian words. The final word is zero-padded, while the exact
/// byte length enters the digest to distinguish a suffix of actual zero bytes.
pub fn statement_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        })
        .collect()
}

impl LeafStatement {
    /// GPU digest with the exact byte-length and little-endian word framing.
    #[cfg(feature = "opencl")]
    pub fn from_bytes_on_gpu(
        profile: [u8; 32],
        context: [u8; 32],
        bytes: &[u8],
        operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
    ) -> Result<Self> {
        require(
            bytes.len() <= u32::MAX as usize,
            "statement exceeds u32 byte limit",
        )?;
        let count = 1 + bytes.len().div_ceil(4);
        operations.admit_field_chunks(count).map_err(error)?;
        let mut fields = Vec::with_capacity(count);
        fields.push(bytes.len() as u64);
        for chunk in bytes.chunks(4) {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            fields.push(u32::from_le_bytes(word) as u64);
        }
        let digest = operations
            .commit_field_chunks([STATEMENT_DOMAIN, count as u64, 0, 0], &fields)
            .map_err(error)?;
        Ok(Self {
            profile,
            context,
            digest,
        })
    }

    pub fn from_bytes(profile: [u8; 32], context: [u8; 32], bytes: &[u8]) -> Result<Self> {
        require(
            bytes.len() <= u32::MAX as usize,
            "statement exceeds u32 byte limit",
        )?;
        let mut fields = Vec::with_capacity(1 + bytes.len().div_ceil(4));
        fields.push(bytes.len() as u64);
        fields.extend(statement_words(bytes).into_iter().map(u64::from));
        let digest = commitment::hash_fields(STATEMENT_DOMAIN, &fields).map_err(error)?;
        Ok(Self {
            profile,
            context,
            digest,
        })
    }

    pub fn public(&self) -> Result<[Val; PUBLIC_VALUES]> {
        require(
            self.digest.iter().all(|&x| x < commitment::MODULUS),
            "noncanonical statement digest",
        )?;
        let mut result = [Val::ZERO; PUBLIC_VALUES];
        result[..8].copy_from_slice(&identifier_words(&self.profile));
        result[8..16].copy_from_slice(&identifier_words(&self.context));
        result[MODE] = Val::from_u64(LEAF_MODE);
        result[COUNT] = Val::ONE;
        result[ROOT..].copy_from_slice(&self.digest.map(Val::from_u64));
        Ok(result)
    }
}

pub struct LeafPublicWires {
    pub context: [Wire; 8],
    pub digest: [Wire; 4],
}

fn assert_constant(b: &mut ProgramBuilder, wire: Wire, value: Val) {
    let constant = b.constant(value);
    b.assert_equal(wire, constant);
}

fn public_header(
    b: &mut ProgramBuilder,
    profile: [u8; 32],
    mode: u64,
    level: u64,
    count: u64,
) -> Result<[Wire; PUBLIC_VALUES]> {
    let public = (0..PUBLIC_VALUES)
        .map(|i| b.public(i).map_err(error))
        .collect::<Result<Vec<_>>>()?;
    let public: [Wire; PUBLIC_VALUES] = public.try_into().map_err(error)?;
    for (wire, value) in public[..8].iter().zip(identifier_words(&profile)) {
        assert_constant(b, *wire, value);
    }
    for &wire in &public[8..16] {
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(b, wire, 32)
            .map_err(error)?;
    }
    for (index, value) in [(MODE, mode), (LEVEL, level), (COUNT, count)] {
        assert_constant(b, public[index], Val::from_u64(value));
    }
    Ok(public)
}

/// Call this from the actual leaf verifier compiler, then use these same context
/// wires in its cryptographic transcript and bind the complete public statement.
pub fn bind_leaf_header(b: &mut ProgramBuilder, profile: [u8; 32]) -> Result<LeafPublicWires> {
    let public = public_header(b, profile, LEAF_MODE, 0, 1)?;
    Ok(LeafPublicWires {
        context: public[8..16].try_into().unwrap(),
        digest: public[ROOT..].try_into().unwrap(),
    })
}

/// Bind canonical input words, not a prover-supplied digest hint. These words must
/// also feed the full leaf predicate. This helper checks ranges and final padding.
pub fn bind_statement_words(
    b: &mut ProgramBuilder,
    public: &LeafPublicWires,
    words: &[Wire],
    byte_len: usize,
) -> Result<()> {
    require(
        byte_len <= u32::MAX as usize && words.len() == byte_len.div_ceil(4),
        "statement word count mismatch",
    )?;
    for (index, &word) in words.iter().enumerate() {
        let used_bits = if index + 1 == words.len() && byte_len % 4 != 0 {
            8 * (byte_len % 4)
        } else {
            32
        };
        lattica_prover_p3::block_v2::machine::pq_modular::bounded_bits(b, word, used_bits as u32)
            .map_err(error)?;
    }
    let mut fields = Vec::with_capacity(1 + words.len());
    fields.push(b.constant(Val::from_usize(byte_len)));
    fields.extend_from_slice(words);
    let digest = b.hash_fields(STATEMENT_DOMAIN, &fields);
    for (actual, expected) in digest.into_iter().zip(public.digest) {
        b.assert_equal(actual, expected);
    }
    Ok(())
}

/// Public artifacts only. This type contains no wallet spending witness.
pub struct LeafProof {
    pub public: [Val; PUBLIC_VALUES],
    pub proof: BatchProof<Config>,
}

/// Source-trusted predicate registration. Construction does not certify that the
/// supplied program implements MatRiCT (or any other particular spend relation).
pub struct RegisteredLeaf {
    registered: RegisteredProgram,
    profile: [u8; 32],
}

impl RegisteredLeaf {
    pub fn new(program: Program, profile: [u8; 32], memory_budget: u64) -> Result<Self> {
        require(
            program.public_values() == PUBLIC_VALUES,
            "leaf public layout mismatch",
        )?;
        let registered =
            RegisteredProgram::new_with_memory_budget(MachineAir::new(program), memory_budget)
                .map_err(error)?;
        Ok(Self {
            registered,
            profile,
        })
    }

    pub fn program(&self) -> &Program {
        self.registered.air().program()
    }
    pub fn profile(&self) -> [u8; 32] {
        self.profile
    }

    pub fn prove(&self, statement: &LeafStatement, witness: &[Val]) -> Result<LeafProof> {
        require(statement.profile == self.profile, "leaf profile mismatch")?;
        let public = statement.public()?;
        let proof = self.registered.prove(&public, witness).map_err(error)?;
        let artifact = LeafProof { public, proof };
        self.verify(&artifact)?;
        Ok(artifact)
    }

    pub fn verify(&self, artifact: &LeafProof) -> Result<()> {
        validate_leaf_public(&artifact.public, self.profile)?;
        self.registered
            .verify(&artifact.proof, &artifact.public)
            .map_err(error)
    }
}

fn validate_leaf_public(public: &[Val; PUBLIC_VALUES], profile: [u8; 32]) -> Result<()> {
    require(
        public[..8] == identifier_words(&profile),
        "leaf profile mismatch",
    )?;
    require(
        public[8..16]
            .iter()
            .all(|x| x.as_canonical_u64() <= u32::MAX as u64),
        "noncanonical context limb",
    )?;
    require(
        public[MODE].as_canonical_u64() == LEAF_MODE
            && public[LEVEL] == Val::ZERO
            && public[COUNT] == Val::ONE,
        "leaf mode/level/count mismatch",
    )
}

/// Ordered two-leaf root expected from public statements independently of proofs.
pub fn expected_pair(left: &LeafStatement, right: &LeafStatement) -> Result<[Val; PUBLIC_VALUES]> {
    pair_public(&left.public()?, &right.public()?, left.profile)
}

fn pair_public(
    left: &[Val; PUBLIC_VALUES],
    right: &[Val; PUBLIC_VALUES],
    profile: [u8; 32],
) -> Result<[Val; PUBLIC_VALUES]> {
    validate_leaf_public(left, profile)?;
    validate_leaf_public(right, profile)?;
    require(left[..16] == right[..16], "child profile/context mismatch")?;
    let mut fields = vec![1, 2];
    fields.extend(left[ROOT..].iter().map(|x| x.as_canonical_u64()));
    fields.extend(right[ROOT..].iter().map(|x| x.as_canonical_u64()));
    let digest = commitment::hash_fields(PAIR_DOMAIN, &fields).map_err(error)?;
    let mut result = *left;
    result[MODE] = Val::from_u64(PAIR_MODE);
    result[LEVEL] = Val::ONE;
    result[COUNT] = Val::TWO;
    result[ROOT..].copy_from_slice(&digest.map(Val::from_u64));
    Ok(result)
}

struct CompiledPair {
    program: Program,
    witness: Vec<Val>,
}

#[derive(Clone, Debug)]
pub struct PairGeometry {
    pub active_rows: usize,
    pub padded_rows: usize,
    pub wires: usize,
    /// Existing P3 analysis lower bound, not a complete RSS/phase peak promise.
    pub retained_lde_bytes: u64,
}

/// Compile the actual recursive-verifier shape without allocating its LDE.
pub fn pair_geometry(leaf: &RegisteredLeaf) -> Result<PairGeometry> {
    let template = verifier::template::batch(leaf.registered.air()).map_err(error)?;
    let dummy = [Val::ZERO; PUBLIC_VALUES];
    let compiled = compile_pair(leaf, [&dummy, &dummy], [&template, &template])?;
    let result = PairGeometry {
        active_rows: compiled.program.active_rows(),
        padded_rows: compiled.program.height(),
        wires: compiled.program.wire_count(),
        retained_lde_bytes: lattica_prover_p3::block_v2::machine::analysis::analyze(
            &MachineAir::new(compiled.program),
        )
        .map_err(error)?
        .retained_lde_bytes,
    };
    Ok(result)
}

fn compile_pair(
    leaf: &RegisteredLeaf,
    children: [&[Val; PUBLIC_VALUES]; 2],
    proofs: [&BatchProof<Config>; 2],
) -> Result<CompiledPair> {
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).map_err(error)?;
    let public = public_header(&mut b, leaf.profile, PAIR_MODE, 1, 2)?;
    // Constants come from local registration, never from proof-supplied metadata.
    let cap: Vec<[Wire; 4]> = leaf
        .registered
        .preprocessing_cap()
        .roots()
        .iter()
        .map(|digest| digest.map(|value| b.constant(value)))
        .collect();
    let mut inputs = ProofInputs::default();
    let mut child_wires = Vec::with_capacity(2);
    for index in 0..2 {
        let fields = inputs.bases(&mut b, children[index]).map_err(error)?;
        for i in 0..16 {
            b.assert_equal(fields[i], public[i]);
        }
        for (offset, value) in [(MODE, LEAF_MODE), (LEVEL, 0), (COUNT, 1)] {
            assert_constant(&mut b, fields[offset], Val::from_u64(value));
        }
        verifier::batch::verify(
            &mut b,
            &mut inputs,
            leaf.registered.air(),
            &fields,
            &cap,
            proofs[index],
        )
        .map_err(error)?;
        child_wires.push(fields);
    }
    let mut fields = vec![b.constant(Val::ONE), b.constant(Val::TWO)];
    fields.extend_from_slice(&child_wires[0][ROOT..]);
    fields.extend_from_slice(&child_wires[1][ROOT..]);
    let root = b.hash_fields(PAIR_DOMAIN, &fields);
    for i in 0..4 {
        b.assert_equal(root[i], public[ROOT + i]);
    }
    let program = b.finish(None).map_err(error)?;
    Ok(CompiledPair {
        program,
        witness: inputs.values,
    })
}

pub struct PairProof {
    pub public: [Val; PUBLIC_VALUES],
    pub proof: BatchProof<Config>,
}

/// One registered parent program verifying two proofs of the pinned leaf program.
/// This initial two-level path permits different leaf and parent heights. It is
/// not a shared-height fixed point or an arbitrary-capacity block registry.
pub struct PreparedPair {
    registered: RegisteredProgram,
    leaf_program_id: [u64; 4],
    leaf_cap: Vec<[Val; 4]>,
    profile: [u8; 32],
}

impl PreparedPair {
    pub fn new(leaf: &RegisteredLeaf, memory_budget: u64) -> Result<Self> {
        let template = verifier::template::batch(leaf.registered.air()).map_err(error)?;
        let dummy = [Val::ZERO; PUBLIC_VALUES];
        let compiled = compile_pair(leaf, [&dummy, &dummy], [&template, &template])?;
        // Templates establish shape only. They never become valid artifacts.
        let registered = RegisteredProgram::new_with_memory_budget(
            MachineAir::new(compiled.program),
            memory_budget,
        )
        .map_err(error)?;
        Ok(Self {
            registered,
            leaf_program_id: leaf.registered.id(),
            leaf_cap: leaf.registered.preprocessing_cap().roots().to_vec(),
            profile: leaf.profile,
        })
    }

    pub fn program(&self) -> &Program {
        self.registered.air().program()
    }
    pub fn verifier(&self) -> RegisteredVerifier {
        self.registered.verifier()
    }

    pub fn prove(&self, leaf: &RegisteredLeaf, children: [&LeafProof; 2]) -> Result<PairProof> {
        require(
            leaf.profile == self.profile
                && leaf.registered.id() == self.leaf_program_id
                && leaf.registered.preprocessing_cap().roots() == self.leaf_cap.as_slice(),
            "different leaf registry",
        )?;
        for child in children {
            leaf.verify(child)?;
        }
        let public = pair_public(&children[0].public, &children[1].public, self.profile)?;
        let compiled = compile_pair(
            leaf,
            [&children[0].public, &children[1].public],
            [&children[0].proof, &children[1].proof],
        )?;
        require(
            compiled.program == *self.program(),
            "recursive program shape changed",
        )?;
        let proof = self
            .registered
            .prove(&public, &compiled.witness)
            .map_err(error)?;
        self.registered.verify(&proof, &public).map_err(error)?;
        Ok(PairProof { public, proof })
    }

    /// Caller supplies expected public transaction statements, rather than trusting
    /// the aggregate's claimed root. Inner artifacts are not needed for this check.
    pub fn verify_expected(&self, proof: &PairProof, children: [&LeafStatement; 2]) -> Result<()> {
        require(
            children[0].profile == self.profile && children[1].profile == self.profile,
            "expected profile mismatch",
        )?;
        let expected = expected_pair(children[0], children[1])?;
        require(
            proof.public == expected,
            "unexpected ordered public statements",
        )?;
        self.registered
            .verify(&proof.proof, &expected)
            .map_err(error)
    }
}
