use super::*;
use sha3::digest::{ExtendableOutput, Update, XofReader};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Selection { N3, N4 }
impl Selection {
    pub const fn transactions(self) -> usize { match self { Self::N3 => 3, Self::N4 => 4 } }
}

/// Owned expected statements obtained independently of every proof envelope.
/// No mutable accessor, artifact, preprocessing cap or program can supply them.
pub struct ExpectedBatch {
    pub(super) selection: Selection,
    pub(super) context: Context,
    pub(super) statements: Vec<Statement>,
    pub(super) public: [Val; PUBLICS],
}
impl ExpectedBatch {
    pub fn new(selection: Selection, context: Context, statements: Vec<Statement>) -> Result<Self, Error> {
        if statements.len() != selection.transactions() || statements.capacity() > MAX_CHILDREN {
            return Err(Error::Geometry);
        }
        let mut bindings = [[Val::ZERO; PUBLICS]; MAX_CHILDREN];
        for (index, statement) in statements.iter().enumerate() {
            statement.admit(context)?;
            if statement.ring.capacity() != crate::ring::RING_PAIRS { return Err(Error::ResourceLimit); }
            if statement.setup_seed != statements[0].setup_seed { return Err(Error::Context); }
            let binding = artifact::statement_binding(statement);
            if bindings[..index].contains(&binding) || statements[..index].iter().any(|prior| {
                prior.serials.iter().any(|serial| statement.serials.contains(serial))
            }) { return Err(Error::DuplicateSpend); }
            bindings[index] = binding;
        }
        let mut hash = sha3::Shake256::default();
        hash.update(b"lattica/research/direct-ring/fixed-flat-aggregate/public/v1");
        hash.update(&(selection.transactions() as u64).to_le_bytes());
        hash.update(&artifact::profile_digest(REPRESENTATION));
        hash.update(&context.0);
        hash.update(&statements[0].setup_seed);
        for (index, statement) in statements.iter().enumerate() {
            hash.update(&(index as u64).to_le_bytes());
            for word in bindings[index] { hash.update(&word.as_canonical_u64().to_le_bytes()); }
            for serial in statement.serials { hash.update(&serial); }
        }
        let mut bytes = [0; 32];
        hash.finalize_xof().read(&mut bytes);
        let public = std::array::from_fn(|i| Val::from_u64(
            u64::from_le_bytes(bytes[8*i..8*i+8].try_into().expect("fixed binding lane")) % crate::GOLDILOCKS_MODULUS));
        Ok(Self { selection, context, statements, public })
    }
    pub fn selection(&self) -> Selection { self.selection }
    pub fn context(&self) -> Context { self.context }
    pub fn public_binding(&self) -> [Val; PUBLICS] { self.public }

    pub(super) fn owned_bytes(&self) -> Result<usize, Failure> {
        let mut bytes = self.statements.capacity().checked_mul(size_of::<Statement>())
            .ok_or_else(|| Failure::new("batch", "statement storage overflow"))?;
        for statement in &self.statements {
            bytes = sum(&[bytes, statement.ring.capacity() * size_of::<[crate::ring::Account; crate::INPUTS]>()])?;
        }
        Ok(bytes)
    }
}

/// Move-only native witness owners. Every witness is destroyed/zeroized when
/// its child is compiled for the final time, including all failure paths.
pub struct BatchInput {
    pub(super) expected: ExpectedBatch,
    pub(super) witnesses: Vec<Witness>,
}
impl BatchInput {
    pub fn new(expected: ExpectedBatch, witnesses: Vec<Witness>) -> Result<Self, Error> {
        if witnesses.len() != expected.selection.transactions() || witnesses.capacity() > MAX_CHILDREN {
            return Err(Error::Geometry);
        }
        for witness in &witnesses { crate::ring::admit_witness(witness)?; }
        Ok(Self { expected, witnesses })
    }
}
