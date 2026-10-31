//! Exact immutable native inputs and the allocation-free initial source census.
//! Existing encoded/decoded owners are charged by the enclosing workflow plan;
//! this view does not retroactively reserve them or create a graph.
use crate::rust_verify::{
    committed_backend::source_graph::InitialSourceFootprint, Proof, Statement,
};
use core::mem::size_of;
use sha3::{Digest, Sha3_256};

/// Holds the same owners used by both native graph construction and subsequent
/// source factories. Private fields and immutable borrows prevent rebinding
/// the allocation census to a different packet or mutated decoded witness.
pub(crate) struct InitialNativeSource<'source> {
    setup_seed: [u8; 32],
    context: [u8; 32],
    statement_bytes: &'source Vec<u8>,
    proof_bytes: &'source Vec<u8>,
    statement: &'source Statement,
    proof: &'source Proof,
    identity: [u8; 32],
    footprint: InitialSourceFootprint,
    retained_bytes: usize,
}

impl<'source> InitialNativeSource<'source> {
    pub(crate) fn new(
        setup_seed: [u8; 32],
        context: [u8; 32],
        statement_bytes: &'source Vec<u8>,
        proof_bytes: &'source Vec<u8>,
        statement: &'source Statement,
        proof: &'source Proof,
    ) -> Result<Self, &'static str> {
        let encoded = InitialSourceFootprint::encoded_owner_bytes(statement_bytes, proof_bytes)?;
        let decoded = InitialSourceFootprint::decoded_owner_bytes(statement, proof)?;
        if !statement
            .matches_encoded(statement_bytes)
            .map_err(|_| "initial statement encoding is not canonical")?
            || !proof
                .matches_encoded(proof_bytes)
                .map_err(|_| "initial proof encoding is not canonical")?
        {
            return Err("initial native encoded and decoded inputs differ");
        }
        let retained_bytes = encoded
            .checked_add(decoded)
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()))
            .ok_or("initial native source owner size overflow")?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/ringct/full-workflow/native-source/v1");
        identity.update(setup_seed);
        identity.update(context);
        identity.update((statement_bytes.len() as u64).to_le_bytes());
        identity.update(statement_bytes);
        identity.update((proof_bytes.len() as u64).to_le_bytes());
        identity.update(proof_bytes);
        Ok(Self {
            setup_seed,
            context,
            statement_bytes,
            proof_bytes,
            statement,
            proof,
            identity: identity.finalize().into(),
            footprint: InitialSourceFootprint::fixed()?,
            retained_bytes,
        })
    }

    pub(crate) fn setup_seed(&self) -> [u8; 32] {
        self.setup_seed
    }

    pub(crate) fn context(&self) -> &[u8; 32] {
        &self.context
    }

    pub(crate) fn statement_bytes(&self) -> &[u8] {
        self.statement_bytes
    }

    pub(crate) fn proof_bytes(&self) -> &[u8] {
        self.proof_bytes
    }

    pub(crate) fn statement(&self) -> &'source Statement {
        self.statement
    }

    pub(crate) fn proof(&self) -> &'source Proof {
        self.proof
    }

    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub(crate) fn footprint(&self) -> InitialSourceFootprint {
        self.footprint
    }

    /// Includes actual spare backing of every existing encoded/decoded Vec.
    /// This is additive to registry/context/driver/thread enclosing duties.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Fixed Rust values in this allocation-free identity/census helper. This
    /// is not a bound on compiled thread stacks or allocator/driver storage.
    pub(crate) fn inspection_frame_bytes() -> usize {
        2 * size_of::<Sha3_256>()
            + 2 * size_of::<InitialSourceFootprint>()
            + 4 * size_of::<[u8; 32]>()
            + size_of::<Self>()
    }
}

#[cfg(test)]
mod tests;
