use crate::Error;

/// Identifies an experimental scheme and its complete parameter specification.
/// No identifier in this codec implies that an implementation is approved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileId {
    pub scheme: u16,
    pub version: u16,
    pub parameters: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingReference {
    /// An authenticated ledger-set commitment, not an arbitrary claimed root.
    /// A verifier must authenticate it and resolve every member to its actual
    /// public key/commitment bytes, which the scheme must bind into verification.
    pub anchor: [u8; 32],
    /// Canonical ledger indices. Sorting is framing, not membership verification.
    pub members: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    pub ring: RingReference,
    /// Profile-specific linkability tag/nullifier; validated by the real backend.
    pub serial: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub commitment: Vec<u8>,
    /// Scheme-specific recipient encryption envelope, including any KEM material.
    pub encrypted_note: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTransaction {
    /// Genesis/network domain. A verifier must compare it with its trusted chain.
    pub chain_id: [u8; 32],
    pub profile: ProfileId,
    pub fee: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub body: PublicTransaction,
    /// Opaque, unverified proof bytes. Nonempty does not mean valid.
    pub proof: Vec<u8>,
}

/// Parser resource policy, independent of any scheme's security parameters.
/// Defaults are research admission ceilings, not target transaction sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_transaction_bytes: usize,
    pub max_body_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub max_ring_members: usize,
    pub max_serial_bytes: usize,
    pub max_commitment_bytes: usize,
    pub max_encrypted_note_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_transaction_bytes: 16 << 20,
            max_body_bytes: 8 << 20,
            max_proof_bytes: 8 << 20,
            max_inputs: 16,
            max_outputs: 16,
            max_ring_members: 1 << 16,
            max_serial_bytes: 4096,
            max_commitment_bytes: 4096,
            max_encrypted_note_bytes: 16384,
        }
    }
}

pub(crate) fn bounded_len(len: usize, max: usize, name: &'static str) -> Result<(), Error> {
    if len == 0 {
        return Err(Error::Empty(name));
    }
    if len > max {
        return Err(Error::Oversize(name));
    }
    u32::try_from(len).map_err(|_| Error::LengthOverflow)?;
    Ok(())
}

impl PublicTransaction {
    /// Structural checks only. Ledger membership, spentness, balance, ranges,
    /// ownership, chain/profile acceptance, and proof validity are not checked.
    pub fn validate_structure(&self, limits: &Limits) -> Result<(), Error> {
        if self.profile.scheme == 0 || self.profile.version == 0 {
            return Err(Error::InvalidProfile);
        }
        bounded_len(self.inputs.len(), limits.max_inputs, "inputs")?;
        bounded_len(self.outputs.len(), limits.max_outputs, "outputs")?;
        for (index, input) in self.inputs.iter().enumerate() {
            bounded_len(
                input.ring.members.len(),
                limits.max_ring_members,
                "ring members",
            )?;
            if input.ring.members.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(Error::NonCanonicalRing);
            }
            bounded_len(input.serial.len(), limits.max_serial_bytes, "serial")?;
            if self.inputs[..index]
                .iter()
                .any(|prior| prior.serial == input.serial)
            {
                return Err(Error::DuplicateSerial);
            }
        }
        for output in &self.outputs {
            bounded_len(
                output.commitment.len(),
                limits.max_commitment_bytes,
                "commitment",
            )?;
            bounded_len(
                output.encrypted_note.len(),
                limits.max_encrypted_note_bytes,
                "encrypted note",
            )?;
        }
        Ok(())
    }
}
