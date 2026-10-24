//! Research-only direct-spend experiments. Nothing here is a production verifier.
//!
//! A successful host relation check is never a proof. Ring proof orchestration is
//! deliberately unavailable until compiler admission and complete proof coverage
//! have been qualified; see [`ring::prove`]. The note profile reuses the existing
//! join-split AIR without changing its parameters.

pub mod note;
pub mod ring;
#[cfg(feature = "ring-circuit")]
pub mod ring_circuit;
mod ring_native;

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use serde::Serialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const INPUTS: usize = 2;
pub const OUTPUTS: usize = 2;
pub const VALUE_BITS: usize = 52;
pub const VALUE_LIMIT: u64 = 1 << VALUE_BITS;
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Profile {
    RingDirectV1,
    PrivateNoteDirectV1,
}

impl Profile {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RingDirectV1 => "lattica/research/ring-direct-v1/n10/in2/out2/bits52",
            Self::PrivateNoteDirectV1 => {
                "lattica/research/private-note-direct-v1/depth32/in2/out2/bits52"
            }
        }
    }
}

/// Public experiment/ledger identity. Callers must supply the expected context
/// independently of any received artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context(pub [u8; 32]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    Profile,
    Context,
    Geometry,
    NonCanonical,
    Range,
    Balance,
    DuplicateSpend,
    Ownership,
    Membership,
    Opening,
    Asset,
    UnsupportedIssuance,
    SamplingExhausted,
    ResourceLimit,
    IncompleteProofCoverage,
    ProofRejected,
    Backend(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub(crate) fn shake(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(bytes);
    let mut reader = h.finalize_xof();
    let mut result = vec![0; count];
    reader.read(&mut result);
    result
}

pub fn context_binding(profile: Profile, context: Context) -> [Goldilocks; 4] {
    let mut bytes = profile.tag().as_bytes().to_vec();
    bytes.extend_from_slice(&context.0);
    let digest = shake(&bytes, 32);
    std::array::from_fn(|i| {
        Goldilocks::from_u64(
            u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().unwrap()) % GOLDILOCKS_MODULUS,
        )
    })
}

pub(crate) fn amounts(input: [u64; 2], output: [u64; 2]) -> Result<(), Error> {
    if input.into_iter().chain(output).any(|v| v >= VALUE_LIMIT) {
        return Err(Error::Range);
    }
    // Do not permit field wraparound or u64 overflow, even on malformed inputs.
    if input.into_iter().map(u128::from).sum::<u128>()
        != output.into_iter().map(u128::from).sum::<u128>()
    {
        return Err(Error::Balance);
    }
    Ok(())
}

pub(crate) fn cpu_request() -> lattica_prover_p3::proving::Request {
    lattica_prover_p3::proving::Request {
        policy: lattica_prover_p3::proving::Policy::CpuRequired,
        emit_report: false,
    }
}
