//! Versioned public artifact framing for the native MatRiCT+ experiment.
//!
//! This retains the complete verifier statement, including the full ring. It
//! supplies neither authenticated ledger references nor encrypted note delivery.
//! The generic `PublicTransaction` codec is intentionally not mapped to this
//! scheme until those protocol semantics are implemented and reviewed.
//!
//! Decoding checks framing/profile/lengths. It does not accept cryptographic
//! coefficients or proofs; call `verify` with an independently trusted context.

use std::fmt;

const MAGIC: &[u8; 8] = b"LPQMPK01";
/// Local research identifier, not a consensus or global registry assignment.
pub const PROFILE_SCHEME: u16 = 1;
pub const PROFILE_VERSION: u16 = 1;
pub const STATEMENT_BYTES: usize = 202_848;
pub const PROOF_BYTES: usize = 53_600;
pub const PACKET_BYTES: usize = 84 + STATEMENT_BYTES + PROOF_BYTES;

/// Exact UTF-8 input to the SHA3-256 parameter fingerprint below. Protocol,
/// parameter, or transcript changes require a new explicit profile version;
/// documentation formatting and source paths do not enter the fingerprint.
pub const PROFILE_DESCRIPTION: &str = concat!(
    "MatRiCT+;lattica-research-v1;N_SPENT=10;M=2;S=2;D=256;R=64;",
    "Q=167770241;QHAT=3489661057;N=4;K=4;N_BAR=4;N_HAT=5;K_HAT=5;",
    "W=44;WA=39;B_K=7525;BA_10_K=111;BRS_13_K=1219127;BETA=40;B_6=38346;",
    "BA_10_6=565;BRS_13_6=6212586;BG_0=6825771;BG_1=1137628;",
    "Z_NORM=3161803581581766;Z_OUT_NORM=135519727172;Z_0_NORM=135519727172;",
    "Z_I_NORM=165635222099;",
    "setup-qhat=correct;challenge-key=correct;packet=1;proof=packed-lsb-v1;",
    "statement=full-public-le32-v1;",
    "transcript=lattica/pq-ringct/matrict-plus-n10/fixture-v1;",
    "hash=SHAKE256;prg=AES256-CTR;sampler=failclosed-v1"
);
pub const PROFILE_PARAMETERS: [u8; 32] = [
    0x4e, 0x3c, 0x0f, 0x07, 0x41, 0x06, 0xa1, 0xf7, 0x77, 0xf6, 0xe8, 0xca, 0x98, 0x72, 0x95, 0x8d,
    0x1f, 0xc9, 0x74, 0x49, 0x15, 0xf7, 0xd8, 0x68, 0x8b, 0x6c, 0xbe, 0xc5, 0x0e, 0xa5, 0x8d, 0x58,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePacket {
    pub context: [u8; 32],
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketError {
    Length,
    Framing,
    Profile,
    Context,
    #[cfg(feature = "native-matrict")]
    Native(crate::native::NativeError),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => {
                f.write_str("native packet requires exact bounded statement and proof lengths")
            }
            Self::Framing => f.write_str("unsupported native packet framing"),
            Self::Profile => f.write_str(
                "native packet profile does not match the supported MatRiCT+ experiment",
            ),
            Self::Context => {
                f.write_str("native packet context differs from the trusted expected context")
            }
            #[cfg(feature = "native-matrict")]
            Self::Native(error) => write!(f, "native packet verification: {error}"),
        }
    }
}

impl std::error::Error for PacketError {}

impl NativePacket {
    /// Canonical framing only; a packet remains unverified after encoding.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        if self.statement.len() != STATEMENT_BYTES || self.proof.len() != PROOF_BYTES {
            return Err(PacketError::Length);
        }
        let mut bytes = Vec::with_capacity(PACKET_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&PROFILE_SCHEME.to_le_bytes());
        bytes.extend_from_slice(&PROFILE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&PROFILE_PARAMETERS);
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&(STATEMENT_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&self.statement);
        bytes.extend_from_slice(&(PROOF_BYTES as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        debug_assert_eq!(bytes.len(), PACKET_BYTES);
        Ok(bytes)
    }

    /// Rejects alternative profiles, lengths, version tags and trailing bytes
    /// before allocating the public statement and proof buffers.
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != PACKET_BYTES {
            return Err(PacketError::Length);
        }
        if &bytes[..8] != MAGIC {
            return Err(PacketError::Framing);
        }
        if bytes[8..10] != PROFILE_SCHEME.to_le_bytes()
            || bytes[10..12] != PROFILE_VERSION.to_le_bytes()
            || bytes[12..44] != PROFILE_PARAMETERS
        {
            return Err(PacketError::Profile);
        }
        let proof_length_offset = 80 + STATEMENT_BYTES;
        if bytes[76..80] != (STATEMENT_BYTES as u32).to_le_bytes()
            || bytes[proof_length_offset..proof_length_offset + 4]
                != (PROOF_BYTES as u32).to_le_bytes()
        {
            return Err(PacketError::Length);
        }
        let mut context = [0; 32];
        context.copy_from_slice(&bytes[44..76]);
        Ok(Self {
            context,
            statement: bytes[80..proof_length_offset].to_vec(),
            proof: bytes[proof_length_offset + 4..].to_vec(),
        })
    }

    /// The expected domain must come from trusted application context, never
    /// from the packet being verified. Successful proof verification still does
    /// not authenticate a ledger, reject already-spent serials, or deliver notes.
    #[cfg(feature = "native-matrict")]
    pub fn verify(&self, expected_context: &[u8; 32]) -> Result<bool, PacketError> {
        if &self.context != expected_context {
            return Err(PacketError::Context);
        }
        if self.statement.len() != STATEMENT_BYTES || self.proof.len() != PROOF_BYTES {
            return Err(PacketError::Length);
        }
        crate::native::verify(expected_context, &self.statement, &self.proof)
            .map_err(PacketError::Native)
    }
}
