use std::fmt;

/// Structural failures only; these are not cryptographic verification results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidMagic,
    Truncated,
    TrailingBytes,
    Empty(&'static str),
    Oversize(&'static str),
    InvalidProfile,
    NonCanonicalRing,
    DuplicateSerial,
    LengthOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("unsupported transaction framing"),
            Self::Truncated => f.write_str("truncated transaction"),
            Self::TrailingBytes => f.write_str("trailing transaction bytes"),
            Self::Empty(field) => write!(f, "empty {field}"),
            Self::Oversize(field) => write!(f, "{field} exceeds the configured bound"),
            Self::InvalidProfile => f.write_str("scheme and scheme version must be nonzero"),
            Self::NonCanonicalRing => f.write_str("ring members must be strictly increasing"),
            Self::DuplicateSerial => f.write_str("duplicate input serial"),
            Self::LengthOverflow => f.write_str("transaction length cannot be represented"),
        }
    }
}

impl std::error::Error for Error {}
