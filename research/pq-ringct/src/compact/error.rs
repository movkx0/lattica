#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Length,
    NonCanonical,
    Format,
    Profile,
    Context,
    LedgerCheckpoint,
    LedgerMembership,
    MissingAccount,
    Reference,
    Capacity,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Length => "incorrect fixed compact encoding length",
            Self::NonCanonical => "noncanonical coefficient or radix block",
            Self::Format => "unsupported compact packet framing or mode",
            Self::Profile => "compact packet has a different native profile",
            Self::Context => "compact packet differs from the trusted context",
            Self::LedgerCheckpoint => "compact packet differs from the trusted ledger checkpoint",
            Self::LedgerMembership => "account membership does not match the trusted checkpoint",
            Self::MissingAccount => "referenced account is not locally available",
            Self::Reference => "invalid account index or reference differs from the original ring",
            Self::Capacity => "fixed codec or in-memory ledger capacity exceeded",
        })
    }
}

impl std::error::Error for Error {}
