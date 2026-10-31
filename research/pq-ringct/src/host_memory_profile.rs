//! Explicit research worker envelopes. Operation and cryptographic limits stay fixed.
use serde::Serialize;

pub const OPERATION_HOST_BYTES: u64 = 32 << 30;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub enum HostMemoryProfile {
    #[default]
    #[serde(rename = "standard")]
    Standard,
    #[serde(rename = "expanded-36")]
    Expanded36,
    #[serde(rename = "expanded-40")]
    Expanded40,
}

impl HostMemoryProfile {
    pub const ALL: [Self; 3] = [Self::Standard, Self::Expanded36, Self::Expanded40];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Expanded36 => "expanded-36",
            Self::Expanded40 => "expanded-40",
        }
    }
    pub const fn worker_bytes(self) -> u64 {
        match self {
            Self::Standard => 32 << 30,
            Self::Expanded36 => 36 << 30,
            Self::Expanded40 => 40 << 30,
        }
    }
    pub const fn process_max_bytes(self) -> u64 { self.worker_bytes() + (15 << 30) }
    pub const fn process_high_bytes(self) -> u64 { self.worker_bytes() + (13 << 30) }
    pub const fn available_bytes(self) -> u64 { self.worker_bytes() + (17 << 30) }

    pub fn from_worker_bytes(bytes: u64) -> Result<Self, &'static str> {
        Self::ALL.into_iter().find(|p| p.worker_bytes() == bytes)
            .ok_or("unrecognized worker host-memory profile")
    }

    /// Legacy smaller ledgers remain valid; expansion must match an explicit profile.
    pub(crate) fn valid_worker_ceiling(bytes: u64) -> bool {
        bytes > 0 && (bytes <= OPERATION_HOST_BYTES || Self::from_worker_bytes(bytes).is_ok())
    }

    pub(crate) fn validate_worker(self, bytes: u64) -> Result<(), &'static str> {
        if bytes == self.worker_bytes() { Ok(()) } else { Err("host-memory profile mismatch") }
    }
}

impl core::str::FromStr for HostMemoryProfile {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|p| p.label() == value)
            .ok_or("expected standard, expanded-36 or expanded-40")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_are_explicit_and_keep_operation_cap() {
        for (p, worker, max, high, available) in [
            (HostMemoryProfile::Standard, 32, 47, 45, 49),
            (HostMemoryProfile::Expanded36, 36, 51, 49, 53),
            (HostMemoryProfile::Expanded40, 40, 55, 53, 57),
        ] {
            assert_eq!(p.label().parse(), Ok(p));
            assert_eq!(HostMemoryProfile::from_worker_bytes(worker << 30), Ok(p));
            assert_eq!(p.process_max_bytes(), max << 30);
            assert_eq!(p.process_high_bytes(), high << 30);
            assert_eq!(p.available_bytes(), available << 30);
            for other in HostMemoryProfile::ALL {
                assert_eq!(p.validate_worker(other.worker_bytes()).is_ok(), p == other);
            }
        }
        for invalid in [0, (32 << 30) + 1, 35 << 30, (36 << 30) + 1, u64::MAX] {
            assert!(HostMemoryProfile::from_worker_bytes(invalid).is_err());
            assert!(!HostMemoryProfile::valid_worker_ceiling(invalid));
        }
        assert_eq!(HostMemoryProfile::default(), HostMemoryProfile::Standard);
        assert_eq!(OPERATION_HOST_BYTES, 32 << 30);
        assert!("expanded".parse::<HostMemoryProfile>().is_err());
        #[cfg(feature = "recursive")]
        for expanded in [HostMemoryProfile::Expanded36, HostMemoryProfile::Expanded40] {
            assert!(crate::execution::ProvingContext::cpu(expanded.worker_bytes()).is_err());
        }
    }
}
