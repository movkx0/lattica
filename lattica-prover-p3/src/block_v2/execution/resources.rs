//! Aggregate admission ledger, not a replacement for OS/device enforcement.

use crate::block_v2::recursive::Error;

const GIB: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resources {
    pub ram_bytes: u64,
    pub vram_bytes: u64,
    pub scratch_bytes: u64,
    pub threads: u32,
}

impl Resources {
    pub(crate) fn add(self, other: Self) -> Option<Self> {
        Some(Self {
            ram_bytes: self.ram_bytes.checked_add(other.ram_bytes)?,
            vram_bytes: self.vram_bytes.checked_add(other.vram_bytes)?,
            scratch_bytes: self.scratch_bytes.checked_add(other.scratch_bytes)?,
            threads: self.threads.checked_add(other.threads)?,
        })
    }

    pub(crate) fn subtract(self, other: Self) -> Option<Self> {
        Some(Self {
            ram_bytes: self.ram_bytes.checked_sub(other.ram_bytes)?,
            vram_bytes: self.vram_bytes.checked_sub(other.vram_bytes)?,
            scratch_bytes: self.scratch_bytes.checked_sub(other.scratch_bytes)?,
            threads: self.threads.checked_sub(other.threads)?,
        })
    }

    pub(crate) fn fits(self, capacity: Self) -> bool {
        self.ram_bytes <= capacity.ram_bytes
            && self.vram_bytes <= capacity.vram_bytes
            && self.scratch_bytes <= capacity.scratch_bytes
            && self.threads <= capacity.threads
    }

    pub(crate) fn validate_request(self) -> Result<(), Error> {
        if self.ram_bytes == 0 || self.threads == 0 {
            return Err("execution request requires RAM and CPU capacity".into());
        }
        Ok(())
    }

    pub(crate) fn validate_capacity(self) -> Result<(), Error> {
        self.validate_request()?;
        // Reserve 3 GiB for the coordinator/cache within the 48 GiB total.
        if self.ram_bytes > 45 * GIB
            || self.vram_bytes > 12 * GIB
            || self.scratch_bytes > 128 * GIB
            || self.threads > 256
        {
            return Err("execution capacity exceeds research resource gate".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_arithmetic_and_gate_are_checked() {
        let r = Resources {
            ram_bytes: 1,
            vram_bytes: 2,
            scratch_bytes: 3,
            threads: 1,
        };
        assert_eq!(r.add(r).unwrap().subtract(r), Some(r));
        assert!(Resources::default().subtract(r).is_none());
        assert!(Resources {
            ram_bytes: u64::MAX,
            ..r
        }
        .add(r)
        .is_none());
        assert!(Resources {
            threads: u32::MAX,
            ..r
        }
        .add(r)
        .is_none());
        assert!(!r.fits(Resources { vram_bytes: 1, ..r }));
        assert!(Resources::default().validate_capacity().is_err());
        assert!(Resources {
            ram_bytes: 46 * GIB,
            ..r
        }
        .validate_capacity()
        .is_err());
        assert!(Resources {
            vram_bytes: 13 * GIB,
            ..r
        }
        .validate_capacity()
        .is_err());
        assert!(Resources {
            scratch_bytes: 129 * GIB,
            ..r
        }
        .validate_capacity()
        .is_err());
    }
}
