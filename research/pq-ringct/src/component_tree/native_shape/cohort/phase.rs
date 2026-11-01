//! A supplement is an actual claim in the caller's original ledger. The
//! compiler allowance is unchanged, and no optional claim outlives its cohort.
use super::*;
use crate::execution::retained_resources::{Bytes, Category, Ledger, Reservation};

const TARGET_BYTES: usize = 3 << 30;
const MAX_EXTRA_BYTES: usize = 1 << 30;

pub(super) struct Backing<'a> {
    pub original: &'a Reservation,
    pub ledger: &'a Ledger,
}
pub(super) struct Permit<'a> {
    _original: &'a Reservation,
    extra: Option<Reservation>,
    original_bytes: usize,
}
impl Backing<'_> {
    pub fn validate(&self, bytes: usize) -> Result<(), CompileError> {
        if !self.original.belongs_to(self.ledger)
            || self
                .original
                .requirements()
                .get(Category::PhaseScratch)
                .host
                < bytes as u64
        {
            return Err(CompileError::ResourceAdmission(
                "native phase original reservation",
            ));
        }
        Ok(())
    }
    pub fn admit(
        &self,
        bytes: usize,
        ready: usize,
        workers: usize,
    ) -> Result<Permit<'_>, CompileError> {
        self.validate(bytes)?;
        let requested = TARGET_BYTES.saturating_sub(bytes).min(MAX_EXTRA_BYTES);
        let available = usize::try_from(self.ledger.remaining().host).unwrap_or(usize::MAX);
        let requested = requested.min(available);
        let extra = if ready > 8 && workers > 8 && requested != 0 {
            // Capacity comes only from this ledger. Refusal leaves the
            // already reserved bytes available to the same scheduler.
            self.ledger
                .reserve(
                    Category::PhaseScratch,
                    Bytes {
                        host: requested as u64,
                        device: 0,
                    },
                )
                .ok()
        } else {
            None
        };
        Ok(Permit {
            _original: self.original,
            extra,
            original_bytes: bytes,
        })
    }
}
impl Permit<'_> {
    pub fn budget(&self) -> usize {
        self.original_bytes
            + self.extra.as_ref().map_or(0, |claim| {
                claim.requirements().get(Category::PhaseScratch).host as usize
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;
    #[test]
    fn phase_supplement_is_real_bounded_and_released_before_original() {
        let ledger = Ledger::new(WorkerAllowance {
            host: 4 << 30,
            device: 0,
        });
        let original = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: 2 << 30,
                    device: 0,
                },
            )
            .unwrap();
        let backing = Backing {
            original: &original,
            ledger: &ledger,
        };
        assert_eq!(backing.admit(2 << 30, 16, 8).unwrap().budget(), 2 << 30);
        {
            let permit = backing.admit(2 << 30, 16, 16).unwrap();
            assert_eq!(permit.budget(), 3 << 30);
            assert_eq!(ledger.snapshot().current.host, 3 << 30);
        }
        assert_eq!(ledger.snapshot().current.host, 2 << 30);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    #[test]
    fn phase_refuses_foreign_or_short_originals_and_respects_other_claims() {
        let ledger = Ledger::new(WorkerAllowance {
            host: 3 << 30,
            device: 0,
        });
        let foreign = Ledger::new(WorkerAllowance {
            host: 3 << 30,
            device: 0,
        });
        let original = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: 2 << 30,
                    device: 0,
                },
            )
            .unwrap();
        assert!(Backing {
            original: &original,
            ledger: &foreign
        }
        .validate(2 << 30)
        .is_err());
        let backing = Backing {
            original: &original,
            ledger: &ledger,
        };
        assert!(backing.validate((2 << 30) + 1).is_err());
        let other = ledger
            .reserve(
                Category::Report,
                Bytes {
                    host: 1 << 30,
                    device: 0,
                },
            )
            .unwrap();
        assert_eq!(backing.admit(2 << 30, 16, 16).unwrap().budget(), 2 << 30);
        assert_eq!(backing.admit(2 << 30, 8, 16).unwrap().budget(), 2 << 30);
        drop(other);
        let other = ledger
            .reserve(
                Category::Report,
                Bytes {
                    host: 768 << 20,
                    device: 0,
                },
            )
            .unwrap();
        {
            let permit = backing.admit(2 << 30, 16, 16).unwrap();
            assert_eq!(permit.budget(), (2 << 30) + (256 << 20));
            assert_eq!(ledger.snapshot().current.host, 3 << 30);
        }
        assert_eq!(ledger.snapshot().current.host, (2 << 30) + (768 << 20));
        drop(other);
        let held = ledger.snapshot().current;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = backing.admit(2 << 30, 16, 16).unwrap();
            panic!("phase unwind");
        }));
        assert!(failed.is_err());
        assert_eq!(ledger.snapshot().current, held);
    }
}
