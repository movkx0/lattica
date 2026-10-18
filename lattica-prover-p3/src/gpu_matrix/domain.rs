//! Public coset metadata shared by device backends; construction does no arithmetic.
use super::GOLDILOCKS_MODULUS;
use crate::config::Val;
use p3_field::{coset::TwoAdicMultiplicativeCoset, PrimeField64};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainSpec {
    log_size: usize,
    shift: u64,
}

impl DomainSpec {
    pub(crate) fn new(shift: u64, log_size: usize) -> Result<Self, String> {
        if shift == 0
            || shift >= GOLDILOCKS_MODULUS
            || log_size > 32
            || log_size >= usize::BITS as usize
        {
            return Err("invalid owned prover domain".into());
        }
        Ok(Self { log_size, shift })
    }
    pub(crate) fn log_size(self) -> usize {
        self.log_size
    }
    pub(crate) fn size(self) -> usize {
        1usize << self.log_size
    }
    pub(crate) fn shift(self) -> Val {
        Val::new(self.shift)
    }
    pub(crate) fn shift_word(self) -> u64 {
        self.shift
    }
}

impl From<TwoAdicMultiplicativeCoset<Val>> for DomainSpec {
    fn from(domain: TwoAdicMultiplicativeCoset<Val>) -> Self {
        Self {
            log_size: domain.log_size(),
            shift: domain.shift().as_canonical_u64(),
        }
    }
}
