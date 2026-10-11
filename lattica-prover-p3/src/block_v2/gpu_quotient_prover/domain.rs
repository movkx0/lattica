//! Keep the owned path independent of upstream coset construction, which
//! computes and caches an inverse even when only size and shift are needed.
use crate::block_v2::{
    gpu_hash::device::DomainSpec,
    profile::{Challenge, Challenger},
    quotient_pcs::CandidatePcs,
};
use crate::config::Val;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::coset::TwoAdicMultiplicativeCoset;

type CpuDomain = TwoAdicMultiplicativeCoset<Val>;
#[derive(Clone, Copy)]
pub(super) enum ProverDomain {
    Cpu(CpuDomain),
    Device(DomainSpec),
}
impl ProverDomain {
    pub(super) fn natural(pcs: &CandidatePcs, degree: usize, device: bool) -> Self {
        if device {
            assert!(degree.is_power_of_two());
            Self::Device(
                DomainSpec::new(1, degree.ilog2() as usize).expect("owned subgroup domain"),
            )
        } else {
            Self::Cpu(
                <CandidatePcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                    pcs, degree,
                ),
            )
        }
    }
    pub(super) fn quotient(self, pcs: &CandidatePcs, log_size: usize) -> Self {
        match self {
            Self::Cpu(domain) => Self::Cpu(domain.create_disjoint_domain(1usize << log_size)),
            Self::Device(domain) => Self::Device(
                pcs.quotient_session()
                    .expect("owned domain session")
                    .disjoint_domain(domain, log_size)
                    .expect("GPU quotient domain failed; no fallback"),
            ),
        }
    }
    pub(super) fn cpu(self) -> CpuDomain {
        match self {
            Self::Cpu(domain) => domain,
            Self::Device(_) => panic!("owned domain cannot enter CPU proving"),
        }
    }
}
impl From<ProverDomain> for DomainSpec {
    fn from(domain: ProverDomain) -> Self {
        match domain {
            ProverDomain::Cpu(domain) => domain.into(),
            ProverDomain::Device(domain) => domain,
        }
    }
}
