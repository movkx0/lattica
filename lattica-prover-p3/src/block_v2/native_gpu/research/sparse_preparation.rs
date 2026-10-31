//! Source census for the unchanged alpha-prime and challenge-x sparse samplers.
//! No AIR callback, observed trace, reservation or runtime authority is accepted.
use super::{GeneratedTrace, TraceContext};
use super::shake_preparation::{LegacyPlannerCensus, OwnedConfigurationCensus};
use crate::block_v2::{
    gpu_hash::device::{self, DeviceMatrix, DeviceSession, MatrixSpec, ProofCapacity},
    gpu_quotient_prover::uni, machine::symbolic, pcs_field::PcsField, profile,
};
use crate::config::Val;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SparseKind { AlphaPrime39, ChallengeX44 }
impl SparseKind {
    pub fn input_bytes(self) -> usize { match self { Self::AlphaPrime39 => 127, Self::ChallengeX44 => 137 } }
    pub fn sign_bytes(self) -> usize { match self { Self::AlphaPrime39 => 5, Self::ChallengeX44 => 6 } }
    pub fn weight(self) -> usize { match self { Self::AlphaPrime39 => 39, Self::ChallengeX44 => 44 } }
    pub(crate) fn gpu_kind(self) -> super::super::sampling::SparseKind {
        match self { Self::AlphaPrime39 => super::super::sampling::SparseKind::AlphaPrime39,
            Self::ChallengeX44 => super::super::sampling::SparseKind::ChallengeX44 }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SparseGeometry { kind: SparseKind }
impl SparseGeometry {
    fn for_kind(kind: SparseKind) -> Self { Self { kind } }
    pub fn kind(self) -> SparseKind { self.kind }
    pub fn rows(self) -> usize { 256 }
    pub fn width(self) -> usize { 506 }
    pub fn public_values(self) -> usize { 8 }
    pub fn periodic_columns(self) -> usize { 82 }
    pub fn periodic_values(self) -> usize { 10 * 256 + 8 * 8 + 64 * 64 }
    pub fn periodic_length(self, column: usize) -> Result<usize> {
        match column { 0..=9 => Ok(256), 10..=17 => Ok(8), 18..=81 => Ok(64),
            _ => Err(Error::UnsupportedProfile) }
    }
    pub fn periodic_lengths(self) -> impl ExactSizeIterator<Item = usize> {
        (0..82).map(|column| match column { 0..=9 => 256, 10..=17 => 8, _ => 64 })
    }
    pub fn raw_words(self) -> usize { self.kind.input_bytes() }
    pub fn periodic_value(self, column: usize, row: usize) -> Result<Val> {
        if row >= self.periodic_length(column)? { return Err(Error::UnsupportedProfile); }
        Ok(Val::from_bool(match column {
            0 => row < self.kind.input_bytes(),
            1 => row >= self.kind.sign_bytes() && row < self.kind.input_bytes(),
            2 => row < self.kind.input_bytes().div_ceil(8) * 8 && row % 8 == 7,
            3 => row >= 192,
            4..=9 => column - 4 < self.kind.sign_bytes() && row == column - 4,
            10..=17 => row == column - 10,
            18..=81 => row == column - 18,
            _ => return Err(Error::UnsupportedProfile),
        }))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SparseDeviceFootprint {
    pub trace_bytes: usize, pub public_bytes: usize, pub raw_bytes: usize,
    pub endpoint_bytes: usize, pub status_bytes: usize, pub history_bytes: usize,
    pub generation_peak_bytes: usize, pub largest_allocation_bytes: usize,
}
impl SparseDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SparsePreparationHost {
    pub symbolic_compiler_bytes: usize, pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize, pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize, pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize, pub required_host_bytes: usize,
}
impl SparsePreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SparsePreparationPlan {
    geometry: SparseGeometry, host: SparsePreparationHost, device: SparseDeviceFootprint,
    configuration: OwnedConfigurationCensus, planner: LegacyPlannerCensus,
}
impl SparsePreparationPlan {
    pub fn geometry(self) -> SparseGeometry { self.geometry }
    pub fn host(self) -> SparsePreparationHost { self.host }
    pub fn device(self) -> SparseDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }
    pub fn new(kind: SparseKind) -> Result<Self> {
        supported_profile()?;
        let geometry = SparseGeometry::for_kind(kind);
        if (kind.gpu_kind().rows(), kind.gpu_kind().width(), kind.gpu_kind().input_bytes())
            != (geometry.rows(), geometry.width(), geometry.raw_words())
        { return Err(Error::UnsupportedProfile); }
        // pq_sampling_trace plans all six allocations before private upload:
        // trace/public/raw/endpoints/status/history. Sparse history requires
        // 512 words (4096 bytes) rather than the uniform path's one. All four
        // scratch matrices stay owned through mandatory scrub/drain.
        let allocations = [mul(mul(geometry.rows(), geometry.width())?, 8)?,
            8 * 8, mul(geometry.raw_words(), 8)?, 8 * 8, 8, 512 * 8];
        let device = SparseDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            raw_bytes: allocations[2], endpoint_bytes: allocations[3], status_bytes: allocations[4],
            history_bytes: allocations[5], generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations[0] };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(geometry.periodic_values(), size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns(), size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // SparseAir::eval allocates 82 periodic expressions, eight public
        // variables, eight raw-bit expressions, six count-bit expressions and
        // eight updated-buffer expressions. The round constants are inline.
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values(), size_of::<Public>())?,
            mul(geometry.periodic_columns() + 8 + 6 + 8, size_of::<Expr>())?,
        ])?;
        let public_readback_and_conversion_bytes = sum(&[
            mul(2 * geometry.public_values(), size_of::<Val>())?, 2 * size_of::<Vec<Val>>(),
        ])?;
        // Full byte-to-word upload staging and its forwarding duplicate are
        // additive; the immutable request's byte Vec remains source-owned.
        let raw_and_transfer_staging_bytes = sum(&[
            mul(2 * geometry.raw_words(), size_of::<u64>())?,
            size_of::<u64>(), 4 * size_of::<Vec<u64>>(),
        ])?;
        let trace_matrix_backing_bytes = mul(6, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            4 * size_of::<Self>(), size_of::<uni::Prepared>(), size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(), 2 * size_of::<DeviceSession>(), size_of::<ProofCapacity>(),
            6 * size_of::<DeviceMatrix>(), size_of::<ocl::Queue>(), 6 * size_of::<MatrixSpec>(),
            32 * size_of::<usize>(), 4 * size_of::<SparseGeometry>(),
            8 * size_of::<core::ops::Range<usize>>(),
            size_of::<Vec<Public>>(), 8 * size_of::<Vec<Expr>>(),
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<SparseGeometry>>(),
            4 * size_of::<Result<SparsePreparationHost>>(), 4 * size_of::<Result<SparseDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = SparsePreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, required_host_bytes };
        Ok(Self { geometry, host, device, configuration, planner })
    }
}
fn supported_profile() -> Result<()> {
    if size_of::<usize>() != 8 || size_of::<Val>() != 8 || size_of::<profile::Challenge>() != 24
        || (profile::LOG_BLOWUP, profile::NUM_QUERIES, profile::CAP_HEIGHT,
            profile::NUM_RANDOM_CODEWORDS, profile::QUERY_POW_BITS, profile::MAX_QUOTIENT_CHUNKS)
            != (4, 128, 6, 4, 16, 32)
        || <profile::Challenge as PcsField>::MAX_LOG_ARITY != 1
        || symbolic::HOST_BYTES != 192 << 20 || p3_poseidon2_air::num_cols::<8, 7, 0, 4, 22>() != 94 {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_samplers_charge_all_six_buffers_and_exact_mixed_periods() {
        for kind in [SparseKind::AlphaPrime39, SparseKind::ChallengeX44] {
            let plan = SparsePreparationPlan::new(kind).unwrap();
            let g = plan.geometry(); let d = plan.device();
            assert_eq!((g.rows(), g.width(), g.periodic_columns()), (256, 506, 82));
            assert_eq!(g.periodic_lengths().sum::<usize>(), 6720);
            assert_eq!(g.periodic_values(), 6720);
            assert_eq!(g.raw_words(), kind.input_bytes());
            assert_eq!(d.history_bytes, 4096);
            assert_eq!(d.trace_bytes, 1_036_288);
            assert_eq!(d.generation_peak_bytes, match kind {
                SparseKind::AlphaPrime39 => 1_041_536,
                SparseKind::ChallengeX44 => 1_041_616,
            });
            assert_eq!(g.periodic_length(9).unwrap(), 256);
            assert_eq!(g.periodic_length(10).unwrap(), 8);
            assert_eq!(g.periodic_length(17).unwrap(), 8);
            assert_eq!(g.periodic_length(18).unwrap(), 64);
            assert_eq!(g.periodic_length(81).unwrap(), 64);
            assert_eq!(g.periodic_value(3, 191).unwrap(), Val::ZERO);
            assert_eq!(g.periodic_value(3, 192).unwrap(), Val::ONE);
            assert_eq!(g.periodic_value(9, 5).unwrap(), match kind {
                SparseKind::AlphaPrime39 => Val::ZERO,
                SparseKind::ChallengeX44 => Val::ONE,
            });
            assert_eq!(g.periodic_value(10, 8), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_value(18, 64), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_length(82), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_value(82, 0), Err(Error::UnsupportedProfile));
        }
    }
}
