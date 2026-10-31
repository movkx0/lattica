//! Source census for the unchanged SampleG and ExpandAlpha uniform samplers.
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
pub enum UniformKind { SampleG4, ExpandAlpha2 }
impl UniformKind {
    pub fn draws(self) -> usize { match self { Self::SampleG4 => 1197, Self::ExpandAlpha2 => 643 } }
    pub fn polynomials(self) -> usize { match self { Self::SampleG4 => 4, Self::ExpandAlpha2 => 2 } }
    pub fn input_bytes(self) -> usize { self.draws() * 4 }
    pub(crate) fn gpu_kind(self) -> super::super::sampling::UniformKind {
        match self { Self::SampleG4 => super::super::sampling::UniformKind::SampleG4,
            Self::ExpandAlpha2 => super::super::sampling::UniformKind::ExpandAlpha2 }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UniformGeometry { kind: UniformKind }
impl UniformGeometry {
    fn for_kind(kind: UniformKind) -> Self { Self { kind } }
    pub fn kind(self) -> UniformKind { self.kind }
    pub fn rows(self) -> usize { match self.kind { UniformKind::SampleG4 => 2048, UniformKind::ExpandAlpha2 => 1024 } }
    pub fn width(self) -> usize { 445 }
    pub fn public_values(self) -> usize { 8 }
    pub fn periodic_columns(self) -> usize { 2 }
    pub fn period(self) -> usize { self.rows() }
    pub fn periodic_length(self) -> usize { self.period() }
    pub fn raw_words(self) -> usize { self.kind.input_bytes() }
    pub fn periodic_value(self, column: usize, row: usize) -> Result<Val> {
        if column >= self.periodic_columns() || row >= self.period() { return Err(Error::UnsupportedProfile); }
        Ok(Val::from_bool(match column {
            0 => row < self.kind.draws(),
            1 => row % 2 == 1 && row < self.kind.draws().div_ceil(2) * 2,
            _ => return Err(Error::UnsupportedProfile),
        }))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UniformDeviceFootprint {
    pub trace_bytes: usize, pub public_bytes: usize, pub raw_bytes: usize,
    pub endpoint_bytes: usize, pub status_bytes: usize, pub history_bytes: usize,
    pub generation_peak_bytes: usize, pub largest_allocation_bytes: usize,
}
impl UniformDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UniformPreparationHost {
    pub symbolic_compiler_bytes: usize, pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize, pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize, pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize, pub required_host_bytes: usize,
}
impl UniformPreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UniformPreparationPlan {
    geometry: UniformGeometry, host: UniformPreparationHost, device: UniformDeviceFootprint,
    configuration: OwnedConfigurationCensus, planner: LegacyPlannerCensus,
}
impl UniformPreparationPlan {
    pub fn geometry(self) -> UniformGeometry { self.geometry }
    pub fn host(self) -> UniformPreparationHost { self.host }
    pub fn device(self) -> UniformDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }
    pub fn new(kind: UniformKind) -> Result<Self> {
        supported_profile()?;
        let geometry = UniformGeometry::for_kind(kind);
        if (kind.gpu_kind().rows(), kind.gpu_kind().width(), kind.gpu_kind().input_bytes())
            != (geometry.rows(), geometry.width(), geometry.raw_words())
        { return Err(Error::UnsupportedProfile); }
        // pq_sampling_trace plans all six allocations before private upload:
        // trace/public/raw/endpoints/status/history. Uniform's history has one
        // word even though the fixed sparse path needs 512 words. All four
        // scratch matrices stay owned through mandatory scrub/drain.
        let allocations = [mul(mul(geometry.rows(), geometry.width())?, 8)?,
            8 * 8, mul(geometry.raw_words(), 8)?, 8 * 8, 8, 8];
        let device = UniformDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            raw_bytes: allocations[2], endpoint_bytes: allocations[3], status_bytes: allocations[4],
            history_bytes: allocations[5], generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations[0] };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(mul(geometry.periodic_columns(), geometry.period())?, size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns(), size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // UniformAir::eval allocates only its two periodic expressions and
        // eight public variables. Bit packing and all three initial states
        // use fixed arrays/folds; the three Poseidon constants are inline.
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values(), size_of::<Public>())?,
            mul(geometry.periodic_columns(), size_of::<Expr>())?,
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
            24 * size_of::<usize>(), 4 * size_of::<UniformGeometry>(),
            size_of::<Vec<Public>>(), 8 * size_of::<Vec<Expr>>(),
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<UniformGeometry>>(),
            4 * size_of::<Result<UniformPreparationHost>>(), 4 * size_of::<Result<UniformDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = UniformPreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
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
    fn fixed_samplers_charge_all_six_trace_allocations_and_full_periods() {
        for kind in [UniformKind::SampleG4, UniformKind::ExpandAlpha2] {
            let plan = UniformPreparationPlan::new(kind).unwrap();
            let g = plan.geometry(); let d = plan.device();
            assert_eq!(g.rows(), kind.draws().next_power_of_two());
            assert_eq!(g.period(), g.rows());
            assert_eq!(g.raw_words(), kind.input_bytes());
            assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                + d.endpoint_bytes + d.status_bytes + d.history_bytes);
            assert_eq!(d.history_bytes, 8);
            assert_eq!(d.trace_bytes, g.rows() * g.width() * 8);
            for row in 0..g.rows() {
                assert_eq!(g.periodic_value(0, row).unwrap(), Val::from_bool(row < kind.draws()));
                assert_eq!(g.periodic_value(1, row).unwrap(),
                    Val::from_bool(row % 2 == 1 && row < kind.draws().div_ceil(2) * 2));
            }
            assert_eq!(g.periodic_value(2, 0), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_value(0, g.rows()), Err(Error::UnsupportedProfile));
        }
    }
}
