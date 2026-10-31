//! Source census for the unchanged bounded mul arithmetic.
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

mod descriptor;
mod constants;
pub use descriptor::{MulDescriptor, MulGeometry, Q, QHAT, ROWS_PER_BLOCK, ROWS_PER_POLYNOMIAL, MAX_POLYNOMIALS};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MulDeviceFootprint {
    pub trace_bytes: usize, pub public_bytes: usize, pub raw_bytes: usize,
    pub geometry_bytes: usize, pub endpoint_bytes: usize, pub status_bytes: usize,
    pub generation_peak_bytes: usize, pub largest_allocation_bytes: usize,
}
impl MulDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MulPreparationHost {
    pub symbolic_compiler_bytes: usize, pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize, pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize, pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize, pub required_host_bytes: usize,
}
impl MulPreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MulPreparationPlan {
    geometry: MulGeometry, host: MulPreparationHost, device: MulDeviceFootprint,
    configuration: OwnedConfigurationCensus, planner: LegacyPlannerCensus,
}
impl MulPreparationPlan {
    pub fn geometry(self) -> MulGeometry { self.geometry }
    pub fn host(self) -> MulPreparationHost { self.host }
    pub fn device(self) -> MulDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }
    pub fn new(kind: MulDescriptor) -> Result<Self> {
        supported_profile()?;
        let geometry = MulGeometry::for_kind(kind);
        // The unchanged MUL generator owns trace/public/raw/geometry/roots/status.
        // Public and endpoint roots both contain12 words per polynomial.
        let allocations = [mul(mul(geometry.rows(), geometry.width())?, 8)?,
            mul(geometry.public_values(), 8)?, mul(geometry.raw_words(), 8)?, mul(geometry.geometry_words(), 8)?,
            mul(geometry.endpoint_words(), 8)?, mul(kind.count(), 8)?];
        let device = MulDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            raw_bytes: allocations[2], geometry_bytes: allocations[3], endpoint_bytes: allocations[4],
            status_bytes: allocations[5], generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations.into_iter().max().ok_or(Error::Overflow)? };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(mul(geometry.periodic_columns(), geometry.period())?, size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns(), size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // The unchanged AIR allocates public/periodic vectors and five
        // canonical ranges. Charge callback allocations
        // additively; recorder node/Arc storage has its independent bound.
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values(), size_of::<Public>())?,
            mul(geometry.periodic_columns() + 5 * 32, size_of::<Expr>())?,
            7 * size_of::<Vec<Expr>>(),
        ])?;
        let public_readback_and_conversion_bytes = sum(&[
            mul(2 * geometry.public_values(), size_of::<Val>())?, 2 * size_of::<Vec<Val>>(),
        ])?;
        // Raw serialization, descriptor and upload staging are additive.
        // Immutable polynomial owners remain retained by the source operation.
        let raw_and_transfer_staging_bytes = sum(&[
            // Original serialized words plus upload; descriptor construction
            // starts at32 words then grows, preserving old allocations.
            mul(2 * geometry.raw_words(), size_of::<u64>())?,
            mul(8 * geometry.geometry_words(), size_of::<u64>())?,
            mul(2 * geometry.endpoint_words() + kind.count(), size_of::<u64>())?,
            8 * size_of::<Vec<u64>>(),
        ])?;
        let trace_matrix_backing_bytes = mul(6, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            4 * size_of::<Self>(), size_of::<uni::Prepared>(), size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(), 2 * size_of::<DeviceSession>(), size_of::<ProofCapacity>(),
            6 * size_of::<DeviceMatrix>(), size_of::<ocl::Queue>(), 6 * size_of::<MatrixSpec>(),
            24 * size_of::<usize>(), 4 * size_of::<MulGeometry>(),
            // Public schedules are fixed stack arrays, including returned
            // construction temporaries and nested source-geometry calls.
            8 * size_of::<[[u64; 2]; 1024]>(),
            size_of::<super::super::arithmetic::ArithmeticSpec>(),
            size_of::<Vec<Public>>(), 7 * size_of::<Vec<Expr>>(),
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<MulGeometry>>(),
            4 * size_of::<Result<MulPreparationHost>>(), 4 * size_of::<Result<MulDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = MulPreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
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
mod tests;
