//! Source census for the unchanged bounded linear_map arithmetic.
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
pub use descriptor::{LinearMapDescriptor, LinearMapGeometry, MAX_INPUTS, MAX_PUBLIC_VALUES, MAX_HEIGHT, MAX_PERIODIC_COLUMNS, D, Q, QHAT};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LinearMapDeviceFootprint {
    pub trace_bytes: usize, pub public_bytes: usize, pub raw_bytes: usize,
    pub geometry_bytes: usize, pub endpoint_bytes: usize, pub status_bytes: usize,
    pub generation_peak_bytes: usize, pub largest_allocation_bytes: usize,
}
impl LinearMapDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LinearMapPreparationHost {
    pub symbolic_compiler_bytes: usize, pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize, pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize, pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize, pub required_host_bytes: usize,
}
impl LinearMapPreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LinearMapPreparationPlan {
    geometry: LinearMapGeometry, host: LinearMapPreparationHost, device: LinearMapDeviceFootprint,
    configuration: OwnedConfigurationCensus, planner: LegacyPlannerCensus,
}
impl LinearMapPreparationPlan {
    pub fn geometry(self) -> LinearMapGeometry { self.geometry }
    pub fn host(self) -> LinearMapPreparationHost { self.host }
    pub fn device(self) -> LinearMapDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }
    pub fn new(kind: LinearMapDescriptor) -> Result<Self> {
        supported_profile()?;
        let geometry = LinearMapGeometry::for_kind(kind);
        // The unchanged linear_map generator owns trace/public/raw/geometry/roots/status.
        // Public and endpoint roots commit to the ordered input and output polynomials.
        let allocations = [mul(mul(geometry.rows(), geometry.width())?, 8)?,
            mul(geometry.public_values(), 8)?, mul(geometry.raw_words(), 8)?, mul(geometry.geometry_words(), 8)?,
            mul(geometry.endpoint_words(), 8)?, mul(kind.count(), 8)?];
        let device = LinearMapDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            raw_bytes: allocations[2], geometry_bytes: allocations[3], endpoint_bytes: allocations[4],
            status_bytes: allocations[5], generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations.into_iter().max().ok_or(Error::Overflow)? };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(geometry.periodic_elements()?, size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns(), size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // Public/periodic callback vectors and all eight maximum canonical
        // range-check vectors (four source/output plus four quotient limbs).
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values(), size_of::<Public>())?,
            mul(geometry.periodic_columns() + 4 * geometry.kind().bits() + 4 * geometry.kind().quotient_bits(), size_of::<Expr>())?,
            10 * size_of::<Vec<Expr>>(),
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
            24 * size_of::<usize>(), 4 * size_of::<LinearMapGeometry>(),
            // Descriptor constructor, identity hashing, arithmetic specification,
            // returned descriptor and nested source/geometry frames. Large
            // per-cell schedule accessors borrow rather than copy this value.
            16 * size_of::<LinearMapDescriptor>(),
            4 * size_of::<sha3::Sha3_256>(),
            size_of::<super::super::arithmetic::ArithmeticSpec>(),
            size_of::<Vec<Public>>(), 10 * size_of::<Vec<Expr>>(),
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<LinearMapGeometry>>(),
            4 * size_of::<Result<LinearMapPreparationHost>>(), 4 * size_of::<Result<LinearMapDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = LinearMapPreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
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
