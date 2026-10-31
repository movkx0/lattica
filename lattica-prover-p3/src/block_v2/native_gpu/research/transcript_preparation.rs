//! Source census for the unchanged ordered graph-transcript source relation.
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

mod layout;
pub use layout::{TranscriptLayout, TranscriptPartKind, MAX_PARTS};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptGeometry { kind: TranscriptLayout }
impl TranscriptGeometry {
    fn for_kind(kind: TranscriptLayout) -> Self { Self { kind } }
    pub fn kind(self) -> TranscriptLayout { self.kind }
    pub fn rows(self) -> usize { self.kind.part_count().next_power_of_two() * 128 }
    pub fn width(self) -> usize { 383 + 2 * self.kind.event_count() }
    pub fn public_values(self) -> usize { 8 }
    pub fn periodic_columns(self) -> usize { 4 }
    pub fn periodic_values(self) -> usize { 3 * 128 + 2 }
    pub fn periodic_length(self, column: usize) -> Result<usize> {
        match column { 0 | 1 | 3 => Ok(128), 2 => Ok(2), _ => Err(Error::UnsupportedProfile) }
    }
    pub fn periodic_lengths(self) -> impl ExactSizeIterator<Item = usize> {
        [128, 128, 2, 128].into_iter()
    }
    pub fn raw_words(self) -> usize { self.kind.part_count() * 256 }
    pub fn geometry_words(self) -> usize { 8 + self.kind.part_count() + self.kind.event_count() }
    pub fn periodic_value(self, column: usize, row: usize) -> Result<Val> {
        if row >= self.periodic_length(column)? { return Err(Error::UnsupportedProfile); }
        Ok(Val::from_bool(match column {
            0 | 2 => row == 0,
            1 => row == 127,
            3 => row < 4,
            _ => return Err(Error::UnsupportedProfile),
        }))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptDeviceFootprint {
    pub trace_bytes: usize, pub public_bytes: usize, pub raw_bytes: usize,
    pub endpoint_bytes: usize, pub status_bytes: usize, pub geometry_bytes: usize,
    pub generation_peak_bytes: usize, pub largest_allocation_bytes: usize,
}
impl TranscriptDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptPreparationHost {
    pub symbolic_compiler_bytes: usize, pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize, pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize, pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize, pub required_host_bytes: usize,
}
impl TranscriptPreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptPreparationPlan {
    geometry: TranscriptGeometry, host: TranscriptPreparationHost, device: TranscriptDeviceFootprint,
    configuration: OwnedConfigurationCensus, planner: LegacyPlannerCensus,
}
impl TranscriptPreparationPlan {
    pub fn geometry(self) -> TranscriptGeometry { self.geometry }
    pub fn host(self) -> TranscriptPreparationHost { self.host }
    pub fn device(self) -> TranscriptDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }
    pub fn new(kind: TranscriptLayout) -> Result<Self> {
        supported_profile()?;
        let geometry = TranscriptGeometry::for_kind(kind);
        // pq_source_trace plans six matrices before allocation or upload:
        // trace, public, raw, geometry, endpoints and status. Their originals
        // remain charged through source/status scrub and actual retirement.
        let allocations = [mul(mul(geometry.rows(), geometry.width())?, 8)?,
            8 * 8, mul(geometry.raw_words(), 8)?, mul(geometry.geometry_words(), 8)?, 8 * 8, 8];
        let device = TranscriptDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            raw_bytes: allocations[2], geometry_bytes: allocations[3], endpoint_bytes: allocations[4],
            status_bytes: allocations[5], generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations[0] };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(geometry.periodic_values(), size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns(), size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // Three Poseidon AIRs use inline constants. The callback allocates
        // eight public variables, four periodic variables and two 32-bit
        // expression vectors. Sum both bit allocations despite sequential use.
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values(), size_of::<Public>())?,
            mul(geometry.periodic_columns() + 64, size_of::<Expr>())?,
        ])?;
        let public_readback_and_conversion_bytes = sum(&[
            mul(2 * geometry.public_values(), size_of::<Val>())?, 2 * size_of::<Vec<Val>>(),
        ])?;
        // RawWords plus upload, exact kinds, growing events and the initial/
        // replaced geometry Vecs all count additively. Eight geometry lengths
        // bound the initial 8 words, both extend reallocations and transfer.
        let raw_and_transfer_staging_bytes = sum(&[
            mul(2 * geometry.raw_words(), size_of::<u64>())?,
            mul(8 * geometry.geometry_words(), size_of::<u64>())?,
            mul(5 * kind.part_count().max(8), size_of::<u64>())?,
            size_of::<u64>(), 8 * size_of::<Vec<u64>>(),
        ])?;
        let trace_matrix_backing_bytes = mul(6, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            4 * size_of::<Self>(), size_of::<uni::Prepared>(), size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(), 2 * size_of::<DeviceSession>(), size_of::<ProofCapacity>(),
            6 * size_of::<DeviceMatrix>(), size_of::<ocl::Queue>(), 6 * size_of::<MatrixSpec>(),
            32 * size_of::<usize>(), 4 * size_of::<TranscriptGeometry>(),
            8 * size_of::<[usize; 4]>(),
            size_of::<Vec<Public>>(), 8 * size_of::<Vec<Expr>>(),
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<TranscriptGeometry>>(),
            4 * size_of::<Result<TranscriptPreparationHost>>(), 4 * size_of::<Result<TranscriptDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = TranscriptPreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
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
    fn transcript_layout_bounds_source_geometry_and_all_six_allocations() {
        use TranscriptPartKind::*;
        for parts in [&[Bytes32][..], &[Bytes32, PolynomialQ, PolynomialQhat][..]] {
            let kind = TranscriptLayout::new(parts).unwrap();
            let plan = TranscriptPreparationPlan::new(kind).unwrap();
            let g = plan.geometry(); let d = plan.device();
            assert_eq!(g.periodic_lengths().collect::<Vec<_>>(), [128, 128, 2, 128]);
            assert_eq!(g.periodic_values(), 386);
            assert_eq!(d.generation_peak_bytes, d.trace_bytes + d.public_bytes + d.raw_bytes
                + d.geometry_bytes + d.endpoint_bytes + d.status_bytes);
            assert_eq!(d.geometry_bytes, g.geometry_words() * 8);
            assert_eq!(g.periodic_value(0, 0).unwrap(), Val::ONE);
            assert_eq!(g.periodic_value(1, 127).unwrap(), Val::ONE);
            assert_eq!(g.periodic_value(2, 1).unwrap(), Val::ZERO);
            assert_eq!(g.periodic_value(2, 2), Err(Error::UnsupportedProfile));
            assert_eq!(g.periodic_value(3, 4).unwrap(), Val::ZERO);
        }
        let max = core::array::from_fn::<_, 256, _>(|i| if i % 2 == 0 { Bytes32 } else { PolynomialQ });
        let g = TranscriptPreparationPlan::new(TranscriptLayout::new(&max).unwrap()).unwrap().geometry();
        assert_eq!((g.rows(), g.width(), g.raw_words(), g.geometry_words()), (32768, 895, 65536, 520));
    }
}

#[cfg(test)]
pub(crate) fn test_layouts() -> [TranscriptLayout; 2] {
    use TranscriptPartKind::*;
    [TranscriptLayout::new(&[Bytes32]).unwrap(),
        TranscriptLayout::new(&[Bytes32, PolynomialQ, PolynomialQhat]).unwrap()]
}
