//! Allocation-free census for the unchanged statement/private-proof sources.
//! These fixed facts confer no runtime, reservation, proof or dispatch authority.
//! The actual AIR, owned quotient/PCS path and retained output remain separate
//! obligations of the concrete source-producer plan.
use super::{GeneratedTrace, TraceContext};
use super::shake_preparation::{LegacyPlannerCensus, OwnedConfigurationCensus};
use crate::block_v2::{
    gpu_hash::device::{self, DeviceMatrix, DeviceSession, MatrixSpec, ProofCapacity},
    gpu_quotient_prover::uni,
    machine::symbolic,
    pcs_field::PcsField,
    profile,
};
use crate::config::Val;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum GraphSourceKind { Statement, PrivateProof }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }

/// The maintained TraceContext source encodings, not caller-supplied widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GraphSourceGeometry {
    kind: GraphSourceKind,
    rows: usize,
    width: usize,
    public_values: usize,
    periodic_columns: usize,
    raw_words: usize,
    geometry_words: usize,
}
impl GraphSourceGeometry {
    fn for_kind(kind: GraphSourceKind) -> Self {
        match kind {
            GraphSourceKind::Statement => Self { kind, rows: 16384, width: 496,
                public_values: 8, periodic_columns: 2, raw_words: 50713, geometry_words: 12 },
            GraphSourceKind::PrivateProof => Self { kind, rows: 8192, width: 469,
                public_values: 4, periodic_columns: 3, raw_words: 23304, geometry_words: 4 },
        }
    }
    pub fn kind(self) -> GraphSourceKind { self.kind }
    pub fn rows(self) -> usize { self.rows }
    pub fn width(self) -> usize { self.width }
    pub fn public_values(self) -> usize { self.public_values }
    pub fn periodic_columns(self) -> usize { self.periodic_columns }
    pub fn period(self) -> usize { 64 }
    pub fn periodic_length(self) -> usize { self.period() }
    pub fn raw_words(self) -> usize { self.raw_words }
    pub fn geometry_words(self) -> usize { self.geometry_words }
    pub fn periodic_value(self, column: usize, row: usize) -> Result<Val> {
        if column >= self.periodic_columns || row >= self.period() { return Err(Error::UnsupportedProfile); }
        Ok(Val::from_bool(match (self.kind, column) {
            (GraphSourceKind::Statement, 0) => row == 3,
            (GraphSourceKind::Statement, 1) => row == 2,
            (GraphSourceKind::PrivateProof, 0) => row == 0,
            (GraphSourceKind::PrivateProof, 1) => row == 63,
            (GraphSourceKind::PrivateProof, 2) => row < 2,
            _ => return Err(Error::UnsupportedProfile),
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GraphSourceDeviceFootprint {
    pub trace_bytes: usize,
    pub public_bytes: usize,
    pub raw_bytes: usize,
    pub geometry_bytes: usize,
    pub endpoint_bytes: usize,
    pub status_bytes: usize,
    pub generation_peak_bytes: usize,
    pub largest_allocation_bytes: usize,
}
impl GraphSourceDeviceFootprint {
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GraphSourcePreparationHost {
    pub symbolic_compiler_bytes: usize,
    pub periodic_staging_bytes: usize,
    pub air_callback_heap_bytes: usize,
    pub public_readback_and_conversion_bytes: usize,
    pub raw_and_transfer_staging_bytes: usize,
    pub trace_matrix_backing_bytes: usize,
    pub explicit_owner_bytes: usize,
    pub required_host_bytes: usize,
}
impl GraphSourcePreparationHost {
    pub fn required_host_bytes(self) -> usize { self.required_host_bytes }
    pub fn periodic_staging_bytes(self) -> usize { self.periodic_staging_bytes }
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GraphSourcePreparationPlan {
    geometry: GraphSourceGeometry,
    host: GraphSourcePreparationHost,
    device: GraphSourceDeviceFootprint,
    configuration: OwnedConfigurationCensus,
    planner: LegacyPlannerCensus,
}
impl GraphSourcePreparationPlan {
    pub fn geometry(self) -> GraphSourceGeometry { self.geometry }
    pub fn host(self) -> GraphSourcePreparationHost { self.host }
    pub fn device(self) -> GraphSourceDeviceFootprint { self.device }
    pub fn configuration(self) -> OwnedConfigurationCensus { self.configuration }
    pub fn planner(self) -> LegacyPlannerCensus { self.planner }

    pub fn new(kind: GraphSourceKind) -> Result<Self> {
        supported_profile()?;
        let geometry = GraphSourceGeometry::for_kind(kind);
        // pq_sources::pq_source_trace plans exactly these six matrices before
        // allocation or private upload: trace, public, raw, geometry, endpoints,
        // status. Source and status scrubbing retain the same owners.
        let allocations = [mul(mul(geometry.rows, geometry.width)?, 8)?,
            mul(geometry.public_values, 8)?, mul(geometry.raw_words, 8)?,
            mul(geometry.geometry_words, 8)?, mul(geometry.public_values, 8)?, 8];
        let device = GraphSourceDeviceFootprint { trace_bytes: allocations[0],
            public_bytes: allocations[1], raw_bytes: allocations[2], geometry_bytes: allocations[3],
            endpoint_bytes: allocations[4], status_bytes: allocations[5],
            generation_peak_bytes: sum(&allocations)?, largest_allocation_bytes: allocations[0] };
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            mul(mul(geometry.periodic_columns, geometry.period())?, size_of::<Val>() + 2 * size_of::<u64>())?,
            mul(geometry.periodic_columns, size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + 3 * size_of::<usize>())?,
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // Retain every callback Vec payload additively, even though successive
        // 32-bit decomposition vectors do not all overlap. StatementAir has
        // four such vectors; ProofAir additionally has eight classes and the
        // sixty-bit norm decomposition. Symbolic nodes are separately bounded.
        let callback_expressions = add(geometry.periodic_columns, match kind {
            GraphSourceKind::Statement => 4 * 32,
            GraphSourceKind::PrivateProof => 4 * 32 + 8 + 60,
        })?;
        let air_callback_heap_bytes = sum(&[
            mul(geometry.public_values, size_of::<Public>())?,
            mul(callback_expressions, size_of::<Expr>())?,
            // StatementAir::eval calls bundle::initial. Its two absorbs each
            // construct the scalar Poseidon permutation, allocating the two
            // four-round external tables and the 22 internal constants.
            // Charge both constructions additively; replay and independent
            // numerical verification consume this same callback census.
            if kind == GraphSourceKind::Statement {
                mul(2, sum(&[
                    mul(4 * 8 + 4 * 8 + 22, size_of::<Val>())?,
                    mul(3, size_of::<Vec<Val>>())?,
                ])?)?
            } else { 0 },
        ])?;
        let public_readback_and_conversion_bytes = sum(&[
            mul(2 * geometry.public_values, size_of::<Val>())?, 2 * size_of::<Vec<Val>>(),
        ])?;
        // Original RawWords + geometry arrays and complete upload staging are
        // separate. Include status readback before any private-source dispatch.
        let raw_and_transfer_staging_bytes = sum(&[
            mul(2 * add(geometry.raw_words, geometry.geometry_words)?, size_of::<u64>())?,
            // Statement appends eight words to an initial four-word Vec.
            // Charge its replaced allocation in addition to the final owner
            // and independently allocated upload staging.
            if kind == GraphSourceKind::Statement { 4 * size_of::<u64>() } else { 0 },
            size_of::<u64>(), 4 * size_of::<Vec<u64>>(),
        ])?;
        let trace_matrix_backing_bytes = mul(6, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            4 * size_of::<Self>(), size_of::<uni::Prepared>(), size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(), 2 * size_of::<DeviceSession>(), size_of::<ProofCapacity>(),
            6 * size_of::<DeviceMatrix>(), size_of::<ocl::Queue>(), 6 * size_of::<MatrixSpec>(),
            24 * size_of::<usize>(), 4 * size_of::<GraphSourceGeometry>(),
            size_of::<Vec<Public>>(), 8 * size_of::<Vec<Expr>>(),
            // The statement AIR invokes three Poseidon sub-AIRs; charge all
            // constants frames without requiring reuse or move-elision credit.
            3 * size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
            4 * size_of::<Result<Self>>(), 4 * size_of::<Result<GraphSourceGeometry>>(),
            4 * size_of::<Result<GraphSourcePreparationHost>>(),
            4 * size_of::<Result<GraphSourceDeviceFootprint>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, raw_and_transfer_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(),
            planner.required_host_bytes()])?;
        let host = GraphSourcePreparationHost { symbolic_compiler_bytes, periodic_staging_bytes,
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
