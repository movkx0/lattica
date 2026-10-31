//! Allocation-free source census for the unchanged serial AES lane producer.
//! Counts carry no proof, reservation, callback or dispatch authority. Original
//! preparation, output, verifier, runtime and PCS owners remain additive.
use super::{GeneratedTrace, TraceContext};
use super::shake_preparation::{LegacyPlannerCensus, OwnedConfigurationCensus};
use crate::block_v2::{
    gpu_hash::device::{self, DeviceMatrix, DeviceSession, MatrixSpec, ProofCapacity},
    gpu_quotient_prover::uni,
    machine::symbolic,
    native_gpu::AesTraceSpec,
    pcs_field::PcsField,
    profile,
};
use crate::config::Val;
use core::mem::size_of;
use p3_air::AirBuilder;
use serde::Serialize;

const WIDTH: usize = 417;
const PUBLIC_VALUES: usize = 12;
const PERIODIC_COLUMNS: usize = 31;
const PERIOD: usize = 64;
const ROWS_PER_BLOCK: usize = 1024;
const MAX_BLOCKS: usize = 64;
const MAX_ROWS: usize = 1 << 20;
const STAGING_WORDS: usize = 2048;
const AES_TABLE_WORDS: usize = 256 * 66;
const CHECKPOINT_WORDS: usize = 15 * (4 + 2) + 14 * 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error { UnsupportedProfile, Length, Segment, RowLimit, Overflow, SharedCensus }
type Result<T> = core::result::Result<T, Error>;
fn add(a: usize, b: usize) -> Result<usize> { a.checked_add(b).ok_or(Error::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize> { a.checked_mul(b).ok_or(Error::Overflow) }
fn sum(parts: &[usize]) -> Result<usize> { parts.iter().try_fold(0, |a, &b| add(a, b)) }
macro_rules! getters {
    ($($name:ident : $ty:ty),* $(,)?) => {$(pub const fn $name(self) -> $ty { self.$name })*};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AesPreparationGeometry {
    domain: u64,
    start_counter: u32,
    output_len: usize,
    first_block: usize,
    blocks: usize,
    rows: usize,
}
impl AesPreparationGeometry {
    getters!(domain: u64, start_counter: u32, output_len: usize,
        first_block: usize, blocks: usize, rows: usize);
    pub const fn width(self) -> usize { WIDTH }
    pub const fn public_values(self) -> usize { PUBLIC_VALUES }
    pub const fn periodic_columns(self) -> usize { PERIODIC_COLUMNS }
    pub const fn periodic_length(self) -> usize { PERIOD }
    pub const fn input_len(self) -> usize { 32 }
    pub const fn kernel_kind(self) -> u32 { 0 }
    pub const fn trace_spec(self) -> AesTraceSpec {
        AesTraceSpec { domain: self.domain, start_counter: self.start_counter,
            output_len: self.output_len, first_block: self.first_block, blocks: self.blocks }
    }
}

/// Five simultaneous crypto_trace matrices, including the prefix-dependent
/// AES stream, shared S-box table, packed block checkpoints and padded inverse
/// slots. This excludes later PCS and runtime storage; neither may borrow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AesTraceDeviceFootprint {
    trace_bytes: usize,
    public_bytes: usize,
    source_bytes: usize,
    scratch_bytes: usize,
    geometry_bytes: usize,
    generation_peak_bytes: usize,
    largest_allocation_bytes: usize,
}
impl AesTraceDeviceFootprint {
    getters!(trace_bytes: usize, public_bytes: usize, source_bytes: usize,
        scratch_bytes: usize, geometry_bytes: usize, generation_peak_bytes: usize,
        largest_allocation_bytes: usize);
    pub fn generated_output_bytes(self) -> Result<usize> { add(self.trace_bytes, self.public_bytes) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AesPreparationHost {
    symbolic_compiler_bytes: usize,
    periodic_staging_bytes: usize,
    air_callback_heap_bytes: usize,
    public_readback_and_conversion_bytes: usize,
    trace_upload_staging_bytes: usize,
    trace_matrix_backing_bytes: usize,
    explicit_owner_bytes: usize,
    required_host_bytes: usize,
}
impl AesPreparationHost {
    getters!(symbolic_compiler_bytes: usize, periodic_staging_bytes: usize,
        air_callback_heap_bytes: usize, public_readback_and_conversion_bytes: usize,
        trace_upload_staging_bytes: usize, trace_matrix_backing_bytes: usize,
        explicit_owner_bytes: usize, required_host_bytes: usize);
    pub fn prepared_partition_bytes(self) -> Result<usize> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AesPreparationPlan {
    geometry: AesPreparationGeometry,
    host: AesPreparationHost,
    trace_device: AesTraceDeviceFootprint,
    configuration: OwnedConfigurationCensus,
    planner: LegacyPlannerCensus,
}
impl AesPreparationPlan {
    getters!(geometry: AesPreparationGeometry, host: AesPreparationHost,
        trace_device: AesTraceDeviceFootprint, configuration: OwnedConfigurationCensus,
        planner: LegacyPlannerCensus);

    pub fn new(spec: AesTraceSpec) -> Result<Self> {
        supported_profile()?;
        if spec.output_len == 0 || spec.output_len > u32::MAX as usize { return Err(Error::Length); }
        if spec.blocks == 0 || spec.blocks > MAX_BLOCKS { return Err(Error::Segment); }
        let end = add(spec.first_block, spec.blocks)?;
        if end > spec.output_len.div_ceil(16) { return Err(Error::Segment); }
        // Preserve the maintained wrapping u32 counter semantics. A partial
        // final segment pads rows, never changes native block coverage.
        let rows = mul(spec.blocks, ROWS_PER_BLOCK)?.checked_next_power_of_two().ok_or(Error::Overflow)?;
        if rows > MAX_ROWS { return Err(Error::RowLimit); }
        let geometry = AesPreparationGeometry { domain: spec.domain, start_counter: spec.start_counter,
            output_len: spec.output_len, first_block: spec.first_block, blocks: spec.blocks, rows };
        // Exact source formula in device/pq_crypto.rs::CryptoPlan::new(kind=0).
        let checkpoints = sum(&[mul(spec.blocks, CHECKPOINT_WORDS + 4)?, mul(rows / ROWS_PER_BLOCK, 3)?, 7 * 4])?;
        let scratch_words = sum(&[mul(end, 16)?, mul(add(spec.blocks, 1)?, 8)?, 64, AES_TABLE_WORDS, checkpoints])?;
        let allocations = [mul(mul(rows, WIDTH)?, 8)?, PUBLIC_VALUES * 8, 32 * 8,
            mul(scratch_words, 8)?, 12 * 8];
        let trace_device = AesTraceDeviceFootprint { trace_bytes: allocations[0], public_bytes: allocations[1],
            source_bytes: allocations[2], scratch_bytes: allocations[3], geometry_bytes: allocations[4],
            generation_peak_bytes: sum(&allocations)?, largest_allocation_bytes: allocations.into_iter().max().unwrap() };
        // These geometry-independent formulas are shared with the unchanged
        // native owned-seed and preceding planner lifecycles, without overlap
        // credit against any separately retained runtime owner.
        let configuration = OwnedConfigurationCensus::new().map_err(|_| Error::SharedCensus)?;
        let planner = LegacyPlannerCensus::new().map_err(|_| Error::SharedCensus)?;
        let periodic_staging_bytes = sum(&[
            PERIODIC_COLUMNS * PERIOD * (size_of::<Val>() + 2 * size_of::<u64>()),
            PERIODIC_COLUMNS * (size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + size_of::<usize>()),
            2 * PERIODIC_COLUMNS * size_of::<u64>(),
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // AesLaneAir::eval has exactly public[12], periodic[31], phase[4]
        // Vec payloads. Symbolic expression nodes belong to HOST_BYTES.
        let air_callback_heap_bytes = sum(&[PUBLIC_VALUES * size_of::<Public>(),
            PERIODIC_COLUMNS * size_of::<Expr>(), 4 * size_of::<Expr>()])?;
        let public_readback_and_conversion_bytes = 2 * PUBLIC_VALUES * size_of::<Val>() + 2 * size_of::<Vec<Val>>();
        let trace_upload_staging_bytes = (STAGING_WORDS + 12) * size_of::<u64>();
        let trace_matrix_backing_bytes = mul(5, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            4 * size_of::<Self>(), size_of::<uni::Prepared>(), size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(), 2 * size_of::<DeviceSession>(), size_of::<ProofCapacity>(),
            5 * size_of::<DeviceMatrix>(), size_of::<ocl::Queue>(), 5 * size_of::<MatrixSpec>(),
            16 * size_of::<usize>(), 2 * size_of::<AesTraceSpec>(), size_of::<Vec<Public>>(),
            2 * size_of::<Vec<Expr>>(), size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
            4 * size_of::<OwnedConfigurationCensus>(), 4 * size_of::<LegacyPlannerCensus>(),
            4 * size_of::<Result<OwnedConfigurationCensus>>(), 4 * size_of::<Result<LegacyPlannerCensus>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[symbolic_compiler_bytes, periodic_staging_bytes,
            air_callback_heap_bytes, public_readback_and_conversion_bytes, trace_upload_staging_bytes,
            trace_matrix_backing_bytes, explicit_owner_bytes, configuration.required_host_bytes(), planner.required_host_bytes()])?;
        let host = AesPreparationHost { symbolic_compiler_bytes, periodic_staging_bytes, air_callback_heap_bytes,
            public_readback_and_conversion_bytes, trace_upload_staging_bytes, trace_matrix_backing_bytes,
            explicit_owner_bytes, required_host_bytes };
        Ok(Self { geometry, host, trace_device, configuration, planner })
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
