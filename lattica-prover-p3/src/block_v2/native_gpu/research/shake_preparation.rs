//! Pure source census for the fixed native SHAKE lane preparation paths.
//!
//! These numbers are not reservations, capabilities or whole-proof admission.
//! The consumer must retain its original shared-ledger preparation owner through
//! normalization and PCS. Raw input backing, runtime ownership, OCL wrappers,
//! reports, later PCS payload and independent verification remain additive.
use super::{GeneratedTrace, TraceContext};
use crate::block_v2::native_gpu::ShakeTraceSpec;
use crate::block_v2::{
    gpu_hash::device::{self, DeviceMatrix, DeviceSession, MatrixSpec, ProofCapacity},
    gpu_quotient_prover::uni,
    machine::symbolic,
    pcs_field::PcsField,
    profile,
    randomness::ProofRng,
    resident_pcs::ResidentState,
};
use crate::config::{Val, ValMmcs};
use core::mem::{align_of, size_of};
use p3_air::AirBuilder;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

const RATE: usize = 136;
const ROWS_PER_PERMUTATION: usize = 4096;
const MAX_ROWS: usize = 1 << 20;
const PUBLIC_VALUES: usize = 216;
const PERIODIC_COLUMNS: usize = 42;
const PERIOD: usize = 128;
const STAGING_WORDS: usize = 2048;
const PREPARATION_WORDS: usize = 133;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Error {
    UnsupportedProfile,
    Length,
    Segment,
    Transition,
    RowLimit,
    Overflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ShakeLaneLayout {
    Singleton,
    HomogeneousBatch,
}

macro_rules! getters {
    ($($name:ident : $ty:ty),* $(,)?) => {$(
        pub const fn $name(self) -> $ty { self.$name }
    )*};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ShakePreparationGeometry {
    layout: ShakeLaneLayout,
    input_len: usize,
    output_len: usize,
    first_permutation: usize,
    permutations: usize,
    rows: usize,
    width: usize,
    public_values: usize,
    periodic_columns: usize,
    periodic_length: usize,
}

impl ShakePreparationGeometry {
    getters!(layout: ShakeLaneLayout, input_len: usize, output_len: usize,
        first_permutation: usize, permutations: usize, rows: usize, width: usize,
        public_values: usize, periodic_columns: usize, periodic_length: usize);

    pub const fn trace_spec(self) -> ShakeTraceSpec {
        ShakeTraceSpec {
            input_len: self.input_len,
            output_len: self.output_len,
            first_permutation: self.first_permutation,
            permutations: self.permutations,
        }
    }

    pub const fn kernel_kind(self) -> u32 {
        match self.layout {
            ShakeLaneLayout::Singleton => 2,
            ShakeLaneLayout::HomogeneousBatch => 3,
        }
    }
}

/// The five simultaneous crypto_trace matrices. Runtime constants, staging,
/// random streams, transcript buffers and later PCS matrices are not included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ShakeTraceDeviceFootprint {
    trace_bytes: usize,
    public_bytes: usize,
    source_bytes: usize,
    scratch_bytes: usize,
    geometry_bytes: usize,
    generation_peak_bytes: usize,
    largest_allocation_bytes: usize,
}

impl ShakeTraceDeviceFootprint {
    getters!(trace_bytes: usize, public_bytes: usize, source_bytes: usize,
        scratch_bytes: usize, geometry_bytes: usize, generation_peak_bytes: usize,
        largest_allocation_bytes: usize);

    /// Source/scratch/geometry retire after generation; public retires after
    /// checked readback. Neither event authorizes releasing the trace owner.
    pub fn generated_output_bytes(self) -> Result<usize, Error> {
        add(self.trace_bytes, self.public_bytes)
    }
}

/// Allocation-request census for R004's owned fresh-seed configuration path.
/// This deliberately includes the maintained opening runtime host partition;
/// no overlap credit is taken against an enclosing original runtime owner.
/// It excludes the legacy make_gpu_proving_config/Prepared::config TLS path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OwnedConfigurationCensus {
    permutation_backing_bytes: usize,
    cpu_mmcs_backing_bytes: usize,
    shared_rng_backing_bytes: usize,
    empty_dft_cache_backing_bytes: usize,
    resident_state_backing_bytes: usize,
    device_rng_backing_bytes: usize,
    opening_runtime_host_partition_bytes: usize,
    owned_seed_and_configuration_bytes: usize,
    required_host_bytes: usize,
}

impl OwnedConfigurationCensus {
    getters!(permutation_backing_bytes: usize, cpu_mmcs_backing_bytes: usize,
        shared_rng_backing_bytes: usize, empty_dft_cache_backing_bytes: usize,
        resident_state_backing_bytes: usize, device_rng_backing_bytes: usize,
        opening_runtime_host_partition_bytes: usize,
        owned_seed_and_configuration_bytes: usize, required_host_bytes: usize);

    pub(super) fn new() -> Result<Self, Error> {
        // Radix2DitParallel's six initially empty Arc<spin::RwLock<BTreeMap>>
        // caches. HeapNormalizedDft's default wrappers add no backing.
        #[repr(C)]
        struct EmptyCache {
            _lock: core::sync::atomic::AtomicUsize,
            _map: std::collections::BTreeMap<usize, usize>,
        }
        // Initial permutation; hash/compress; reference-FRI clone;
        // resident opening-FRI clone. Active shares do not clone a stream.
        let permutation_backing_bytes = 7 * (32 + 22 + 32) * size_of::<Val>();
        let cpu_mmcs_backing_bytes = mul(3, arc_bytes::<ValMmcs>())?;
        let shared_rng_backing_bytes = mul(5, ProofRng::host_storage_bytes())?;
        let empty_dft_cache_backing_bytes = mul(6, arc_bytes::<EmptyCache>())?;
        let resident_state_backing_bytes = add(
            arc_bytes::<ResidentState<profile::Challenge>>(),
            arc_bytes::<core::sync::atomic::AtomicBool>(),
        )?;
        let device_rng_backing_bytes = mul(4, device::retained_stream_host_backing())?;
        let opening_runtime_host_partition_bytes =
            device::opening_runtime_host_bound().map_err(|_| Error::Overflow)?;
        // Producer-owned seeds, helper arguments, all three expanded RNGs,
        // and configuration. SysRng has no source-owned heap on pinned Linux.
        // Charge seed transfer copies without relying on compiler elision.
        let owned_seed_and_configuration_bytes = sum(&[
            2 * size_of::<[[u8; 32]; 3]>(),
            size_of::<[ChaCha20Rng; 3]>(),
            size_of::<rand::rngs::SysRng>(),
            size_of::<profile::Config>(),
            size_of::<Self>(),
        ])?;
        let required_host_bytes = sum(&[
            permutation_backing_bytes,
            cpu_mmcs_backing_bytes,
            shared_rng_backing_bytes,
            empty_dft_cache_backing_bytes,
            resident_state_backing_bytes,
            device_rng_backing_bytes,
            opening_runtime_host_partition_bytes,
            owned_seed_and_configuration_bytes,
        ])?;
        Ok(Self {
            permutation_backing_bytes,
            cpu_mmcs_backing_bytes,
            shared_rng_backing_bytes,
            empty_dft_cache_backing_bytes,
            resident_state_backing_bytes,
            device_rng_backing_bytes,
            opening_runtime_host_partition_bytes,
            owned_seed_and_configuration_bytes,
            required_host_bytes,
        })
    }
}

/// Original reserve_wallet_proof_capacity -> Plan::new -> Plan::report path.
/// The newer exact-capacity/streaming constructor is not silently substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LegacyPlannerCensus {
    maintained_bounded_planner_bytes: usize,
    original_vector_requests_bytes: usize,
    original_json_requests_bytes: usize,
    required_host_bytes: usize,
}

impl LegacyPlannerCensus {
    getters!(maintained_bounded_planner_bytes: usize,
        original_vector_requests_bytes: usize, original_json_requests_bytes: usize,
        required_host_bytes: usize);

    pub(super) fn new() -> Result<Self, Error> {
        // This maintained helper counts actual private planner element types,
        // exact maximum record counts, temporary planners and failure scratch.
        let maintained_bounded_planner_bytes = device::WalletPlannerResources::new()
            .map_err(|_| Error::UnsupportedProfile)?
            .required_host_bytes();
        // All seven final capacities are >=4 elements. For push growth from
        // 4 by doubling, cumulative capacities 4+8+...+C < 2C < 4n.
        // Applying 4 to the entire bounded census also overcharges its
        // sequential temporary/inline/failure storage instead of releasing it.
        let original_vector_requests_bytes = mul(4, maintained_bounded_planner_bytes)?;
        let original_json_requests_bytes = legacy_json_requests()?;
        let required_host_bytes =
            add(original_vector_requests_bytes, original_json_requests_bytes)?;
        Ok(Self {
            maintained_bounded_planner_bytes,
            original_vector_requests_bytes,
            original_json_requests_bytes,
            required_host_bytes,
        })
    }
}

fn legacy_json_requests() -> Result<usize, Error> {
    use serde_json::{Map, Value};
    // Pinned serde_json BTreeMap layout, not preserve_order. Dependency features
    // remain pinned by the enclosing build manifest. Scalar strings below also
    // conservatively cover decimal Number backing if that feature is unified.
    if size_of::<Map<String, Value>>() != size_of::<std::collections::BTreeMap<String, Value>>()
        || size_of::<Value>() != 32
    {
        return Err(Error::UnsupportedProfile);
    }
    // phases, quotient tiles, operations, randomness, FRI, commitments, inputs.
    // Same maxima as planner_storage, including all five quotient partitions.
    let records = [76usize, 5, 15, 43, 50, 11, 10];
    let fields = [3usize, 4, 7, 9, 8, 7, 6];
    let mut objects = 1usize;
    let mut entries = 26usize; // Plan::report's root object.
    let mut array_items = 0usize;
    for (count, fields) in records.into_iter().zip(fields) {
        objects = add(objects, count)?;
        entries = add(entries, mul(count, fields)?)?;
        array_items = add(array_items, count)?;
    }
    // Rust 1.96 BTree node: parent pointer, two u16 fields, 11 keys/values,
    // and up to 12 child pointers. Four alignment units conservatively cover
    // all field/node padding; every node is charged at the larger internal size.
    let node_bytes = sum(&[
        size_of::<usize>(),
        2 * size_of::<u16>(),
        11 * (size_of::<String>() + size_of::<Value>()),
        12 * size_of::<usize>(),
        4 * align_of::<Value>().max(align_of::<String>()),
    ])?;
    // Without removals, every allocated node contains a key except an empty
    // root; entries+objects bounds all allocations while constructing maps.
    let maps = mul(add(entries, objects)?, node_bytes)?;
    // Every key and every scalar is overcharged as an owned string. 64 covers
    // all fixed report keys/names/schema; no input-controlled text is accepted.
    let strings = mul(mul(entries, 2)?, 64)?;
    // ExactSize/TrustedLen map collects and SerializeVec::with_capacity are
    // exact; include array backing and all temporary Vec/Value owner headers.
    let root_arrays = add(
        mul(array_items, size_of::<Value>())?,
        mul(records.len(), size_of::<Vec<Value>>())?,
    )?;
    // Each commitment's allocation_bytes is [usize; 3], serialized as a
    // nested Array even though every other reported scalar is non-container.
    // Account its own backing explicitly, without using map/string overcharge.
    let commitment_arrays = commitment_array_requests()?;
    let one_tree = sum(&[
        maps,
        strings,
        root_arrays,
        commitment_arrays,
        size_of::<Value>(),
    ])?;
    // json!(iterator.collect::<Vec<Value>>()) calls to_value(&temporary):
    // original children and their serialization copy coexist. Two complete
    // trees conservatively include the root even though it is not cloned.
    mul(2, one_tree)
}

fn commitment_array_requests() -> Result<usize, Error> {
    mul(
        11,
        add(
            3 * size_of::<serde_json::Value>(),
            size_of::<Vec<serde_json::Value>>(),
        )?,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ShakePreparationHost {
    symbolic_compiler_bytes: usize,
    periodic_staging_bytes: usize,
    air_callback_heap_bytes: usize,
    public_readback_and_conversion_bytes: usize,
    trace_upload_staging_bytes: usize,
    trace_matrix_backing_bytes: usize,
    explicit_owner_bytes: usize,
    required_host_bytes: usize,
}

impl ShakePreparationHost {
    getters!(symbolic_compiler_bytes: usize, periodic_staging_bytes: usize,
        air_callback_heap_bytes: usize, public_readback_and_conversion_bytes: usize,
        trace_upload_staging_bytes: usize, trace_matrix_backing_bytes: usize,
        explicit_owner_bytes: usize, required_host_bytes: usize);

    /// This is the exact partition Prepared subtracts from the operation
    /// allowance. Keep it live through normalization and later PCS work.
    pub fn prepared_partition_bytes(self) -> Result<usize, Error> {
        add(self.symbolic_compiler_bytes, self.periodic_staging_bytes)
    }
}

/// Source-limited data only. No environment read, driver query, entropy draw,
/// AIR callback, cache entry, allocation token or dispatch method is provided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ShakePreparationPlan {
    geometry: ShakePreparationGeometry,
    host: ShakePreparationHost,
    trace_device: ShakeTraceDeviceFootprint,
    configuration: OwnedConfigurationCensus,
    planner: LegacyPlannerCensus,
}

impl ShakePreparationPlan {
    pub fn singleton(spec: ShakeTraceSpec) -> Result<Self, Error> {
        Self::new(ShakeLaneLayout::Singleton, spec)
    }

    pub fn batch(spec: ShakeTraceSpec) -> Result<Self, Error> {
        Self::new(ShakeLaneLayout::HomogeneousBatch, spec)
    }

    getters!(geometry: ShakePreparationGeometry, host: ShakePreparationHost,
        trace_device: ShakeTraceDeviceFootprint, configuration: OwnedConfigurationCensus,
        planner: LegacyPlannerCensus);

    fn new(layout: ShakeLaneLayout, spec: ShakeTraceSpec) -> Result<Self, Error> {
        pinned()?;
        if spec.input_len > u32::MAX as usize || spec.output_len > u32::MAX as usize {
            return Err(Error::Length);
        }
        if spec.permutations == 0
            || (layout == ShakeLaneLayout::Singleton && spec.permutations != 1)
        {
            return Err(Error::Segment);
        }
        let end = add(spec.first_permutation, spec.permutations)?;
        let absorb = add(spec.input_len / RATE, 1)?;
        let total = add(absorb, spec.output_len.saturating_sub(1) / RATE)?;
        if end > total {
            return Err(Error::Segment);
        }
        if layout == ShakeLaneLayout::HomogeneousBatch
            && (!spec.permutations.is_power_of_two()
                || !(end <= spec.input_len / RATE
                    || (spec.first_permutation >= absorb
                        && end <= add(absorb - 1, spec.output_len / RATE)?)))
        {
            return Err(Error::Transition);
        }
        let rows = mul(spec.permutations, ROWS_PER_PERMUTATION)?;
        if rows > MAX_ROWS {
            return Err(Error::RowLimit);
        }
        let width = match layout {
            ShakeLaneLayout::Singleton => 517,
            ShakeLaneLayout::HomogeneousBatch => 518,
        };
        let geometry = ShakePreparationGeometry {
            layout,
            input_len: spec.input_len,
            output_len: spec.output_len,
            first_permutation: spec.first_permutation,
            permutations: spec.permutations,
            rows,
            width,
            public_values: PUBLIC_VALUES,
            periodic_columns: PERIODIC_COLUMNS,
            periodic_length: PERIOD,
        };
        let allocations = [
            mul(mul(rows, width)?, 8)?,
            PUBLIC_VALUES * 8,
            mul(spec.input_len.max(1), 8)?,
            mul(
                add(mul(spec.permutations, PREPARATION_WORDS)?, PUBLIC_VALUES)?,
                8,
            )?,
            12 * 8,
        ];
        let trace_device = ShakeTraceDeviceFootprint {
            trace_bytes: allocations[0],
            public_bytes: allocations[1],
            source_bytes: allocations[2],
            scratch_bytes: allocations[3],
            geometry_bytes: allocations[4],
            generation_peak_bytes: sum(&allocations)?,
            largest_allocation_bytes: allocations.into_iter().max().unwrap(),
        };
        let configuration = OwnedConfigurationCensus::new()?;
        let planner = LegacyPlannerCensus::new()?;
        // Exactly uni::admission::periodic::Source's conservative coexistence:
        // fields, canonical word columns, flattened upload, outer vectors,
        // captured lengths and offset/length metadata. The source is retained.
        let periodic_staging_bytes = sum(&[
            PERIODIC_COLUMNS * PERIOD * (size_of::<Val>() + 2 * size_of::<u64>()),
            PERIODIC_COLUMNS * (size_of::<Vec<Val>>() + size_of::<Vec<u64>>() + size_of::<usize>()),
            2 * PERIODIC_COLUMNS * size_of::<u64>(),
        ])?;
        type Expr = <symbolic::Builder as AirBuilder>::Expr;
        type Public = <symbolic::Builder as AirBuilder>::PublicVar;
        // Both fixed AIRs have these exact four Vec allocations outside the
        // recorder's own quota. Expression node backing remains in HOST_BYTES.
        let air_callback_heap_bytes = sum(&[
            PUBLIC_VALUES * size_of::<Public>(),
            PERIODIC_COLUMNS * size_of::<Expr>(),
            5 * size_of::<Expr>(),
            4 * size_of::<(Expr, Expr, Expr, Expr)>(),
        ])?;
        let public_readback_and_conversion_bytes =
            2 * PUBLIC_VALUES * size_of::<Val>() + 2 * size_of::<Vec<Val>>();
        let trace_upload_staging_bytes = (STAGING_WORDS + 12) * size_of::<u64>();
        let trace_matrix_backing_bytes = mul(5, device::matrix_host_backing(false))?;
        let explicit_owner_bytes = sum(&[
            size_of::<Self>(),
            size_of::<uni::Prepared>(),
            size_of::<TraceContext<'static>>(),
            size_of::<GeneratedTrace>(),
            2 * size_of::<DeviceSession>(),
            size_of::<ProofCapacity>(),
            5 * size_of::<DeviceMatrix>(),
            size_of::<ocl::Queue>(),
            5 * size_of::<MatrixSpec>(),
            4 * size_of::<usize>(),
            2 * size_of::<ShakeTraceSpec>(),
            size_of::<Vec<Public>>(),
            2 * size_of::<Vec<Expr>>(),
            size_of::<Vec<(Expr, Expr, Expr, Expr)>>(),
            size_of::<p3_poseidon2_air::RoundConstants<Val, 8, 4, 22>>(),
        ])?;
        let symbolic_compiler_bytes = symbolic::HOST_BYTES as usize;
        let required_host_bytes = sum(&[
            symbolic_compiler_bytes,
            periodic_staging_bytes,
            air_callback_heap_bytes,
            public_readback_and_conversion_bytes,
            trace_upload_staging_bytes,
            trace_matrix_backing_bytes,
            explicit_owner_bytes,
            configuration.required_host_bytes(),
            planner.required_host_bytes(),
        ])?;
        let host = ShakePreparationHost {
            symbolic_compiler_bytes,
            periodic_staging_bytes,
            air_callback_heap_bytes,
            public_readback_and_conversion_bytes,
            trace_upload_staging_bytes,
            trace_matrix_backing_bytes,
            explicit_owner_bytes,
            required_host_bytes,
        };
        Ok(Self {
            geometry,
            host,
            trace_device,
            configuration,
            planner,
        })
    }
}

fn pinned() -> Result<(), Error> {
    if size_of::<usize>() != 8
        || size_of::<Val>() != 8
        || size_of::<profile::Challenge>() != 24
        || (
            profile::LOG_BLOWUP,
            profile::NUM_QUERIES,
            profile::CAP_HEIGHT,
            profile::NUM_RANDOM_CODEWORDS,
            profile::QUERY_POW_BITS,
            profile::MAX_QUOTIENT_CHUNKS,
        ) != (4, 128, 6, 4, 16, 32)
        || <profile::Challenge as PcsField>::MAX_LOG_ARITY != 1
        || symbolic::HOST_BYTES != 192 << 20
        || p3_poseidon2_air::num_cols::<8, 7, 0, 4, 22>() != 94
    {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}

fn arc_bytes<T>() -> usize {
    #[repr(C)]
    struct Allocation<T> {
        _strong: core::sync::atomic::AtomicUsize,
        _weak: core::sync::atomic::AtomicUsize,
        _value: T,
    }
    size_of::<Allocation<T>>()
}

fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or(Error::Overflow)
}
fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0, |total, &bytes| add(total, bytes))
}

#[cfg(test)]
mod tests;
