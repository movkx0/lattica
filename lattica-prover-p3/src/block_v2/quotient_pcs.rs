//! Experimental, prove-only fusion of quotient interpolation and hiding masks.
//!
//! Opt-in research adapter for the pinned quadratic and cubic profiles. Proof
//! types and verification delegate to upstream PCS; fusion is disabled by default.
//! A separate full-entropy quotient RNG is required; NEVER clone the inner
//! witness-randomization seed to initialize it. Deterministic seeds are tests
//! only. Component equivalence is not a complete-tree zero-knowledge review.

use super::profile::Challenger;
use crate::config::Val;
use p3_commit::{BuildPeriodicLdeTableFast, OpenedValues, Pcs, PeriodicLdeTable, PolynomialSpace};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{batch_multiplicative_inverse, Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::RngExt;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, OnceLock};

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::extension_mmcs::CandidateExtensionMmcs as ExtensionMmcs;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::gpu_hash::CandidateMmcs as ValMmcs;
#[cfg(feature = "stream")]
use super::normalization_workspace::HeapNormalizedDft as Dft;
use super::pcs_field::PcsField;
use super::profile::{self, Challenge};
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use p3_commit::ExtensionMmcs;
type ChallengeMmcs<E = Challenge> = ExtensionMmcs<Val, E, ValMmcs>;
#[cfg(not(feature = "stream"))]
use crate::config::Dft;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::config::ValMmcs;

type Domain = TwoAdicMultiplicativeCoset<Val>;
type Inner<E = Challenge> = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs<E>, ChaCha20Rng>;

// This component admits at most the existing bounded-heap DFT workspace size.
// It does not substitute for the worker/slice RAM and scratch limits, or account
// for all other matrices retained by the enclosing proof.
const MAX_CHUNK_LDE_BYTES: usize = 2 << 30;
const MAX_CHUNKS: usize = profile::MAX_QUOTIENT_CHUNKS;

static RESEARCH_FUSION: OnceLock<bool> = OnceLock::new();
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct GpuSelection {
    quotient: bool,
    quotient_eval: bool,
    quotient_resident: bool,
    lookup: bool,
    opening_eval: bool,
    fri_resident: bool,
    device_only: bool,
    witness: bool,
    randomness: bool,
    transcript: bool,
}
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
static GPU_SELECTION: OnceLock<GpuSelection> = OnceLock::new();

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn record_gpu_selection(
    cell: &OnceLock<GpuSelection>,
    selection: GpuSelection,
) -> Result<(), String> {
    match cell.set(selection) {
        Ok(()) => Ok(()),
        Err(requested) if cell.get() == Some(&requested) => Ok(()),
        Err(_) => Err("GPU proving selection is immutable after initialization".into()),
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_quotient(value: Option<&str>, resident: bool, fusion: bool) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") if resident && fusion => Ok(true),
        _ => {
            Err("GPU quotient LDE requires ASCII 0 or 1, resident LDEs and quotient fusion".into())
        }
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_quotient_eval(
    value: Option<&str>,
    quotient_lde: bool,
    opencl: bool,
) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") if quotient_lde && opencl => Ok(true),
        _ => {
            Err("GPU quotient evaluation requires ASCII 0 or 1, OpenCL and GPU quotient LDE".into())
        }
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub fn initialize_gpu_quotient_from_env(resident: bool, fusion: bool) -> Result<bool, String> {
    let value = match std::env::var("LATTICA_V2_GPU_QUOTIENT_LDE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let enabled = parse_gpu_quotient(value.as_deref(), resident, fusion)?;
    let value = match std::env::var("LATTICA_V2_GPU_QUOTIENT_EVAL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let evaluate = parse_gpu_quotient_eval(value.as_deref(), enabled, cfg!(feature = "gpu"))?;
    let value = match std::env::var("LATTICA_V2_GPU_QUOTIENT_RESIDENT") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let resident_inputs =
        parse_gpu_quotient_eval(value.as_deref(), evaluate, cfg!(feature = "gpu")).map_err(
            |_| {
                "GPU quotient residency requires ASCII 0 or 1, OpenCL and GPU quotient evaluation"
                    .to_owned()
            },
        )?;
    let value = match std::env::var("LATTICA_V2_GPU_LOOKUP") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let lookup = parse_gpu_quotient_eval(value.as_deref(), resident_inputs, cfg!(feature = "gpu"))
        .map_err(|_| "GPU lookup requires ASCII 0 or 1 and owned OpenCL GPU quotient evaluation")?;
    let value = match std::env::var("LATTICA_V2_GPU_OPENING_EVAL") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let opening_eval = parse_gpu_quotient_eval(
        value.as_deref(),
        resident_inputs && std::env::var("LATTICA_V2_GPU_OPENINGS").as_deref() == Ok("1"),
        cfg!(feature = "gpu"),
    ).map_err(|_| "GPU opening evaluation requires ASCII 0 or 1, owned OpenCL quotient inputs and GPU openings")?;
    let value = match std::env::var("LATTICA_V2_GPU_FRI_RESIDENT") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let fri_resident =
        parse_gpu_quotient_eval(value.as_deref(), opening_eval, cfg!(feature = "gpu")).map_err(
            |_| "resident GPU FRI requires ASCII 0 or 1 and owned OpenCL opening evaluation",
        )?;
    let value = match std::env::var("LATTICA_V2_GPU_PCS_DEVICE_ONLY") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let device_only = parse_gpu_pcs_device_only(
        value.as_deref(),
        fri_resident,
        lookup,
        cfg!(feature = "gpu"),
    )?;
    let value = match std::env::var("LATTICA_V2_GPU_WITNESS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let witness = parse_gpu_witness(value.as_deref(), device_only, cfg!(feature = "gpu"))?;
    let value = match std::env::var("LATTICA_V2_GPU_RANDOMNESS") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let randomness = parse_gpu_randomness(value.as_deref(), witness, cfg!(feature = "gpu"))?;
    let value = match std::env::var("LATTICA_V2_GPU_TRANSCRIPT") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.to_string()),
    };
    let transcript = parse_gpu_transcript(value.as_deref(), randomness, cfg!(feature = "gpu"))?;
    super::machine::gpu_backend::resources::check_worker(witness, None)?;
    super::randomness::resources::check_worker(randomness, None)?;
    super::challenger::resources::check_worker(transcript)?;
    let selection = GpuSelection {
        quotient: enabled,
        quotient_eval: evaluate,
        quotient_resident: resident_inputs,
        lookup,
        opening_eval,
        fri_resident,
        device_only,
        witness,
        randomness,
        transcript,
    };
    record_gpu_selection(&GPU_SELECTION, selection)?;
    Ok(enabled)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_quotient_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.quotient)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_quotient_eval_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.quotient_eval)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_quotient_resident_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.quotient_resident)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_lookup_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.lookup)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_opening_eval_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.opening_eval)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_fri_resident_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.fri_resident)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_pcs_device_only(
    value: Option<&str>,
    fri: bool,
    lookup: bool,
    opencl: bool,
) -> Result<bool, String> {
    parse_gpu_quotient_eval(value, fri && lookup, opencl)
        .map_err(|_| "device-only GPU PCS requires ASCII 0 or 1, owned OpenCL lookup, openings and resident FRI".into())
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_pcs_device_only_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.device_only)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_witness(value: Option<&str>, device_only: bool, opencl: bool) -> Result<bool, String> {
    parse_gpu_quotient_eval(value, device_only, opencl).map_err(|_| {
        "GPU witness construction requires ASCII 0 or 1 and device-only OpenCL PCS".into()
    })
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_witness_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.witness)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_randomness(value: Option<&str>, witness: bool, opencl: bool) -> Result<bool, String> {
    parse_gpu_quotient_eval(value, witness, opencl).map_err(|_| {
        "GPU randomness requires ASCII 0 or 1 and registered device-only OpenCL witnesses".into()
    })
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_randomness_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.randomness)
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
fn parse_gpu_transcript(
    value: Option<&str>,
    randomness: bool,
    opencl: bool,
) -> Result<bool, String> {
    parse_gpu_quotient_eval(value, randomness, opencl).map_err(|_| {
        "GPU transcript requires ASCII 0 or 1 and registered private OpenCL randomness".into()
    })
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) fn gpu_transcript_enabled() -> bool {
    GPU_SELECTION
        .get()
        .is_some_and(|selection| selection.transcript)
}

fn parse_research_mode(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err("LATTICA_V2_QUOTIENT_FUSION must be 0 or 1"),
    }
}

fn record_research_mode(mode: &OnceLock<bool>, enabled: bool) -> Result<(), &'static str> {
    if let Some(previous) = mode.get() {
        return if *previous == enabled {
            Ok(())
        } else {
            Err("quotient mode cannot change during a research process")
        };
    }
    mode.set(enabled)
        .map_err(|_| "quotient mode initialized concurrently")
}

/// Call ONLY from explicit research-runner entrypoints, before starting work.
/// Merely setting an environment variable never changes a library config or
/// the default verifier. There is no C ABI or production activation here.
pub fn initialize_research_from_env() -> Result<bool, String> {
    let value = match std::env::var("LATTICA_V2_QUOTIENT_FUSION") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("LATTICA_V2_QUOTIENT_FUSION must be ASCII 0 or 1".into());
        }
    };
    let enabled = parse_research_mode(value.as_deref()).map_err(str::to_owned)?;
    record_research_mode(&RESEARCH_FUSION, enabled).map_err(str::to_owned)?;
    Ok(enabled)
}

pub(crate) fn research_enabled() -> bool {
    RESEARCH_FUSION.get().copied().unwrap_or(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FusionError {
    UnsupportedParameters,
    ChunkCount,
    EmptyWidth,
    DomainSize,
    MatrixShape,
    OverlappingDomains,
    ArithmeticOverflow,
    WorkspaceLimit,
}

fn collect_inputs(
    evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
    chunks: usize,
) -> Result<Vec<(Domain, RowMajorMatrix<Val>)>, FusionError> {
    if !(2..=MAX_CHUNKS).contains(&chunks) || !chunks.is_power_of_two() {
        return Err(FusionError::ChunkCount);
    }
    let mut inputs = Vec::with_capacity(chunks);
    for input in evaluations.into_iter().take(chunks + 1) {
        if inputs.len() == chunks {
            return Err(FusionError::ChunkCount);
        }
        inputs.push(input);
    }
    if inputs.len() != chunks {
        return Err(FusionError::ChunkCount);
    }
    Ok(inputs)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Geometry {
    log_height: usize,
    height: usize,
    input_elements: usize,
    width: usize,
    chunk_elements: usize,
    mask_elements: usize,
    lde_elements: usize,
    chunk_lde_bytes: usize,
    retained_lde_bytes: usize,
}

impl Geometry {
    fn new(
        log_height: usize,
        input_width: usize,
        chunks: usize,
        log_blowup: usize,
        random_columns: usize,
    ) -> Result<Self, FusionError> {
        // No security-parameter tuning is exposed by this optimization.
        if log_blowup != profile::LOG_BLOWUP || random_columns != profile::NUM_RANDOM_CODEWORDS {
            return Err(FusionError::UnsupportedParameters);
        }
        if !(2..=MAX_CHUNKS).contains(&chunks) || !chunks.is_power_of_two() {
            return Err(FusionError::ChunkCount);
        }
        if input_width == 0 {
            return Err(FusionError::EmptyWidth);
        }
        let lde_log = log_height
            .checked_add(log_blowup)
            .and_then(|x| x.checked_add(1))
            .filter(|&x| x <= 32)
            .ok_or(FusionError::DomainSize)?;
        let height = 1usize
            .checked_shl(log_height as u32)
            .ok_or(FusionError::ArithmeticOverflow)?;
        let width = input_width
            .checked_add(random_columns)
            .ok_or(FusionError::ArithmeticOverflow)?;
        let input_elements = height
            .checked_mul(input_width)
            .ok_or(FusionError::ArithmeticOverflow)?;
        let chunk_elements = height
            .checked_mul(width)
            .ok_or(FusionError::ArithmeticOverflow)?;
        let mask_elements = chunk_elements
            .checked_mul(chunks)
            .ok_or(FusionError::ArithmeticOverflow)?;
        let lde_elements = 1usize
            .checked_shl(lde_log as u32)
            .and_then(|x| x.checked_mul(width))
            .ok_or(FusionError::ArithmeticOverflow)?;
        let chunk_lde_bytes = lde_elements
            .checked_mul(core::mem::size_of::<Val>())
            .ok_or(FusionError::ArithmeticOverflow)?;
        let retained_lde_bytes = chunk_lde_bytes
            .checked_mul(chunks)
            .ok_or(FusionError::ArithmeticOverflow)?;
        if chunk_lde_bytes > MAX_CHUNK_LDE_BYTES {
            return Err(FusionError::WorkspaceLimit);
        }
        Ok(Self {
            log_height,
            height,
            input_elements,
            width,
            chunk_elements,
            mask_elements,
            lde_elements,
            chunk_lde_bytes,
            retained_lde_bytes,
        })
    }
}

fn preflight(
    evaluations: &[(Domain, RowMajorMatrix<Val>)],
    chunks: usize,
    log_blowup: usize,
    random_columns: usize,
) -> Result<(Geometry, Vec<Val>), FusionError> {
    if evaluations.len() != chunks || evaluations.is_empty() {
        return Err(FusionError::ChunkCount);
    }
    let geometry = Geometry::new(
        evaluations[0].0.log_size(),
        evaluations[0].1.width,
        chunks,
        log_blowup,
        random_columns,
    )?;
    for (domain, matrix) in evaluations {
        if domain.log_size() != geometry.log_height {
            return Err(FusionError::DomainSize);
        }
        if matrix.width != evaluations[0].1.width || matrix.values.len() != geometry.input_elements
        {
            return Err(FusionError::MatrixShape);
        }
    }
    // Match upstream's NORMALIZED vanishing polynomials: (X/s)^h - 1,
    // not X^h - s^h. Validate disjointness before inversions or RNG draws.
    let mut denominators = Vec::with_capacity(chunks);
    for (i, (domain, _)) in evaluations.iter().enumerate() {
        let mut denominator = Val::ONE;
        for (j, (other, _)) in evaluations.iter().enumerate() {
            if i != j {
                denominator *= other.vanishing_poly_at_point(domain.first_point());
            }
        }
        if denominator == Val::ZERO {
            return Err(FusionError::OverlappingDomains);
        }
        denominators.push(denominator);
    }
    Ok((geometry, batch_multiplicative_inverse(&denominators)))
}

// Shared by CPU fusion and GPU quotient commitments. Admission must precede RNG draws.
fn randomized_quotients(
    evaluations: Vec<(Domain, RowMajorMatrix<Val>)>,
    geometry: Geometry,
    weights: &[Val],
    random_columns: usize,
    rng: &super::randomness::ProofRng,
) -> (Vec<(Domain, RowMajorMatrix<Val>)>, Vec<Val>) {
    let chunks = evaluations.len();
    let (randomized, mut masks) = {
        let mut rng = rng.lock().expect("quotient RNG poisoned");
        // Exact upstream component draw ordering: widen ALL matrices first,
        // then draw masks for chunks [0, last), then construct the last mask.
        let randomized: Vec<_> = evaluations
            .into_iter()
            .map(|(domain, matrix)| (domain, matrix.with_random_cols(random_columns, &mut *rng)))
            .collect();
        let random_len = geometry.mask_elements - geometry.chunk_elements;
        // Reserve the final size through the exact iterator hint. Collecting
        // only the random prefix then resizing could double Vec capacity.
        let masks: Vec<Val> = (0..random_len)
            .map(|_| rng.random())
            .chain(core::iter::repeat_n(Val::ZERO, geometry.chunk_elements))
            .collect();
        (randomized, masks)
    };
    let last = chunks - 1;
    let last_inverse = weights[last].inverse();
    let last_offset = last * geometry.chunk_elements;
    for (i, weight) in weights.iter().take(last).enumerate() {
        let scale = *weight * last_inverse;
        for j in 0..geometry.chunk_elements {
            let value = masks[i * geometry.chunk_elements + j] * scale;
            masks[last_offset + j] -= value;
        }
    }
    (randomized, masks)
}

fn fused_ldes<D: TwoAdicSubgroupDft<Val>>(
    dft: &D,
    evaluations: Vec<(Domain, RowMajorMatrix<Val>)>,
    chunks: usize,
    log_blowup: usize,
    random_columns: usize,
    rng: &super::randomness::ProofRng,
) -> Result<Vec<RowMajorMatrix<Val>>, FusionError>
where
    D::Evaluations: BitReversibleMatrix<Val, BitRev = RowMajorMatrix<Val>>,
{
    let (geometry, weights) = preflight(&evaluations, chunks, log_blowup, random_columns)?;
    let _phase = tracing::info_span!(
        target: "lattica_block_v2_perf", "fused quotient ldes",
        chunks, height = geometry.height, width = geometry.width,
        chunk_lde_bytes = geometry.chunk_lde_bytes,
        retained_lde_bytes = geometry.retained_lde_bytes,
    )
    .entered();
    let (randomized, masks) =
        randomized_quotients(evaluations, geometry, &weights, random_columns, rng);
    randomized
        .into_iter()
        .enumerate()
        .map(|(chunk, (domain, matrix))| {
            let _phase = tracing::info_span!(
                target: "lattica_block_v2_perf", "fused quotient chunk", chunk
            )
            .entered();
            let coefficients = dft.idft_batch(matrix);
            // Goldilocks::zero_vec uses a zeroed allocation. With spilling
            // armed, the existing allocator leaves the fresh file-backed
            // zero tail lazy. Avoid resize(), which explicitly initializes
            // all added elements of this much larger coefficient buffer.
            let mut fused =
                RowMajorMatrix::new(Val::zero_vec(geometry.lde_elements), geometry.width);
            let ratio = Val::GENERATOR / domain.shift();
            let ratio_h = ratio.exp_u64(geometry.height as u64);
            let mask =
                &masks[chunk * geometry.chunk_elements..(chunk + 1) * geometry.chunk_elements];
            for (row, (ratio_power, generator_power)) in ratio
                .powers()
                .zip(Val::GENERATOR.powers())
                .take(geometry.height)
                .enumerate()
            {
                let offset = row * geometry.width;
                for col in 0..geometry.width {
                    let index = offset + col;
                    let random = generator_power * mask[index];
                    fused.values[index] = coefficients.values[index] * ratio_power - random;
                    fused.values[geometry.chunk_elements + index] = ratio_h * random;
                }
            }
            drop(coefficients);
            // One large forward transform. Cancellation of the bit-reversed
            // evaluation view exposes physical commitment storage directly.
            // Under HeapNormalizedDft the bounded heap allocation is retained,
            // not silently converted back to a spill-mapped quotient matrix.
            // Require an owned physical buffer at the type boundary. Upstream's
            // DenseStorage<Vec<_>>::to_vec also preserves ownership; this direct
            // return makes that property explicit without another conversion.
            Ok(dft.dft_batch(fused).bit_reverse_rows())
        })
        .collect()
}

// Reference construction preserves the existing deep-clone semantics. Resident
// clones must instead share the *whole* attempt, including the upstream PCS's
// input/FRI MMCSs; cloning just its RNG handle would still replay MMCS salts.
#[derive(Clone)]
enum Backend<E: PcsField = Challenge> {
    Reference(Inner<E>),
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    Resident(Arc<super::resident_pcs::ResidentState<E>>),
}

// The RNG type is not part of any PCS proof or prover-data type. Keep the
// associated types below pinned to the existing reference PCS and let Rust
// check that every resident delegation returns those exact same types.
macro_rules! delegate_pcs {
    ($pcs:expr, $method:ident $(, $arg:expr)* $(,)?) => {
        match &$pcs.inner {
            Backend::Reference(inner) =>
                <Inner<E> as Pcs<E, Challenger>>::$method(inner $(, $arg)*),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Resident(state) => {
                state.lock_opening_mode();
                <super::resident_pcs::ResidentInner<E> as Pcs<E, Challenger>>::$method(
                    &state.inner $(, $arg)*
                )
            },
        }
    };
}

/// Hiding PCS adapter with the candidate cubic field as its default.
#[derive(Clone)]
pub struct CandidatePcs<E: PcsField = Challenge> {
    inner: Backend<E>,
    dft: Dft,
    log_blowup: usize,
    random_columns: usize,
    // Clones share the stream, so a wrapper clone cannot replay quotient masks.
    // Production still constructs a fresh complete config for every proof.
    quotient_rng: Option<super::randomness::ProofRng>,
}

impl<E: PcsField> CandidatePcs<E> {
    /// Resident clones share the immutable allowance of their original attempt.
    /// Reference configurations retain their existing process-wide limit.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn host_output_budget(&self) -> usize {
        match &self.inner {
            Backend::Resident(state) => state.host_budget,
            Backend::Reference(_) => super::resident_pcs::host_output_budget(),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn device_preprocessing_salts(&self) -> Result<bool, String> {
        match &self.inner {
            Backend::Resident(state) if state.device_randomness.is_none() => {
                Ok(state.preprocessing_salts.is_some())
            }
            _ => Err("cached preprocessing requires its public resident PCS".into()),
        }
    }
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn randomization_device(
        &self,
        domains: impl IntoIterator<Item = super::gpu_hash::device::DomainSpec>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        match &self.inner {
            Backend::Resident(state) => state.randomization_device(domains),
            _ => Err("owned randomization requires resident PCS".into()),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn require_host_storage(&self) -> Result<(), String> {
        if let Backend::Resident(state) = &self.inner {
            if state.mmcs.uses_device_storage() {
                return Err("device-only PCS requires the owned GPU interface; host PCS arithmetic is unavailable".into());
            }
        }
        Ok(())
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn quotient_session(
        &self,
    ) -> Result<super::gpu_hash::device::DeviceSession, String> {
        match &self.inner {
            Backend::Resident(state) => state
                .device_session
                .clone()
                .ok_or_else(|| "PCS has no owned quotient session".into()),
            _ => Err("owned quotient evaluation requires resident PCS".into()),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn quotient_device_prefix(
        &self,
        data: &<Self as Pcs<E, Challenger>>::ProverData,
        index: usize,
        domain: impl Into<super::gpu_hash::device::DomainSpec>,
        columns: usize,
        extension: super::gpu_hash::device::Extension,
    ) -> Result<super::gpu_hash::device::DeviceMatrix, String> {
        use p3_field::PrimeField64;
        let domain = domain.into();
        let session = self.quotient_session()?;
        let input = data.owned_matrix(&session, index)?;
        session.quotient_input(
            &input,
            (domain.log_size() as u32).min(input.spec().rows().trailing_zeros()),
            domain.shift().as_canonical_u64(),
            columns,
            extension,
        )
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn lookup_original_trace(
        &self,
        data: &<Self as Pcs<E, Challenger>>::ProverData,
        index: usize,
        log_rows: u32,
        columns: usize,
    ) -> Result<super::gpu_hash::device::DeviceMatrix, String> {
        let session = self.quotient_session()?;
        let prefix = data.owned_matrix(&session, index)?;
        session.original_trace(&prefix, log_rows, columns)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_lookup_device(
        &self,
        inputs: Vec<(
            impl Into<super::gpu_hash::device::DomainSpec>,
            super::gpu_hash::device::DeviceMatrix,
        )>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        self.commit_trace_device(inputs, E::DEVICE_EXTENSION)
    }

    /// Commit a natural-order base-field witness without a host trace copy.
    /// Lookup and main inputs have separate typed entry points so accepting
    /// base fields here does not weaken the existing lookup contract.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_main_device(
        &self,
        inputs: Vec<(
            impl Into<super::gpu_hash::device::DomainSpec>,
            super::gpu_hash::device::DeviceMatrix,
        )>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        self.commit_trace_device(inputs, super::gpu_hash::device::Extension::Base)
    }

    /// Only compiler-generated deterministic columns can enter this path.
    /// The committed prefixes become public; salts keep their existing
    /// separate host storage and no private matrix is promoted.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_preprocessing_device(
        &self,
        inputs: Vec<(
            super::gpu_hash::device::DomainSpec,
            super::gpu_hash::device::PreprocessingTrace,
        )>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        use super::gpu_hash::device::TraceCommitShape;
        let Backend::Resident(state) = &self.inner else {
            return Err("device preprocessing requires resident PCS".into());
        };
        if state.device_randomness.is_some() {
            return Err("private GPU randomness cannot create reusable preprocessing; use trusted public setup".into());
        }
        state.lock_opening_mode();
        let session = self.quotient_session()?;
        let mut shapes = Vec::with_capacity(inputs.len());
        for (domain, trace) in &inputs {
            trace.check_session(&session)?;
            let shape = TraceCommitShape::preprocessing(trace.spec())?;
            if domain.size() != shape.height || domain.shift() != Val::ONE {
                return Err(
                    "device preprocessing does not match its doubled subgroup domain".into(),
                );
            }
            shapes.push(shape);
        }
        if let Some(stream) = &state.preprocessing_salts {
            let stream = stream.lock().map_err(|_| "public salt stream poisoned")?;
            let plan = state
                .mmcs
                .preflight_public_preprocessing_salts(&shapes, state.host_budget)?;
            let pending: Vec<_> = shapes.iter().flat_map(|s| s.allocation_bytes()).collect();
            stream.preflight(plan.output_height(), shapes.len(), &pending)?;
            let prepared = inputs
                .iter()
                .map(|(_, trace)| session.prepare_preprocessing_commit(trace))
                .collect::<Result<Vec<_>, _>>()?;
            let salts = stream.generate(plan.output_height(), shapes.len())?;
            let result = match state.mmcs.commit_preprocessing_with_public_salts(
                &prepared,
                salts,
                &session,
                state.host_budget,
            ) {
                Ok(result) => result,
                Err(error) => {
                    stream.retire()?;
                    return Err(error);
                }
            };
            eprintln!("bounded_gpu_public_salts matrices={} salt_upload_bytes=0 salt_matrix_readback_bytes=0", shapes.len());
            return Ok(result);
        }
        state
            .mmcs
            .preflight_owned_traces(&shapes, state.host_budget, true)?;
        let prepared = inputs
            .iter()
            .map(|(_, trace)| session.prepare_preprocessing_commit(trace))
            .collect::<Result<Vec<_>, _>>()?;
        let result = state
            .mmcs
            .commit_owned_traces(&prepared, &session, state.host_budget)?;
        eprintln!(
            "bounded_owned_preprocessing_commit matrices={} preprocessing_upload_bytes=0 preprocessing_readback_bytes=0 random_sample_upload_bytes=0",
            inputs.len()
        );
        Ok(result)
    }

    #[cfg(debug_assertions)]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn audit_main_device(
        &self,
        trace: &super::gpu_hash::device::DeviceMatrix,
    ) -> Result<RowMajorMatrix<Val>, String> {
        let Backend::Resident(state) = &self.inner else {
            return Err("device trace audit requires resident PCS".into());
        };
        if trace.spec().extension() != super::gpu_hash::device::Extension::Base {
            return Err("device main trace audit requires base fields".into());
        }
        if trace
            .spec()
            .bytes()
            .checked_mul(2)
            .is_none_or(|n| n > state.host_budget)
        {
            return Err("device main trace audit exceeds host allowance".into());
        }
        let words = self.quotient_session()?.read(trace, state.host_budget)?;
        eprintln!(
            "bounded_gpu_main_trace_debug_audit readback_bytes={}",
            trace.spec().bytes()
        );
        Ok(RowMajorMatrix::new(
            words.into_iter().map(Val::from_u64).collect(),
            trace.spec().columns(),
        ))
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn commit_trace_device(
        &self,
        inputs: Vec<(
            impl Into<super::gpu_hash::device::DomainSpec>,
            super::gpu_hash::device::DeviceMatrix,
        )>,
        extension: super::gpu_hash::device::Extension,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        use super::gpu_hash::device::{DomainSpec, TraceCommitShape};
        let inputs: Vec<(DomainSpec, _)> = inputs
            .into_iter()
            .map(|(domain, matrix)| (domain.into(), matrix))
            .collect();
        let Backend::Resident(state) = &self.inner else {
            return Err("device trace commitment requires resident PCS".into());
        };
        state.require_device_proving()?;
        state.lock_opening_mode();
        let session = self.quotient_session()?;
        // All ownership, shape and memory checks precede the hiding RNG draws.
        let mut shapes = Vec::with_capacity(inputs.len());
        for (domain, matrix) in &inputs {
            if matrix.spec().extension() != extension {
                return Err("device trace field does not match its commitment interface".into());
            }
            let owned = session.alias_private(matrix)?;
            let shape = TraceCommitShape::new(owned.spec(), self.random_columns)?;
            if domain.size() != shape.height || domain.shift() != Val::ONE {
                return Err("device trace does not match its doubled subgroup domain".into());
            }
            shapes.push(shape);
        }
        if let Some(failure) = &state.device_randomness {
            let pending: Vec<_> = shapes.iter().flat_map(|s| s.allocation_bytes()).collect();
            let lde_shapes: Vec<_> = shapes.iter().map(|s| s.lde_shape()).collect();
            let plan =
                state
                    .mmcs
                    .preflight_private_salts(&lde_shapes, state.host_budget, 0, &pending)?;
            state.rng.with_device(|rng| {
                rng.preflight_fields(
                    &shapes.iter().map(|s| s.random_words).collect::<Vec<_>>(),
                    &vec![8; shapes.len()],
                )
            })?;
            let guard = failure.begin()?;
            let prepared = state.rng.with_device(|rng| {
                inputs
                    .iter()
                    .zip(&shapes)
                    .map(|((_, trace), shape)| {
                        session.prepare_trace_commit_with_random(
                            trace,
                            self.random_columns,
                            rng.sample_fields(shape.random_words)?,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;
            let salts = state
                .mmcs
                .private_device_salts(plan.output_height(), prepared.len())?;
            let result = state.mmcs.commit_traces_with_device_salts(
                &prepared,
                salts,
                &session,
                state.host_budget,
            )?;
            guard.complete();
            eprintln!("bounded_gpu_random_stage stage=trace extension={extension:?} sample_upload_bytes=0 sample_readback_bytes=0");
            return Ok(result);
        }
        let _plan = state
            .mmcs
            .preflight_owned_traces(&shapes, state.host_budget, true)?;
        let mut prepared = Vec::with_capacity(inputs.len());
        let mut sample_bytes = 0usize;
        for ((_, trace), shape) in inputs.iter().zip(shapes) {
            let random = state.trace_random_words(shape.random_words)?;
            prepared.push(session.prepare_trace_commit(trace, self.random_columns, &random)?);
            sample_bytes += random.len() * 8;
        }
        let result = state
            .mmcs
            .commit_owned_traces(&prepared, &session, state.host_budget)?;
        if extension == E::DEVICE_EXTENSION {
            eprintln!(
                "bounded_owned_lookup_commit matrices={} permutation_matrix_upload_bytes=0 permutation_matrix_readback_bytes=0 random_sample_upload_bytes={sample_bytes}",
                inputs.len()
            );
        } else {
            eprintln!(
                "bounded_owned_main_commit matrices={} main_matrix_upload_bytes=0 main_matrix_readback_bytes=0 random_sample_upload_bytes={sample_bytes}",
                inputs.len()
            );
        }
        Ok(result)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_quotient_device(
        &self,
        domain: impl Into<super::gpu_hash::device::DomainSpec>,
        quotient: &super::gpu_hash::device::DeviceMatrix,
        chunks: usize,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        self.commit_quotients_device(vec![(domain.into(), quotient, chunks)])
    }

    /// Commit all AIR quotient partitions in one MMCS batch, preserving AIR and
    /// chunk order. Every input and the combined allocation plan are admitted
    /// before any private randomness is consumed.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_quotients_device(
        &self,
        groups: Vec<(
            super::gpu_hash::device::DomainSpec,
            &super::gpu_hash::device::DeviceMatrix,
            usize,
        )>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        use super::gpu_hash::device::QuotientCommitShape;
        use p3_field::PrimeField64;
        if groups.is_empty() || groups.len() > 256 {
            return Err("owned quotient AIR count exceeded".into());
        }
        let Backend::Resident(state) = &self.inner else {
            return Err("owned quotient commitment requires resident PCS".into());
        };
        state.require_device_proving()?;
        state.lock_opening_mode();
        let session = self.quotient_session()?;
        let mut quotients = Vec::with_capacity(groups.len());
        let mut shapes = Vec::with_capacity(groups.len());
        for (domain, quotient, chunks) in &groups {
            let quotient = session.alias_private(quotient)?;
            if quotient.spec().extension() != E::DEVICE_EXTENSION
                || quotient.spec().rows() != domain.size()
                || quotient.spec().shift() != domain.shift().as_canonical_u64()
            {
                return Err("owned quotient output does not match its domain".into());
            }
            let shape = QuotientCommitShape::new(quotient.spec(), *chunks, self.random_columns)?;
            Geometry::new(
                shape.height.ilog2() as usize,
                shape.degree,
                *chunks,
                self.log_blowup,
                self.random_columns,
            )
            .map_err(|e| format!("owned quotient geometry: {e:?}"))?;
            shapes.push(shape);
            quotients.push(quotient);
        }
        let lde_shapes = state.mmcs.quotient_batch_shapes(&shapes)?;
        let rng = self
            .quotient_rng
            .as_ref()
            .ok_or("owned quotient requires independent fusion RNG")?;
        if let Some(failure) = &state.device_randomness {
            let pending: Vec<_> = shapes
                .iter()
                .flat_map(|shape| shape.allocation_words().map(|words| words * 8))
                .collect();
            let plan =
                state
                    .mmcs
                    .preflight_private_salts(&lde_shapes, state.host_budget, 1, &pending)?;
            plan.validate_quotient_batch_storage(lde_shapes.len())?;
            let samples: Vec<_> = shapes
                .iter()
                .flat_map(|shape| [shape.random_words, shape.mask_words])
                .collect();
            let parameters: Vec<_> = shapes
                .iter()
                .map(|shape| shape.allocation_words()[2] * 8)
                .collect();
            rng.with_device(|rng| rng.preflight_fields(&samples, &parameters))?;
            let guard = failure.begin()?;
            let prepared = rng.with_device(|rng| {
                quotients
                    .iter()
                    .zip(&shapes)
                    .map(|(quotient, shape)| {
                        session.prepare_quotient_commit_with_random(
                            quotient,
                            shape.chunks,
                            self.random_columns,
                            rng.sample_fields(shape.random_words)?,
                            rng.sample_fields(shape.mask_words)?,
                        )
                    })
                    .collect::<Result<Vec<_>, String>>()
            })?;
            let inputs: Vec<_> = prepared.iter().collect();
            let salts = state
                .mmcs
                .private_device_salts(plan.output_height(), lde_shapes.len())?;
            let result = state.mmcs.commit_quotients_with_device_salts(
                &inputs,
                salts,
                &session,
                state.host_budget,
            )?;
            guard.complete();
            eprintln!("bounded_gpu_random_stage stage=quotient airs={} chunks={} sample_upload_bytes=0 sample_readback_bytes=0",
                      groups.len(), lde_shapes.len());
            return Ok(result);
        }
        let _admission = state.mmcs.preflight_owned_quotients(
            &shapes,
            state.host_budget,
            gpu_opening_eval_enabled(),
        )?;
        let mut prepared = Vec::with_capacity(groups.len());
        let mut sample_bytes = 0usize;
        for (quotient, shape) in quotients.iter().zip(&shapes) {
            let mut random = Vec::new();
            let mut masks = Vec::new();
            random
                .try_reserve_exact(shape.random_words)
                .map_err(|e| e.to_string())?;
            masks
                .try_reserve_exact(shape.mask_words)
                .map_err(|e| e.to_string())?;
            {
                let mut rng = rng.lock().map_err(|_| "quotient RNG poisoned")?;
                // Upstream samples each AIR's chunk/row/column random columns,
                // then its masks, before advancing to the next AIR.
                random.extend(
                    (0..shape.random_words).map(|_| rng.random::<Val>().as_canonical_u64()),
                );
                masks.extend((0..shape.mask_words).map(|_| rng.random::<Val>().as_canonical_u64()));
            }
            prepared.push(session.prepare_quotient_commit(
                quotient,
                shape.chunks,
                self.random_columns,
                &random,
                &masks,
            )?);
            sample_bytes = sample_bytes
                .checked_add((random.len() + masks.len()) * 8)
                .ok_or("quotient sample accounting overflow")?;
        }
        let inputs: Vec<_> = prepared.iter().collect();
        let result = state.mmcs.commit_owned_quotients(
            &inputs,
            state.host_budget,
            gpu_opening_eval_enabled().then_some(&session),
        )?;
        eprintln!("bounded_owned_quotient_commit airs={} chunks={} quotient_matrix_upload_bytes=0 quotient_matrix_readback_bytes=0 random_sample_upload_bytes={sample_bytes}",
                  groups.len(), lde_shapes.len());
        Ok(result)
    }

    /// Single-table research hook; keeps small quotient evaluations until the
    /// masked GPU transform and commitment. No expanded LDE upload or fallback.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn commit_quotient_evaluations(
        &self,
        groups: Vec<(Vec<Domain>, Vec<RowMajorMatrix<Val>>)>,
    ) -> Result<
        (
            <Self as Pcs<E, Challenger>>::Commitment,
            <Self as Pcs<E, Challenger>>::ProverData,
        ),
        String,
    > {
        self.require_host_storage()?;
        if groups.len() != 1 {
            return Err("GPU quotient commitment currently admits exactly one AIR".into());
        }
        let Backend::Resident(state) = &self.inner else {
            return Err("GPU quotient commitment requires resident PCS".into());
        };
        state.lock_opening_mode();
        let rng = self
            .quotient_rng
            .as_ref()
            .ok_or("GPU quotient requires independent fusion RNG")?;
        let (domains, matrices) = groups.into_iter().next().unwrap();
        if domains.len() != matrices.len() {
            return Err("GPU quotient domain/matrix count mismatch".into());
        }
        let chunks = domains.len();
        let evaluations: Vec<_> = domains.into_iter().zip(matrices).collect();
        let (geometry, weights) =
            preflight(&evaluations, chunks, self.log_blowup, self.random_columns)
                .map_err(|e| format!("GPU quotient geometry: {e:?}"))?;
        let _plan = state.mmcs.preflight_resident(
            &vec![
                super::gpu_hash::LdeInputShape {
                    height: geometry.height,
                    width: geometry.width,
                    added_bits: self.log_blowup + 1,
                };
                chunks
            ],
            state.host_budget,
        )?;
        let (randomized, masks) =
            randomized_quotients(evaluations, geometry, &weights, self.random_columns, rng);
        let chunk_masks: Vec<_> = masks
            .chunks_exact(geometry.chunk_elements)
            .map(|values| RowMajorMatrix::new(values.to_vec(), geometry.width))
            .collect();
        drop(masks);
        state.mmcs.commit_resident_with_masks(
            randomized,
            self.log_blowup + 1,
            state.host_budget,
            Some(&chunk_masks),
        )
    }

    /// Select before sharing/using a newly constructed resident proof attempt.
    /// There is no per-call switching or fallback after randomness is consumed.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn with_gpu_randomness(mut self) -> Result<Self, String> {
        super::randomness::resources::check_worker(true, None)?;
        let quotient = self
            .quotient_rng
            .as_ref()
            .ok_or("GPU randomness requires independent quotient fusion")?;
        match &mut self.inner {
            Backend::Resident(state) => Arc::get_mut(state)
                .ok_or("GPU randomness must be selected before PCS cloning")?
                .enable_gpu_randomness(quotient)?,
            Backend::Reference(_) => {
                return Err("GPU randomness requires resident commitments".into())
            }
        }
        Ok(self)
    }

    /// A full proof attempt retires every selected stream on any failure,
    /// including admission failures between randomness-consuming stages.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn begin_randomness_attempt(
        &self,
    ) -> Result<Option<super::randomness::FailureGuard>, String> {
        match &self.inner {
            Backend::Resident(state) => state
                .device_randomness
                .as_ref()
                .map(super::randomness::Failure::begin)
                .transpose(),
            Backend::Reference(_) => Ok(None),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn uses_gpu_randomness(&self) -> bool {
        matches!(&self.inner, Backend::Resident(state) if state.device_randomness.is_some())
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn transcript_session(&self) -> Result<super::gpu_hash::device::DeviceSession, String> {
        if !cfg!(feature = "gpu")
            || !self.uses_gpu_randomness()
            || !gpu_pcs_device_only_enabled()
            || !gpu_lookup_enabled()
            || !gpu_opening_eval_enabled()
            || !gpu_fri_resident_enabled()
            || !matches!(&self.inner, Backend::Resident(state) if state.gpu_openings)
        {
            return Err("GPU transcript requires the owned OpenCL witness/PCS path with private GPU randomness".into());
        }
        self.quotient_session()
    }

    /// Internal conformance selection before the first observation.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn gpu_challenger(&self) -> Result<Challenger, String> {
        Challenger::new_gpu(&self.transcript_session()?)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn registered_gpu_challenger(&self) -> Result<Challenger, String> {
        Challenger::new_gpu_registered(&self.transcript_session()?)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn check_gpu_challenger(&self, challenger: &Challenger) -> Result<(), String> {
        if gpu_transcript_enabled() && !challenger.is_gpu() {
            return Err("registered GPU transcript cannot use a CPU challenger".into());
        }
        if challenger.is_gpu() {
            challenger.check_session(&self.transcript_session()?)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn observe_execution<'a>(
        &self,
        run: &'a crate::proving::Run,
    ) -> Result<Option<super::gpu_hash::device::ExecutionObservation<'a>>, String> {
        match &self.inner {
            Backend::Resident(state) => state
                .device_session
                .as_ref()
                .map(|session| session.observe_execution(run))
                .transpose(),
            _ => Ok(None),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn observe_randomness<'a>(
        &self,
        run: &'a crate::proving::Run,
    ) -> Result<Option<super::randomness::RandomnessObservation<'a>>, String> {
        match &self.inner {
            Backend::Resident(state)
                if state.device_randomness.is_some() || state.preprocessing_salts.is_some() =>
            {
                let session = state
                    .device_session
                    .as_ref()
                    .ok_or("missing random session")?
                    .clone();
                super::randomness::RandomnessObservation::new(run, session).map(Some)
            }
            _ => Ok(None),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn with_gpu_preprocessing_salts(mut self) -> Result<Self, String> {
        super::randomness::resources::check_worker(true, None)?;
        match &mut self.inner {
            Backend::Resident(state) => Arc::get_mut(state)
                .ok_or("GPU public salts must be selected before PCS cloning")?
                .enable_gpu_preprocessing_salts()?,
            Backend::Reference(_) => {
                return Err("GPU public salts require resident commitments".into())
            }
        }
        Ok(self)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn with_gpu_openings(mut self) -> Result<Self, String> {
        match &mut self.inner {
            Backend::Resident(state) => {
                Arc::get_mut(state)
                    .ok_or("GPU openings must be selected before PCS cloning")?
                    .enable_gpu_openings()?;
            }
            Backend::Reference(_) => return Err("GPU openings require resident commitments".into()),
        }
        Ok(self)
    }
    #[cfg(all(test, any(feature = "gpu", feature = "gpu-metal")))]
    pub(crate) fn uses_resident_commitments(&self) -> bool {
        matches!(self.inner, Backend::Resident(_))
    }

    pub fn new(
        dft: Dft,
        mmcs: ValMmcs,
        fri: FriParameters<ChallengeMmcs<E>>,
        random_columns: usize,
        inner_rng: ChaCha20Rng,
    ) -> Self {
        let log_blowup = fri.log_blowup;
        Self {
            inner: Backend::Reference(Inner::new(
                dft.clone(),
                mmcs,
                fri,
                random_columns,
                inner_rng,
            )),
            dft,
            log_blowup,
            random_columns,
            quotient_rng: None,
        }
    }

    /// Explicit research construction, requiring the initialized retained GPU
    /// backend and the pinned parameters for its field. This is never a fallback.
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn new_resident(
        dft: Dft,
        mmcs: ValMmcs,
        fri: FriParameters<ChallengeMmcs<E>>,
        random_columns: usize,
        inner_rng: ChaCha20Rng,
        host_output_budget: usize,
    ) -> Result<Self, String> {
        let log_blowup = fri.log_blowup;
        let state = super::resident_pcs::ResidentState::new(
            dft.clone(),
            mmcs,
            fri,
            random_columns,
            inner_rng,
            host_output_budget,
        )?;
        Ok(Self {
            inner: Backend::Resident(Arc::new(state)),
            dft,
            log_blowup,
            random_columns,
            quotient_rng: None,
        })
    }

    /// Caller must supply a fresh independent full-entropy seed in real proving.
    /// This explicit method is intentionally not an environment-variable switch.
    pub(crate) fn with_fused_quotients(mut self, independent_rng: ChaCha20Rng) -> Self {
        self.quotient_rng = Some(super::randomness::ProofRng::new(independent_rng));
        self
    }
}

impl<E: PcsField> BuildPeriodicLdeTableFast for CandidatePcs<E> {
    type PeriodicDomain = Domain;

    fn maybe_build_periodic_lde_table_fast(
        &self,
        periodic_cols: &[Vec<Val>],
        trace_domain: Domain,
        quotient_domain: Domain,
    ) -> Option<PeriodicLdeTable<Val>> {
        match &self.inner {
            Backend::Reference(inner) => inner.maybe_build_periodic_lde_table_fast(
                periodic_cols,
                trace_domain,
                quotient_domain,
            ),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Resident(state) => state.inner.maybe_build_periodic_lde_table_fast(
                periodic_cols,
                trace_domain,
                quotient_domain,
            ),
        }
    }
}

impl<E: PcsField> Pcs<E, Challenger> for CandidatePcs<E> {
    type Domain = <Inner<E> as Pcs<E, Challenger>>::Domain;
    type Commitment = <Inner<E> as Pcs<E, Challenger>>::Commitment;
    type ProverData = <Inner<E> as Pcs<E, Challenger>>::ProverData;
    type EvaluationsOnDomain<'a> = <Inner<E> as Pcs<E, Challenger>>::EvaluationsOnDomain<'a>;
    type Proof = <Inner<E> as Pcs<E, Challenger>>::Proof;
    type Error = <Inner<E> as Pcs<E, Challenger>>::Error;

    const ZK: bool = <Inner<E> as Pcs<E, Challenger>>::ZK;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        delegate_pcs!(self, natural_domain_for_degree, degree)
    }

    fn log_max_lde_height(&self) -> usize {
        delegate_pcs!(self, log_max_lde_height)
    }

    fn commit(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        match &self.inner {
            Backend::Reference(inner) => {
                <Inner<E> as Pcs<E, Challenger>>::commit(inner, evaluations)
            }
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Resident(state) => state
                .commit(evaluations, false)
                .expect("resident commitment failed; no silent fallback"),
        }
    }

    fn commit_preprocessing(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        match &self.inner {
            Backend::Reference(inner) => {
                <Inner<E> as Pcs<E, Challenger>>::commit_preprocessing(inner, evaluations)
            }
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Resident(state) => state
                .commit(evaluations, true)
                .expect("resident preprocessing commitment failed; no silent fallback"),
        }
    }

    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<Val>)>,
        num_chunks: usize,
    ) -> Vec<RowMajorMatrix<Val>> {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        self.require_host_storage()
            .expect("device-only PCS cannot materialize quotient LDEs");
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let Backend::Resident(state) = &self.inner {
            state.lock_opening_mode();
        }
        match &self.quotient_rng {
            None => delegate_pcs!(self, get_quotient_ldes, evaluations, num_chunks),
            Some(rng) => fused_ldes(
                &self.dft,
                collect_inputs(evaluations, num_chunks)
                    .expect("invalid fused quotient chunk count; no silent fallback"),
                num_chunks,
                self.log_blowup,
                self.random_columns,
                rng,
            )
            .expect("unsupported fused quotient geometry; no silent fallback"),
        }
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<Val>>) -> (Self::Commitment, Self::ProverData) {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        self.require_host_storage()
            .expect("device-only PCS cannot commit host LDEs");
        delegate_pcs!(self, commit_ldes, ldes)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        self.require_host_storage()
            .expect("device-only PCS has no host domain evaluations");
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let super::gpu_hash::ProverData::Compact(_) = prover_data {
            return self.compact_evaluations(prover_data, idx, domain, self.random_columns);
        }
        delegate_pcs!(self, get_evaluations_on_domain, prover_data, idx, domain)
    }

    fn get_evaluations_on_domain_no_random<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Domain,
    ) -> Self::EvaluationsOnDomain<'a> {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        self.require_host_storage()
            .expect("device-only PCS has no host domain evaluations");
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let super::gpu_hash::ProverData::Compact(_) = prover_data {
            return self.compact_evaluations(prover_data, idx, domain, 0);
        }
        delegate_pcs!(
            self,
            get_evaluations_on_domain_no_random,
            prover_data,
            idx,
            domain
        )
    }

    fn open(
        &self,
        rounds: Vec<(&Self::ProverData, Vec<Vec<E>>)>,
        challenger: &mut Challenger,
    ) -> (OpenedValues<E>, Self::Proof) {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let Backend::Resident(state) = &self.inner {
            state
                .require_device_proving()
                .expect("device-only PCS cannot use CPU openings");
            if state.gpu_openings {
                return state.open(rounds, challenger, false);
            }
        }
        delegate_pcs!(self, open, rounds, challenger)
    }

    fn open_with_preprocessing(
        &self,
        rounds: Vec<(&Self::ProverData, Vec<Vec<E>>)>,
        challenger: &mut Challenger,
        is_preprocessing: bool,
    ) -> (OpenedValues<E>, Self::Proof) {
        #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
        if let Backend::Resident(state) = &self.inner {
            state
                .require_device_proving()
                .expect("device-only PCS cannot use CPU openings");
            if state.gpu_openings {
                return state.open(rounds, challenger, is_preprocessing);
            }
        }
        delegate_pcs!(
            self,
            open_with_preprocessing,
            rounds,
            challenger,
            is_preprocessing
        )
    }

    #[allow(clippy::type_complexity)]
    fn verify(
        &self,
        rounds: Vec<(Self::Commitment, Vec<(Domain, Vec<(E, Vec<E>)>)>)>,
        proof: &Self::Proof,
        challenger: &mut Challenger,
    ) -> Result<(), Self::Error> {
        delegate_pcs!(self, verify, rounds, proof, challenger)
    }

    fn get_opt_randomization_poly_commitment(
        &self,
        domain: impl IntoIterator<Item = Domain>,
    ) -> Option<(Self::Commitment, Self::ProverData)> {
        match &self.inner {
            Backend::Reference(inner) => {
                <Inner<E> as Pcs<E, Challenger>>::get_opt_randomization_poly_commitment(
                    inner, domain,
                )
            }
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            Backend::Resident(state) => Some(
                state
                    .randomization(domain)
                    .expect("resident randomization commitment failed; no silent fallback"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    #[test]
    fn gpu_transcript_selection_requires_randomness_and_is_immutable() {
        for randomness in [false, true] {
            for opencl in [false, true] {
                assert_eq!(
                    super::parse_gpu_transcript(None, randomness, opencl),
                    Ok(false)
                );
                assert_eq!(
                    super::parse_gpu_transcript(Some("0"), randomness, opencl),
                    Ok(false)
                );
                assert_eq!(
                    super::parse_gpu_transcript(Some("1"), randomness, opencl).is_ok(),
                    randomness && opencl
                );
                for value in ["true", " 1", "01", "", "2"] {
                    assert!(super::parse_gpu_transcript(Some(value), randomness, opencl).is_err());
                }
            }
        }
        let cell = std::sync::OnceLock::new();
        let initial = super::GpuSelection {
            transcript: true,
            ..Default::default()
        };
        super::record_gpu_selection(&cell, initial).unwrap();
        super::record_gpu_selection(&cell, initial).unwrap();
        assert!(super::record_gpu_selection(&cell, super::GpuSelection::default()).is_err());
        assert_eq!(cell.get(), Some(&initial));
    }
    use super::*;

    #[test]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn gpu_randomness_selection_is_strict_and_atomic() {
        for witness in [false, true] {
            for opencl in [false, true] {
                assert_eq!(parse_gpu_randomness(None, witness, opencl), Ok(false));
                assert_eq!(parse_gpu_randomness(Some("0"), witness, opencl), Ok(false));
                assert_eq!(
                    parse_gpu_randomness(Some("1"), witness, opencl).is_ok(),
                    witness && opencl
                );
                for invalid in ["", "true", "01", " 1", "2", "１"] {
                    assert!(parse_gpu_randomness(Some(invalid), witness, opencl).is_err());
                }
            }
        }
        let cell = OnceLock::new();
        let initial = GpuSelection::default();
        record_gpu_selection(&cell, initial).unwrap();
        record_gpu_selection(&cell, initial).unwrap();
        let changed = GpuSelection {
            witness: true,
            randomness: true,
            ..initial
        };
        assert!(record_gpu_selection(&cell, changed).is_err());
        assert_eq!(cell.get(), Some(&initial));
    }

    #[test]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn gpu_witness_selection_requires_device_only_opencl_and_is_immutable() {
        for device_only in [false, true] {
            for opencl in [false, true] {
                assert_eq!(parse_gpu_witness(None, device_only, opencl), Ok(false));
                assert_eq!(parse_gpu_witness(Some("0"), device_only, opencl), Ok(false));
                assert_eq!(
                    parse_gpu_witness(Some("1"), device_only, opencl).is_ok(),
                    device_only && opencl
                );
                for value in ["", "true", "2", " 1", "1 ", "01", "１"] {
                    assert!(parse_gpu_witness(Some(value), device_only, opencl).is_err());
                }
            }
        }
        for value in ["0", "1"] {
            let selected = parse_gpu_witness(Some(value), true, true).unwrap();
            let mode = OnceLock::new();
            record_research_mode(&mode, selected).unwrap();
            record_research_mode(&mode, selected).unwrap();
            assert!(record_research_mode(&mode, !selected).is_err());
            assert_eq!(mode.get(), Some(&selected));
        }
    }

    #[test]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn device_only_pcs_requires_all_owned_consumers() {
        for fri in [false, true] {
            for lookup in [false, true] {
                for opencl in [false, true] {
                    assert_eq!(
                        parse_gpu_pcs_device_only(None, fri, lookup, opencl),
                        Ok(false)
                    );
                    assert_eq!(
                        parse_gpu_pcs_device_only(Some("0"), fri, lookup, opencl),
                        Ok(false)
                    );
                    assert_eq!(
                        parse_gpu_pcs_device_only(Some("1"), fri, lookup, opencl).is_ok(),
                        fri && lookup && opencl
                    );
                    for value in ["", "true", "2", " 1", "1 ", "01", "１"] {
                        assert!(
                            parse_gpu_pcs_device_only(Some(value), fri, lookup, opencl).is_err()
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn gpu_quotient_eval_requires_opencl_and_lde_without_implicit_fallback() {
        for lde in [false, true] {
            for opencl in [false, true] {
                assert_eq!(parse_gpu_quotient_eval(None, lde, opencl), Ok(false));
                assert_eq!(parse_gpu_quotient_eval(Some("0"), lde, opencl), Ok(false));
                assert_eq!(
                    parse_gpu_quotient_eval(Some("1"), lde, opencl).is_ok(),
                    lde && opencl
                );
                for value in ["", "true", "2", " 1", "1 ", "01", "１"] {
                    assert!(parse_gpu_quotient_eval(Some(value), lde, opencl).is_err());
                }
            }
        }
    }

    #[test]
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    fn gpu_quotient_policy_requires_both_dependencies_and_explicit_opt_in() {
        for resident in [false, true] {
            for fusion in [false, true] {
                assert!(!parse_gpu_quotient(None, resident, fusion).unwrap());
                assert!(!parse_gpu_quotient(Some("0"), resident, fusion).unwrap());
                assert_eq!(
                    parse_gpu_quotient(Some("1"), resident, fusion).is_ok(),
                    resident && fusion
                );
                for value in ["", "true", "2", " 1"] {
                    assert!(parse_gpu_quotient(Some(value), resident, fusion).is_err());
                }
            }
        }
    }
    use crate::config::{MyCompress, MyHash};
    use p3_field::PrimeField64;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::Matrix;
    use rand::SeedableRng;

    #[test]
    fn research_mode_is_explicit_strict_and_immutable() {
        assert_eq!(parse_research_mode(None), Ok(false));
        assert_eq!(parse_research_mode(Some("0")), Ok(false));
        assert_eq!(parse_research_mode(Some("1")), Ok(true));
        for invalid in ["", "true", "01", " 1", "1 ", "2", "\u{ff11}"] {
            assert!(parse_research_mode(Some(invalid)).is_err());
        }
        let mode = OnceLock::new();
        record_research_mode(&mode, false).unwrap();
        record_research_mode(&mode, false).unwrap();
        assert!(record_research_mode(&mode, true).is_err());
        assert_eq!(mode.get(), Some(&false));
    }

    #[test]
    fn input_collection_is_bounded_and_rejects_wrong_counts() {
        let one = input(1, 3, 2).remove(0);
        let mut consumed = 0;
        let endless = std::iter::from_fn(|| {
            consumed += 1;
            Some(one.clone())
        });
        assert_eq!(
            collect_inputs(endless, 4).unwrap_err(),
            FusionError::ChunkCount
        );
        assert_eq!(consumed, 5);
        assert!(collect_inputs(input(1, 3, 2), 4).is_err());
        let never = std::iter::from_fn(|| -> Option<(Domain, RowMajorMatrix<Val>)> {
            panic!("invalid chunk count must be rejected before input consumption")
        });
        assert!(collect_inputs(never, usize::MAX).is_err());
        assert_eq!(collect_inputs(input(1, 3, 2), 2).unwrap().len(), 2);
    }

    fn mmcs() -> ValMmcs {
        let permutation = default_goldilocks_poseidon2_8();
        ValMmcs::new(
            MyHash::new(permutation.clone()),
            MyCompress::new(permutation),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([19; 32]),
        )
    }

    fn reference(seed: [u8; 32]) -> Inner {
        let mmcs = mmcs();
        Inner::new(
            Dft::default(),
            mmcs.clone(),
            profile::fri(ChallengeMmcs::new(mmcs)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed(seed),
        )
    }

    fn candidate(fusion: bool) -> CandidatePcs {
        let mmcs = mmcs();
        let pcs = CandidatePcs::new(
            Dft::default(),
            mmcs.clone(),
            profile::fri(ChallengeMmcs::new(mmcs)),
            profile::NUM_RANDOM_CODEWORDS,
            ChaCha20Rng::from_seed([53; 32]),
        );
        if fusion {
            pcs.with_fused_quotients(ChaCha20Rng::from_seed([61; 32]))
        } else {
            pcs
        }
    }

    fn input(log_height: usize, width: usize, chunks: usize) -> Vec<(Domain, RowMajorMatrix<Val>)> {
        let log_total = log_height + chunks.ilog2() as usize;
        let quotient = Domain::new(Val::GENERATOR, log_total).unwrap();
        let mut rng = ChaCha20Rng::from_seed([103; 32]);
        let flat = RowMajorMatrix::new(
            (0..(1 << log_total) * width)
                .map(|_| Val::from_u64(rng.random()))
                .collect(),
            width,
        );
        quotient
            .split_domains(chunks)
            .into_iter()
            .zip(quotient.split_evals(chunks, flat))
            .collect()
    }

    fn assert_equal(expected: &[RowMajorMatrix<Val>], actual: &[RowMajorMatrix<Val>]) {
        assert_eq!(expected.len(), actual.len());
        for (expected, actual) in expected.iter().zip(actual) {
            assert_eq!(expected.dimensions(), actual.dimensions());
            for (expected, actual) in expected.values.iter().zip(&actual.values) {
                assert_eq!(expected, actual);
                assert_eq!(expected.as_canonical_u64(), actual.as_canonical_u64());
            }
        }
    }

    #[test]
    fn exact_upstream_quotient_equivalence_including_repeated_calls() {
        for (log_height, width, chunks) in [(0, 1, 2), (1, 3, 4), (4, 3, 16), (5, 7, 8)] {
            let reference = reference([61; 32]);
            let candidate = candidate(true);
            for _ in 0..3 {
                let input = input(log_height, width, chunks);
                let expected = <Inner as Pcs<Challenge, Challenger>>::get_quotient_ldes(
                    &reference,
                    input.clone(),
                    chunks,
                );
                let actual = candidate.get_quotient_ldes(input, chunks);
                assert_equal(&expected, &actual);
            }
        }
    }

    #[test]
    fn disabled_mode_exactly_delegates_rng_and_quotient_work() {
        let reference = reference([53; 32]);
        let candidate = candidate(false);
        for _ in 0..2 {
            let input = input(3, 3, 4);
            let expected = <Inner as Pcs<Challenge, Challenger>>::get_quotient_ldes(
                &reference,
                input.clone(),
                4,
            );
            assert_equal(&expected, &candidate.get_quotient_ldes(input, 4));
        }
    }

    #[test]
    fn common_geometry_is_admitted_without_claiming_a_job_peak() {
        let geometry = Geometry::new(19, 3, 16, 4, 4).unwrap();
        assert_eq!(geometry.height, 524_288);
        assert_eq!(geometry.width, 7);
        assert_eq!(geometry.chunk_lde_bytes, 896 << 20);
        assert_eq!(geometry.retained_lde_bytes, 14 << 30);
        assert_eq!(geometry.mask_elements * 8, 448 << 20);
    }

    #[cfg(feature = "stream")]
    #[test]
    #[ignore = "large workspace equivalence; run alone in a bounded <=3 GiB service"]
    fn spill_armed_large_quotients_match_and_retain_heap_storage() {
        // Each output is 112 MiB: above the 64 MiB workspace threshold and
        // below its 2 GiB ceiling. This is not the full recursive workload.
        let _spill = crate::spill_alloc::SpillScope::arm();
        let before = crate::spill_alloc::spill_stats();
        let reference = reference([61; 32]);
        let candidate = candidate(true);
        let input = input(16, 3, 2);
        // The input chunks are only 1.5 MiB each, below the allocator's 64 MiB
        // threshold. The 112 MiB transformed workspaces, not these inputs,
        // must exercise mapped allocation.
        assert!(crate::spill_alloc::is_armed());
        assert_eq!(crate::spill_alloc::spill_stats(), before);
        let expected =
            <Inner as Pcs<Challenge, Challenger>>::get_quotient_ldes(&reference, input.clone(), 2);
        drop(reference);
        assert_eq!(crate::spill_alloc::spill_stats(), before);
        crate::spill_alloc::reset_spill_peak();
        let actual = candidate.get_quotient_ldes(input, 2);
        let peak_mapped_bytes = crate::spill_alloc::spill_peak_bytes();
        assert!(peak_mapped_bytes >= 112 << 20);
        assert_equal(&expected, &actual);
        // Drop transform caches before accounting for the retained outputs.
        // Neither output should keep a mapped allocation alive. The test must
        // run in a fresh serial process because allocator counters are global.
        drop(candidate);
        assert_eq!(crate::spill_alloc::spill_stats(), before);
        assert_eq!(actual[0].values.len() * 8, 112 << 20);
        eprintln!(
            "fusion_workspace_equivalence=PASS output_bytes={} peak_mapped_bytes={} full_recursive_geometry=false",
            actual[0].values.len() * 8,
            peak_mapped_bytes,
        );
        drop(actual);
        drop(expected);
        assert_eq!(crate::spill_alloc::spill_stats(), before);
    }

    #[test]
    fn geometry_arithmetic_parameters_and_workspace_fail_closed() {
        assert_eq!(Geometry::new(4, 3, 1, 4, 4), Err(FusionError::ChunkCount));
        assert_eq!(Geometry::new(4, 3, 3, 4, 4), Err(FusionError::ChunkCount));
        assert!(Geometry::new(4, 3, 32, 4, 4).is_ok());
        assert_eq!(Geometry::new(4, 3, 64, 4, 4), Err(FusionError::ChunkCount));
        assert_eq!(Geometry::new(4, 0, 4, 4, 4), Err(FusionError::EmptyWidth));
        assert_eq!(Geometry::new(28, 3, 4, 4, 4), Err(FusionError::DomainSize));
        assert_eq!(
            Geometry::new(usize::MAX, 3, 4, 4, 4),
            Err(FusionError::DomainSize)
        );
        assert_eq!(
            Geometry::new(4, usize::MAX, 4, 4, 4),
            Err(FusionError::ArithmeticOverflow)
        );
        assert_eq!(
            Geometry::new(21, 3, 16, 4, 4),
            Err(FusionError::WorkspaceLimit)
        );
        assert_eq!(
            Geometry::new(4, 3, 4, 3, 4),
            Err(FusionError::UnsupportedParameters)
        );
        assert_eq!(
            Geometry::new(4, 3, 4, 4, 0),
            Err(FusionError::UnsupportedParameters)
        );
    }

    #[test]
    fn bad_shapes_and_overlaps_are_rejected_before_rng_consumption() {
        let mut cases = Vec::new();
        let mut bad = input(3, 3, 4);
        bad.pop();
        cases.push(bad);
        let mut bad = input(3, 3, 4);
        bad[1].1.width = 0;
        cases.push(bad);
        let mut bad = input(3, 3, 4);
        bad[0].1.width = 0;
        cases.push(bad);
        let mut bad = input(3, 3, 4);
        bad[1].1.values.pop();
        cases.push(bad);
        let mut bad = input(3, 3, 4);
        bad[1].0 = bad[0].0;
        cases.push(bad);
        let mut bad = input(3, 3, 4);
        bad[1].0 = Domain::new(Val::GENERATOR, 4).unwrap();
        cases.push(bad);
        for bad in cases {
            let rng = super::super::randomness::ProofRng::new(ChaCha20Rng::from_seed([71; 32]));
            let mut expected_rng = ChaCha20Rng::from_seed([71; 32]);
            assert!(fused_ldes(&Dft::default(), bad, 4, 4, 4, &rng).is_err());
            assert_eq!(
                rng.lock().unwrap().random::<u64>(),
                expected_rng.random::<u64>()
            );
        }
    }

    #[test]
    fn quotient_rng_is_shared_not_replayed_by_clone() {
        let candidate = candidate(true);
        let clone = candidate.clone();
        assert!(candidate
            .quotient_rng
            .as_ref()
            .unwrap()
            .shares_with(clone.quotient_rng.as_ref().unwrap()));
        let input = input(2, 3, 4);
        let first = candidate.get_quotient_ldes(input.clone(), 4);
        let second = clone.get_quotient_ldes(input, 4);
        assert_ne!(first[0].values, second[0].values);
    }

    #[test]
    fn fusion_does_not_change_deterministic_preprocessing_caps() {
        let reference = reference([53; 32]);
        let candidate = candidate(true);
        let matrix = RowMajorMatrix::new((0..192).map(Val::from_usize).collect(), 3);
        // HidingFriPcs interleaves public preprocessing with zero rows, so its
        // caller supplies the doubled domain even though the input has 64 rows.
        let domain = <Inner as Pcs<Challenge, Challenger>>::natural_domain_for_degree(
            &reference,
            2 * matrix.height(),
        );
        assert_eq!(domain.size(), 128);
        let (expected, _) = <Inner as Pcs<Challenge, Challenger>>::commit_preprocessing(
            &reference,
            [(domain, matrix.clone())],
        );
        let (actual, _) = candidate.commit_preprocessing([(domain, matrix)]);
        assert_eq!(
            postcard::to_allocvec(&expected).unwrap(),
            postcard::to_allocvec(&actual).unwrap()
        );
    }

    struct RecurrenceAir;

    impl p3_air::BaseAir<Val> for RecurrenceAir {
        fn width(&self) -> usize {
            2
        }

        fn num_public_values(&self) -> usize {
            3
        }
    }

    impl<AB: p3_air::AirBuilder<F = Val>> p3_air::Air<AB> for RecurrenceAir {
        fn eval(&self, builder: &mut AB) {
            use p3_air::{AirBuilder, WindowAccess};
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let public = builder.public_values();
            let (first, second, last) = (public[0], public[1], public[2]);
            builder.when_first_row().assert_eq(local[0], first);
            builder.when_first_row().assert_eq(local[1], second);
            builder.when_transition().assert_eq(next[0], local[1]);
            builder
                .when_transition()
                .assert_eq(next[1], local[0] + local[1]);
            builder.when_last_row().assert_eq(local[0], last);
        }
    }

    #[test]
    fn full_strength_cubic_proofs_replay_through_unwrapped_cpu_pcs() {
        type CpuExtensionMmcs = p3_commit::ExtensionMmcs<Val, Challenge, crate::config::ValMmcs>;
        type CpuPcs = HidingFriPcs<
            Val,
            crate::config::Dft,
            crate::config::ValMmcs,
            CpuExtensionMmcs,
            ChaCha20Rng,
        >;
        type CpuConfig = p3_uni_stark::StarkConfig<CpuPcs, Challenge, Challenger>;
        type FusedConfig = p3_uni_stark::StarkConfig<CandidatePcs, Challenge, Challenger>;

        let permutation = default_goldilocks_poseidon2_8();
        let cpu_mmcs = crate::config::ValMmcs::new(
            MyHash::new(permutation.clone()),
            MyCompress::new(permutation.clone()),
            profile::CAP_HEIGHT,
            ChaCha20Rng::from_seed([29; 32]),
        );
        let cpu = CpuConfig::new(
            CpuPcs::new(
                crate::config::Dft::default(),
                cpu_mmcs.clone(),
                profile::fri(CpuExtensionMmcs::new(cpu_mmcs)),
                profile::NUM_RANDOM_CODEWORDS,
                ChaCha20Rng::from_seed([31; 32]),
            ),
            Challenger::new(permutation.clone()),
        );
        let fused = FusedConfig::new(candidate(true), Challenger::new(permutation));
        let (mut a, mut b) = (Val::from_u64(3), Val::from_u64(5));
        let mut values = Vec::with_capacity(256);
        for _ in 0..128 {
            values.extend([a, b]);
            (a, b) = (b, a + b);
        }
        let public = [values[0], values[1], values[values.len() - 2]];
        let trace = RowMajorMatrix::new(values, 2);
        let mut commitments = Vec::new();
        for _ in 0..2 {
            let proof = p3_uni_stark::prove(&fused, &RecurrenceAir, trace.clone(), &public);
            commitments.push(postcard::to_allocvec(&proof.commitments).unwrap());
            // CPU verifier uses the original HidingFriPcs, CPU MMCS and original
            // proof type; it never invokes the candidate PCS's verifier method.
            let bytes = postcard::to_allocvec(&proof).unwrap();
            let decoded: p3_uni_stark::Proof<CpuConfig> = postcard::from_bytes(&bytes).unwrap();
            p3_uni_stark::verify(&cpu, &RecurrenceAir, &decoded, &public).unwrap();
            let mut wrong = public;
            wrong[2] += Val::ONE;
            assert!(p3_uni_stark::verify(&cpu, &RecurrenceAir, &decoded, &wrong).is_err());
        }
        assert_ne!(
            commitments[0], commitments[1],
            "proof randomness must advance"
        );
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
impl<E: PcsField> CandidatePcs<E> {
    fn compact_evaluations<'a>(
        &self,
        data: &'a <Self as Pcs<E, Challenger>>::ProverData,
        idx: usize,
        domain: Domain,
        random_columns: usize,
    ) -> <Self as Pcs<E, Challenger>>::EvaluationsOnDomain<'a> {
        use p3_matrix::{horizontally_truncated::HorizontallyTruncated, Matrix};
        let Backend::Resident(state) = &self.inner else {
            panic!("compact data requires resident PCS")
        };
        let matrices = state.mmcs.prefix_matrices(data);
        let matrix = matrices[idx].0;
        assert_eq!(domain.shift(), Val::GENERATOR, "compact quotient coset");
        assert!(
            domain.size() <= matrix.height(),
            "quotient domain exceeds retained prefix"
        );
        let values: &'a [Val] = matrix.values;
        let view = p3_matrix::dense::RowMajorMatrixView::new(
            &values[..domain.size() * matrix.width],
            matrix.width,
        )
        .as_cow()
        .bit_reverse_rows();
        let width = view.width();
        HorizontallyTruncated::new(view, width - random_columns).unwrap()
    }
}
