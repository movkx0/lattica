//! Native single-AIR STARK orchestration with the p3-uni-stark 0.6.1 wire format.
//! Public AIR compilation and final serialization are host work. Trace,
//! quotient, hiding, transcript and PCS arithmetic consume resident inputs.
//! This module does not select a backend or claim witness-generation coverage.
use super::{
    Buffer, Commitments, DeviceRandom, FieldSpan, FriField, FriParameters, Hiding, HidingInput,
    Kernel, Matrix, OpeningPoints, OpeningRound, PcsOpenings, PreparedQuotient, Quotients, Result,
    Runtime, Scalars, Specialization, Transcript, Transcripts, Transforms,
};
use crate::{
    block_v2::{
        machine::{compiler_constants::Constants, symbolic, verifier::periodic::Source},
        pcs_field::{FriExtension, PcsField},
        quotient_program::Program,
    },
    config::{self, Challenger, Dft, Val, ValMmcs},
    gpu_matrix::{Extension, MatrixSpec, RowOrder},
};
use p3_air::{symbolic::AirLayout, Air};
use p3_commit::ExtensionMmcs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::HidingFriPcs;
use p3_lookup::LogUpGadget;
use p3_merkle_tree::MerkleCap;
use rand_chacha::ChaCha20Rng;
use std::{marker::PhantomData, sync::Arc};

mod periodic;
mod prove;
#[cfg(test)]
mod tests;

const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("stark.cu"));
const HOST_METADATA: usize = 128 << 10;

pub(crate) trait StarkField: FriField + FriExtension + PcsField {}
impl<F: FriField + FriExtension + PcsField> StarkField for F {}

type EncodingPcs<F> = HidingFriPcs<Val, Dft, ValMmcs, ExtensionMmcs<Val, F, ValMmcs>, ChaCha20Rng>;
pub(crate) type NativeStarkConfig<F> = p3_uni_stark::StarkConfig<EncodingPcs<F>, F, Challenger>;
pub(crate) type NativeStarkProof<F> = p3_uni_stark::Proof<NativeStarkConfig<F>>;

pub(crate) struct PreparedStark<F> {
    runtime: Runtime,
    quotient: PreparedQuotient,
    periodic: Option<Matrix>,
    layout: AirLayout,
    log_rows: u32,
    log_chunks: usize,
    main_next: bool,
    field: PhantomData<F>,
}

#[derive(Clone, Copy)]
pub(crate) struct StarkRandomness<'a> {
    pub masks: &'a DeviceRandom,
    pub commitments: &'a DeviceRandom,
    pub fri: &'a DeviceRandom,
}

pub(crate) struct Starks {
    runtime: Runtime,
    hiding: Hiding,
    commitments: Commitments,
    quotients: Quotients,
    transforms: Transforms,
    scalars: Arc<Scalars>,
    transcripts: Arc<Transcripts>,
    openings: PcsOpenings,
    periodic_expand: Kernel,
}

fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(capacity).map_err(super::error)?;
    Ok(result)
}

fn parameters<F: StarkField>() -> FriParameters {
    let mut result =
        FriParameters::from_upstream(&crate::block_v2::profile::fri(()), config::CAP_HEIGHT);
    result.max_log_arity = F::MAX_LOG_ARITY;
    result.num_queries = F::NUM_QUERIES;
    result
}

impl Starks {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let periodic_expand = module.kernel_for_stage(
            "stark_periodic_expand",
            crate::proving::Stage::Preprocessing,
        )?;
        if !super::kernel::private_memory_fits(runtime.identity(), periodic_expand.local_bytes()?)?
        {
            return Err("CUDA periodic kernel exceeds private-memory admission".into());
        }
        Ok(Self {
            runtime: runtime.clone(),
            hiding: Hiding::new(runtime)?,
            commitments: Commitments::new(runtime)?,
            quotients: Quotients::new(runtime)?,
            transforms: Transforms::new(runtime)?,
            scalars: Scalars::new(runtime)?,
            transcripts: Transcripts::new(runtime)?,
            openings: PcsOpenings::new(runtime)?,
            periodic_expand,
        })
    }

    /// Prepare public AIR code and periodic prefixes once. The caller admits
    /// the symbolic compiler's bounded host workspace separately from proofs.
    pub(crate) fn prepare<F: StarkField, A: Air<symbolic::Builder> + Source>(
        &self,
        air: &A,
        log_rows: u32,
        host_bytes: usize,
        mode: Specialization,
    ) -> Result<PreparedStark<F>> {
        let params = parameters::<F>();
        let layout = AirLayout::from_air::<Val>(air);
        let periodic_allowance = host_bytes
            .checked_sub(symbolic::HOST_BYTES as usize)
            .ok_or("CUDA STARK preparation exceeds symbolic host allowance")?;
        if !(1..=24).contains(&log_rows)
            || log_rows as usize + 1 + params.log_blowup > 25
            || layout.main_width == 0
            || layout.preprocessed_width != 0
            || layout.permutation_width != 0
            || layout.num_permutation_challenges != 0
            || layout.num_permutation_values != 0
            || layout.num_periodic_columns != air.count()
            || F::EXTENSION != F::DEVICE_EXTENSION
        {
            return Err("unsupported CUDA single-AIR STARK geometry".into());
        }
        // This records only the public AIR. There is no witness, sampled
        // challenge or proof randomness in compiler inputs or cached programs.
        let recorded = symbolic::RecordedUni::new(air).map_err(super::error)?;
        let constants = recorded.normalize(Constants::cpu()).map_err(super::error)?;
        let log_chunks = symbolic::batch_log_chunks(air, &constants, &[], &LogUpGadget::new(), 1)
            .map_err(super::error)?;
        if log_chunks > params.log_blowup {
            return Err("CUDA STARK quotient degree exceeds the production LDE".into());
        }
        let constraints = constants.into_base_only::<F>().map_err(super::error)?;
        let program = Arc::new(Program::from_periodic_constraints(layout, &constraints)?);
        drop(constraints);
        let quotient = self.quotients.prepare(program, mode)?;
        let periodic = self.prepare_periodic(air, log_rows, periodic_allowance)?;
        Ok(PreparedStark {
            runtime: self.runtime.clone(),
            quotient,
            periodic,
            layout,
            log_rows,
            log_chunks,
            main_next: !air.main_next_row_columns().is_empty(),
            field: PhantomData,
        })
    }
}
