//! Native batch-STARK orchestration for immutable recursive MachineAir programs.
//! This internal entry point is not yet the registered recursive worker route.
use super::{
    budget::Reservation, hiding::CommittedMatrix, Buffer, Commitments, FieldSpan, FriParameters,
    HiddenCommitment, Hiding, HidingInput, Lookups, Matrix, OpeningPoints, OpeningRound,
    PcsOpenings, PreparedLookup, PreparedQuotient, PreparedWitness, PreprocessingTrace, Quotients,
    Randoms, Result, Runtime, Scalars, Specialization, StarkRandomness, Transcript, Transcripts,
    Witnesses,
};
use crate::{
    block_v2::{
        lookup_bus_layout as bus_layout,
        machine::{compiler_constants::Constants, symbolic, MachineAir},
        profile::{self, Challenge},
        quotient_program::Program,
    },
    config::{Val, ValMmcs},
    gpu_matrix::Extension,
};
use p3_air::{symbolic::AirLayout, BaseAir};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_lookup::LogUpGadget;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;

mod prove;
#[cfg(test)]
mod tests;

pub(crate) type NativeBatchProof = p3_batch_stark::BatchProof<super::NativeStarkConfig<Challenge>>;
type Cap = <ValMmcs as p3_commit::Mmcs<Val>>::Commitment;
// Each instance retains three public handles. The runtime independently caps
// their aggregate storage/count, modules, allocations and expanded PCS matrices.
const MAX_INSTANCES: usize = 8;
const HOST_METADATA: usize = 128 << 10;
const PROOF_HEADERS: usize = 256 << 10;
const CAP_BYTES: usize = (1 << profile::CAP_HEIGHT) * 4 * 8;

fn vector<T>(capacity: usize) -> Result<Vec<T>> {
    let mut result = Vec::new();
    result.try_reserve_exact(capacity).map_err(super::error)?;
    Ok(result)
}
fn parameters() -> FriParameters {
    FriParameters::from_upstream(&profile::fri(()), profile::CAP_HEIGHT)
}
fn cap(data: &HiddenCommitment) -> Result<Cap> {
    let raw = data.cap(CAP_BYTES)?;
    let mut roots = vector(raw.len() / 4)?;
    for words in raw.chunks_exact(4) {
        roots.push(std::array::from_fn(|i| Val::from_u64(words[i])));
    }
    Ok(p3_merkle_tree::MerkleCap::new(roots))
}
fn observe_cap(data: &HiddenCommitment, transcript: &mut Transcript) -> Result<Cap> {
    let raw = data.cap(CAP_BYTES)?;
    transcript.observe(&raw)?;
    let mut roots = vector(raw.len() / 4)?;
    for words in raw.chunks_exact(4) {
        roots.push(std::array::from_fn(|i| Val::from_u64(words[i])));
    }
    Ok(p3_merkle_tree::MerkleCap::new(roots))
}

struct Instance {
    witness: PreparedWitness,
    quotient: PreparedQuotient,
    lookup: PreparedLookup,
    preprocessing: PreprocessingTrace,
    layout: AirLayout,
    log_rows: u32,
    log_chunks: usize,
    witnesses: usize,
}
impl Instance {
    fn chunks(&self) -> usize {
        1 << (self.log_chunks + 1)
    }
    fn log_lde(&self, params: FriParameters) -> u32 {
        self.log_rows + 1 + params.log_blowup as u32
    }
}

/// Public preparation is bound to one runtime and to the compiled programs.
/// Successful proofs may reuse it. A failed consuming attempt retires its salt
/// family; callers must prepare afresh before retrying that public commitment.
pub(crate) struct PreparedBatch {
    runtime: Runtime,
    instances: Vec<Instance>,
    preprocessing: HiddenCommitment,
    bus_ids: Vec<Vec<usize>>,
    message_width: usize,
    _host: Reservation,
}
impl PreparedBatch {
    /// Registration must authenticate this root against the independently
    /// approved public program. A GPU-produced cap alone is not a trusted key.
    pub(crate) fn preprocessing_cap(&self) -> Result<Cap> {
        cap(&self.preprocessing)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MachineInputs<'a> {
    pub public: &'a [u64],
    pub witness: &'a [u64],
}

pub(crate) struct BatchStarks {
    runtime: Runtime,
    witnesses: Witnesses,
    lookups: Lookups,
    hiding: Hiding,
    commitments: Commitments,
    quotients: Quotients,
    scalars: Arc<Scalars>,
    transcripts: Arc<Transcripts>,
    openings: PcsOpenings,
    randoms: Arc<Randoms>,
}
impl BatchStarks {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        Ok(Self {
            runtime: runtime.clone(),
            witnesses: Witnesses::new(runtime)?,
            lookups: Lookups::new(runtime)?,
            hiding: Hiding::new(runtime)?,
            commitments: Commitments::new(runtime)?,
            quotients: Quotients::new(runtime)?,
            scalars: Scalars::new(runtime)?,
            transcripts: Transcripts::new(runtime)?,
            openings: PcsOpenings::new(runtime)?,
            randoms: Randoms::new(runtime)?,
        })
    }

    /// Source program storage is caller-owned and separately admitted. CPU
    /// work compiles public metadata only; preprocessing expansion runs on CUDA.
    pub(crate) fn prepare(
        &self,
        airs: &[&MachineAir],
        host_bytes: usize,
        mode: Specialization,
    ) -> Result<PreparedBatch> {
        if airs.is_empty() || airs.len() > MAX_INSTANCES {
            return Err("CUDA machine batch requires 1..8 instances".into());
        }
        let host_peak = (symbolic::HOST_BYTES as usize)
            .checked_add(airs.len() * symbolic::LOOKUP_RETAINED_HOST_BYTES as usize)
            .and_then(|n| n.checked_add(self.runtime.snapshot().public_program_bytes))
            .and_then(|n| n.checked_add(HOST_METADATA))
            .ok_or("CUDA batch preparation host allowance overflow")?;
        if host_bytes < host_peak {
            return Err("CUDA batch preparation exceeds host allowance".into());
        }
        let params = parameters();
        for air in airs {
            let log = air.program().height().ilog2();
            if !(1..=24).contains(&log)
                || log as usize + 1 + params.log_blowup > 25
                || air.num_periodic_columns() != 0
                || air.preprocessed_width() == 0
                || !air.main_next_row_columns().is_empty()
                || !air.preprocessed_next_row_columns().is_empty()
            {
                return Err("unsupported CUDA machine batch geometry".into());
            }
        }
        let host = self.runtime.state.budget.public_program(HOST_METADATA)?;
        let mut instances = vector(airs.len())?;
        let mut lookups = vector(airs.len())?;
        let mut chunks = 0;
        for air in airs {
            let symbolic =
                symbolic::prepare_machine(air, Constants::cpu()).map_err(super::error)?;
            let layout = symbolic::batch_layout(
                AirLayout::from_air::<Val>(*air),
                &symbolic.lookups,
                &LogUpGadget::new(),
            )
            .map_err(super::error)?;
            if symbolic.lookups.is_empty() || symbolic.log_chunks > params.log_blowup {
                return Err("CUDA machine batch requires supported LogUp constraints".into());
            }
            chunks += 1 << (symbolic.log_chunks + 1);
            if chunks > 256 {
                return Err("CUDA batch expands beyond 256 quotient matrices".into());
            }
            let program = Arc::new(Program::from_constraints(layout, &symbolic.constraints)?);
            drop(symbolic.constraints);
            let quotient = self.quotients.prepare(program, mode)?;
            let lookup = self.lookups.prepare(
                AirLayout::from_air::<Val>(*air),
                &symbolic.lookups,
                host_bytes,
            )?;
            let witness = self.witnesses.prepare(air.program(), host_bytes)?;
            let preprocessing = self.witnesses.preprocessing(&witness)?;
            instances.push(Instance {
                witness,
                quotient,
                lookup,
                preprocessing,
                layout,
                log_rows: air.program().height().ilog2(),
                log_chunks: symbolic.log_chunks,
                witnesses: air.program().witness_values(),
            });
            lookups.push(symbolic.lookups);
        }
        let refs: Vec<_> = lookups.iter().map(|l| &**l).collect();
        let (bus_ids, message_width, _) = bus_layout(&refs)?;
        drop(refs);
        drop(lookups);
        let mut inputs = vector(instances.len())?;
        for instance in &instances {
            inputs.push(self.hiding.prepare_preprocessing(
                instance.preprocessing.matrix(),
                instance.log_lde(params),
                16,
            )?);
        }
        let borrowed: Vec<_> = inputs.iter().map(HidingInput::Trace).collect();
        // Exact production public seed, distinct from every private proof RNG.
        let salts = self.randoms.import(ChaCha20Rng::from_seed([0; 32]))?;
        let preprocessing =
            self.hiding
                .commit_batch(&self.commitments, &borrowed, &salts, params.cap_height)?;
        Ok(PreparedBatch {
            runtime: self.runtime.clone(),
            instances,
            preprocessing,
            bus_ids,
            message_width,
            _host: host,
        })
    }
}
