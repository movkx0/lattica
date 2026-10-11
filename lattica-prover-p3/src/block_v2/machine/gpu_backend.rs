//! Device setup for batches of single-table execution AIRs. Selection and worker
//! resource profiles are intentionally separate from this internal adapter.
use super::{gpu_program::WitnessProgram, MachineAir};
use crate::block_v2::{gpu_hash::device::PreparedWitness, profile};
use p3_air::BaseAir;
use p3_batch_stark::{common::ProverOnlyData, ProverData};
use p3_uni_stark::StarkGenericConfig;
use std::sync::Arc;
pub(crate) mod resources;

pub(crate) struct PreparedProgram {
    pub(crate) witness: PreparedWitness,
    pub(crate) data: ProverData<profile::Config>,
}

pub(crate) struct PreparedBatch {
    pub(crate) witnesses: Vec<PreparedWitness>,
    pub(crate) data: ProverData<profile::Config>,
}

fn admit_batch(
    airs: &[&MachineAir],
    config: &profile::Config,
    host_allowance: usize,
) -> Result<(), String> {
    if config.is_zk() != 1 {
        return Err("device execution setup requires hiding profile".into());
    }
    if airs.is_empty() || airs.len() > 256 {
        return Err("GPU witness AIR count exceeded".into());
    }
    if airs
        .iter()
        .any(|air| air.program().height() != airs[0].program().height())
    {
        return Err("GPU preprocessing batch requires equal padded AIR heights".into());
    }
    let device_salts = config.pcs().device_preprocessing_salts()?;
    let bounds = airs
        .iter()
        .map(|air| resources::Bounds::for_program_with_device_salts(air.program(), device_salts))
        .collect::<Result<Vec<_>, _>>()?;
    let reservation = resources::batch_reservation(&bounds)?;
    if reservation.host_bytes > host_allowance as u64 {
        return Err("GPU witness batch source/compiler/staging exceeds host allowance".into());
    }
    resources::check_batch_worker(
        crate::block_v2::quotient_pcs::gpu_witness_enabled(),
        &bounds,
    )?;
    eprintln!(
        "bounded_gpu_witness_resources bounds={} reservation={}",
        serde_json::to_string(&bounds).unwrap(),
        serde_json::to_string(&reservation).unwrap()
    );
    Ok(())
}

#[cfg(test)]
pub(crate) fn prepare(
    air: &MachineAir,
    config: &profile::Config,
    host_allowance: usize,
    run: &crate::proving::Run,
) -> Result<PreparedProgram, String> {
    let mut batch = prepare_batch(&[air], config, host_allowance, run)?;
    Ok(PreparedProgram {
        witness: batch.witnesses.remove(0),
        data: batch.data,
    })
}

#[cfg(test)]
pub(crate) fn prepare_batch(
    airs: &[&MachineAir],
    config: &profile::Config,
    host_allowance: usize,
    run: &crate::proving::Run,
) -> Result<PreparedBatch, String> {
    // Admission precedes even the bounded symbolic field operations.
    admit_batch(airs, config, host_allowance)?;
    let session = config.pcs().quotient_session()?;
    let _execution_observation = session.observe_execution(run)?;
    let symbolic = airs
        .iter()
        .map(|air| {
            super::symbolic::prepare_machine(
                air,
                super::compiler_constants::Constants::device(&session, run),
            )
            .map(|prepared| prepared.into_parts().0)
            .map_err(|e| format!("GPU setup analysis: {e:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    prepare_batch_admitted(airs, config, host_allowance, symbolic)
}

pub(crate) fn prepare_with_symbolic(
    air: &MachineAir,
    config: &profile::Config,
    host_allowance: usize,
    symbolic: super::symbolic::LookupLayout,
) -> Result<PreparedProgram, String> {
    let mut batch = prepare_batch_with_symbolic(&[air], config, host_allowance, vec![symbolic])?;
    Ok(PreparedProgram {
        witness: batch.witnesses.remove(0),
        data: batch.data,
    })
}

pub(crate) fn prepare_batch_with_symbolic(
    airs: &[&MachineAir],
    config: &profile::Config,
    host_allowance: usize,
    symbolic: Vec<super::symbolic::LookupLayout>,
) -> Result<PreparedBatch, String> {
    admit_batch(airs, config, host_allowance)?;
    prepare_batch_admitted(airs, config, host_allowance, symbolic)
}

fn prepare_batch_admitted(
    airs: &[&MachineAir],
    config: &profile::Config,
    host_allowance: usize,
    symbolic: Vec<super::symbolic::LookupLayout>,
) -> Result<PreparedBatch, String> {
    if symbolic.len() != airs.len() || symbolic.iter().any(|s| s.log_chunks > profile::LOG_BLOWUP) {
        return Err("GPU preprocessing symbolic batch geometry mismatch".into());
    }
    let pcs = config.pcs();
    let session = pcs.quotient_session()?;
    let mut witnesses = Vec::with_capacity(airs.len());
    let mut traces = Vec::with_capacity(airs.len());
    for air in airs {
        let program = WitnessProgram::compile(air.program(), host_allowance)
            .map_err(|e| format!("GPU witness compilation failed: {e:?}"))?;
        let witness = session.prepare_witness(Arc::new(program))?;
        let trace = witness.preprocessing_trace(&session)?;
        if trace.spec().rows() != air.program().height()
            || trace.spec().columns() != air.preprocessed_width()
        {
            return Err("GPU preprocessing does not match registered AIR".into());
        }
        let domain = crate::block_v2::gpu_hash::device::DomainSpec::new(
            1,
            air.program().height().ilog2() as usize + 1,
        )?;
        traces.push((domain, trace));
        witnesses.push(witness);
    }
    let (cap, data) = pcs.commit_preprocessing_device(traces)?;
    let common = super::backend::common_batch_from_prepared(airs, cap, symbolic)
        .map_err(|e| format!("GPU preprocessing metadata failed: {e:?}"))?;
    let prepared = PreparedBatch {
        witnesses,
        data: ProverData {
            common,
            prover_only: ProverOnlyData {
                preprocessed_prover_data: Some(data),
            },
        },
    };
    super::backend::cache_storage::admit_data(
        &prepared.data,
        airs[0].program().height(),
        airs.len(),
    )?;
    Ok(prepared)
}

pub(crate) fn check_selected() -> Result<(), String> {
    use crate::block_v2::{gpu_hash, quotient_pcs, resident_pcs};
    let selected = quotient_pcs::gpu_witness_enabled();
    resources::check_worker(selected, None)?;
    if selected
        && (!cfg!(feature = "gpu")
            || !gpu_hash::is_enabled()
            || !resident_pcs::research_enabled()
            || !quotient_pcs::research_enabled()
            || !quotient_pcs::gpu_pcs_device_only_enabled())
    {
        return Err("GPU witness mode requires initialized OpenCL device-only proving".into());
    }
    Ok(())
}

pub(super) fn trace(
    prepared: &PreparedWitness,
    session: &crate::block_v2::gpu_hash::device::DeviceSession,
    public: &[super::program::Val],
    witness: &[super::program::Val],
    host_allowance: usize,
) -> Result<crate::block_v2::gpu_hash::device::DeviceMatrix, super::ExecutionError> {
    use p3_field::PrimeField64;
    let values = public
        .len()
        .checked_add(witness.len())
        .ok_or(super::ExecutionError::TooLarge)?;
    // Caller field values, canonical staging and the device API's upload
    // vector can coexist. Check the complete staging before converting.
    if values
        .checked_mul(24)
        .and_then(|n| n.checked_add(8))
        .is_none_or(|n| n > host_allowance)
    {
        return Err(super::ExecutionError::TooLarge);
    }
    let words: Vec<_> = public
        .iter()
        .chain(witness)
        .map(|v| v.as_canonical_u64())
        .collect();
    prepared
        .trace(
            session,
            &words[..public.len()],
            &words[public.len()..],
            host_allowance,
        )
        .map_err(|error| match error {
            crate::block_v2::gpu_hash::device::WitnessError::Execution(error) => error,
            crate::block_v2::gpu_hash::device::WitnessError::Device(error) => {
                eprintln!("GPU witness execution rejected: {error}");
                super::ExecutionError::GpuFailure
            }
        })
}
