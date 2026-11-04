//! CPU registration can run ahead of the single GPU source-preparation owner.
//! Each graph has two immutable readers. Once both finish, the coordinator
//! moves the exact vector into its normal source phase without copying it.
use super::*;
use crate::execution::retained_resources::{Bytes, Category, Requirements};
use crate::metadata_parallel::{self as workers, Error};
use crate::rust_verify::committed_backend::source_binding::prepared::{EncodedGraphStructure, FRAME_BYTES};
use std::sync::RwLock;

fn host(requirements: Requirements) -> Result<usize> {
    usize::try_from(requirements.total().map_err(|_| failure("registration budget overflow"))?.host)
        .map_err(|_| failure("registration host range"))
}

pub(super) fn prepare<'graph, const N: usize>(planning: &mut WorkflowPlanning<'_>,
    plans: &FixedCaseOwnerSlots<'_, PreparationPlanResult<'graph>, N>,
    outputs: &FixedCaseOwnerSlots<'_, PreparedSourceResult<'graph>, N>) -> Result<bool>
{
    let ceiling = lattica_prover_p3::block_v2::machine::verifier::batch::shape::metadata_cpu_worker_ceiling();
    if ceiling < 2 || !crate::preparation_options::metadata_workers_enabled("registration")
        || !crate::preparation_options::parallel_registration()
        || !crate::preparation_options::structural_reuse()
        || !crate::preparation_options::buffered_encoding() { return Ok(false); }
    if !matches!(N, 3 | 4) { return Err(failure("registration case size")); }
    let mut inputs = [None; 4];
    let mut retained = 0usize;
    let mut output_bytes = 0usize;
    let mut largest_phase = 0usize;
    let mut costs = [0usize; 4];
    for index in 0..N {
        let plan = plans.get(index)?.get()?.as_ref().map_err(|_| failure("registration plan refused"))?;
        let input = plan.registration_input();
        costs[index] = input.1;
        retained = retained.checked_add(input.2).ok_or_else(|| failure("registration retained overflow"))?;
        output_bytes = output_bytes.checked_add(host(plan.output_requirements())?)
            .ok_or_else(|| failure("registration source retained overflow"))?;
        largest_phase = largest_phase.max(host(planning.source_preparation_requirements(plan)
            .map_err(|_| failure("registration source admission"))?)?);
        inputs[index] = Some(input);
    }
    // Preserve room for every retained output and the largest normal source
    // phase, including its original bookkeeping/backend allowance.
    let future = output_bytes.checked_add(largest_phase).ok_or_else(|| failure("registration future overflow"))?;
    let budget = usize::try_from(planning.ledger().remaining().host).unwrap_or(usize::MAX).saturating_sub(future);
    let transient = FRAME_BYTES.checked_add(16 << 10).ok_or_else(|| failure("registration frame overflow"))?;
    let encode = match workers::Plan::new(ceiling, N, budget, retained, transient) {
        Ok(plan) if plan.width >= 2 => plan, _ => return Ok(false),
    };
    let hash = match workers::Plan::new(ceiling, 2 * N, budget, retained, transient) {
        Ok(plan) if plan.width >= 2 => plan, _ => return Ok(false),
    };
    let _original = planning.ledger().reserve(Category::PhaseScratch,
        Bytes { host: encode.host_bytes.max(hash.host_bytes) as u64, device: 0 })
        .map_err(|_| failure("registration parallel original"))?;
    let mut cells: [RwLock<Option<Box<EncodedGraphStructure<'graph>>>>; 4] = core::array::from_fn(|_| RwLock::new(None));
    let outcome = (|| {
        let stats = workers::run(encode, &costs[..N], |_| Ok(()), |_, index| {
            let (graph, words, _) = inputs[index].ok_or(Error::Geometry)?;
            EncodedGraphStructure::encode(graph, words).map_err(|_| Error::Worker)
        }, |index, encoded| {
            *cells[index].get_mut().map_err(|_| Error::Publication)? = Some(encoded);
            Ok(())
        }).map_err(|_| failure("registration encoding worker failed"))?;
        workers::report("registration_encode", stats);
        let mut hash_costs = [0usize; 8];
        for i in 0..2 * N { hash_costs[i] = costs[i / 2]; }
        let mut labels = [[0u8; 32]; 4];
        let stats = workers::run(hash, &hash_costs[..2 * N], |_| Ok(()), |_, index| {
            let encoded = cells[index / 2].read().map_err(|_| Error::Worker)?;
            encoded.as_ref().ok_or(Error::Geometry)?.hash(index % 2 != 0).map_err(|_| Error::Worker)
        }, |index, digest| {
            let member = index / 2;
            if index % 2 == 0 { labels[member] = digest; return Ok(()); }
            let encoded = cells[member].write().map_err(|_| Error::Publication)?.take().ok_or(Error::Publication)?;
            let registration = (*encoded).finish(labels[member], digest);
            let plan = plans.get(member).and_then(|slot| slot.get()).map_err(|_| Error::Publication)?
                .as_ref().map_err(|_| Error::Publication)?;
            let output = outputs.get(member).map_err(|_| Error::Publication)?;
            output.install(planning.prepare_sources(plan.operation_with_registration(registration)))
                .map_err(|_| Error::Publication)?;
            output.get().map_err(|_| Error::Publication)?.as_ref().map_err(|_| Error::Publication)?;
            Ok(())
        }).map_err(|_| failure("registration hashing or source continuation failed"))?;
        workers::report("registration_hash", stats);
        Ok(true)
    })();
    if outcome.is_err() { planning.poison_numeric_preparation(); }
    outcome
}
