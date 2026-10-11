//! Cached prover host metadata, excluding separately admitted program source,
//! witness schedule and packed lookup graphs. Shared engine/driver state and
//! the enclosing cache container require worker-level lifetime accounting.
use super::*;
use crate::block_v2::gpu_hash::cache_metadata::{add, bound, capacity};
use p3_batch_stark::common::PreprocessedInstanceMeta;
use p3_lookup::Lookups;

fn backing(data: &ProverData<Config>, rows: usize, count: usize) -> Result<(usize, bool), String> {
    let common = &data.common;
    let pre = common
        .preprocessed
        .as_ref()
        .ok_or("cached preprocessing metadata missing")?;
    if common.lookups.len() != count
        || pre.instances.len() != count
        || pre.matrix_to_instance.len() != count
    {
        return Err("cached preprocessing metadata count".into());
    }
    let mut bytes = capacity::<Lookups<Val>>(common.lookups.capacity())?;
    bytes = add(
        bytes,
        capacity::<Option<PreprocessedInstanceMeta>>(pre.instances.capacity())?,
    )?;
    bytes = add(bytes, capacity::<usize>(pre.matrix_to_instance.capacity())?)?;
    bytes = add(bytes, capacity::<[Val; 4]>(pre.commitment.root_capacity())?)?;
    let (pcs, device_salts) = data
        .prover_only
        .preprocessed_prover_data
        .as_ref()
        .ok_or("cached PCS data missing")?
        .cached_preprocessing_backing(rows, count)?;
    Ok((add(bytes, pcs)?, device_salts))
}

pub(crate) fn admit_data(
    data: &ProverData<Config>,
    rows: usize,
    count: usize,
) -> Result<(), String> {
    let (backing, device_salts) = backing(data, rows, count)?;
    let bytes = add(core::mem::size_of::<ProverData<Config>>(), backing)?;
    let limit = bound(rows as u64, device_salts)?
        .checked_mul(count as u64)
        .ok_or("cached preprocessing allowance overflow")?;
    if bytes as u64 > limit {
        return Err("cached preprocessing metadata exceeds allowance".into());
    }
    Ok(())
}

pub(super) fn admit_registered(program: &RegisteredProgram) -> Result<(), String> {
    let rows = program.air.program().height();
    let (backing, device_salts) = backing(&program.data, rows, 1)?;
    let bytes = add(
        core::mem::size_of::<RegisteredProgram>(),
        add(
            backing,
            program.preprocessing_receipt.retained_host_bytes()?,
        )?,
    )?;
    let limit = bound(rows as u64, device_salts)?;
    if bytes as u64 > limit {
        return Err("cached registered prover metadata exceeds allowance".into());
    }
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_cached_prover_metadata rows={rows} device_salts={device_salts} host_bytes={bytes} limit_bytes={limit} source_schedule_lookup_separate=true shared_context_separate=true");
    }
    Ok(())
}
