//! Context/report source census only. Native input arrays, packed scratch,
//! output buffers, C fixture/verification and decode owners are root claims.
use super::*;

fn add(a: usize, b: usize) -> GenerationResult<usize> {
    a.checked_add(b).ok_or(GenerationError::Overflow)
}
fn bytes<T>(n: usize) -> GenerationResult<usize> {
    n.checked_mul(size_of::<T>()).filter(|n| *n <= isize::MAX as usize)
        .ok_or(GenerationError::Overflow)
}
pub(super) fn combine(mut a: Requirements, b: Requirements) -> GenerationResult<Requirements> {
    for category in Category::ALL { a.add(category, b.get(category)).map_err(|_| GenerationError::Overflow)?; }
    Ok(a)
}
fn host(category: Category, host: usize) -> GenerationResult<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(host).map_err(|_| GenerationError::Overflow)?, device: 0,
    }))
}
fn frames() -> GenerationResult<usize> {
    [
        bytes::<GenerationContextPlan>(8)?, bytes::<OwnedGenerationContext>(8)?,
        bytes::<ProvingContext>(8)?, bytes::<GenerationSpendSummary>(8)?,
        bytes::<NativeGenerationCompletion>(8)?, bytes::<NativeGenerationTotals>(8)?,
        bytes::<NativeSessionRecord>(8)?, bytes::<RetiredGenerationSession>(8)?,
        bytes::<NativeGenerationTerminal>(8)?, bytes::<GenerationFailure>(8)?,
        bytes::<TerminalRecord>(8)?, bytes::<Reservation>(16)?, bytes::<Ledger>(8)?,
        bytes::<Report>(8)?, bytes::<SpendEvidence>(8)?, bytes::<SpendLimits>(8)?,
        bytes::<GenerationResult<(PrivateSpendOutput, GenerationSpendSummary)>>(8)?,
        bytes::<Result<NativeGenerationTerminal, GenerationFailure>>(8)?,
        bytes::<[u64; 32]>(8)?, bytes::<lattica_prover_p3::block_v2::gpu_hash::Snapshot>(8)?,
        report_transport::required_host_bytes(),
        super::super::owned_workflow_observation::additional_host_bytes().map_err(|_| GenerationError::Overflow)?,
    ].into_iter().try_fold(64 << 10, add)
}
pub(super) fn terminal_requirements() -> GenerationResult<Requirements> {
    // All terminal serialization/move/error frames survive runtime destruction.
    host(Category::Report, frames()?)
}
pub(super) fn runtime_requirements() -> GenerationResult<Requirements> {
    let startup = WorkflowRuntimePlan::outer_host_v1_requirement().map_err(|_| GenerationError::Resource)?;
    let startup_bytes = startup.get(Category::PhaseScratch);
    if startup.total().map_err(|_| GenerationError::Resource)? != startup_bytes
        || startup_bytes.host < 8 << 30 || startup_bytes.device == 0 || startup_bytes.device >= 8 << 30
    { return Err(GenerationError::Resource); }
    let diagnostics = Diagnostics::generation_declared_enclosing_bytes().map_err(|_| GenerationError::Resource)?;
    let identity = Diagnostics::generation_declared_identity_json_bytes().map_err(|_| GenerationError::Resource)?;
    // Session identity is already in the core startup. Additional owned JSON,
    // serialization input, context seed and diagnostics cloning overlap here.
    let context = [diagnostics, identity.checked_mul(8).ok_or(GenerationError::Overflow)?,
        frames()?, bytes::<Sha3_256>(8)?, bytes::<Value>(16)?,
        bytes::<String>(16)?, bytes::<Vec<u8>>(16)?].into_iter().try_fold(0, add)?;
    // The native entry uses the same bounded Run Operation/WitnessTrace path
    // (16 capabilities, 19*6 closed observation keys, no components). Its entry
    // and MatrictN10 profile labels fit the existing static JSON/error envelope.
    // SpendEvidence is fixed scalars plus a validated static 64-byte source ID.
    let reports = lattica_prover_p3::proving::operation_storage::RawPreparationReportStorage::new()
        .map_err(|_| GenerationError::Resource)?;
    if lattica_prover_p3::block_v2::native_gpu::private_spend::ENTRY_POINT != "native_matrict_spend" {
        return Err(GenerationError::Resource);
    }
    let report = add(reports.required_host_bytes, add(bytes::<Report>(8)?, bytes::<SpendEvidence>(8)?)?)?;
    combine(combine(combine(startup,
        host(Category::RegisteredMetadata, PUBLIC_METADATA_LIMIT_BYTES)?)?,
        host(Category::PhaseScratch, context)?)?, host(Category::Report, report)?)
}

pub(super) fn minimum_output_requirements() -> GenerationResult<Requirements> {
    // Native output: fixed encoded statement/proof and eighteen 256-word
    // output-key polynomials. Source dispatch uses exact fixed-size Vecs.
    let data = 202_848usize.checked_add(53_600).and_then(|n| n.checked_add(18 * 256 * 8))
        .ok_or(GenerationError::Overflow)?;
    host(Category::NativeProof, add(data,
        add(bytes::<PrivateSpendOutput>(8)?, bytes::<GenerationSpendSummary>(8)?)?)?)
}
