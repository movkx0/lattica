//! One source registry for OpenCL compilation and allocation-free startup censuses.
//! Prover-only programs omit native transaction/source witness kernels. Arithmetic,
//! transcript, randomness, commitments and all proof constraints remain identical.
use super::*;

// bool marks kernels needed only for native transaction/source generation.
const SOURCES: &[(bool, &str)] = &[
    (false, crate::gpu::KERNEL_SRC),
    (false, RETAINED_PATH_KERNEL),
    (false, lde_execute::KERNEL_SRC),
    (false, opening_reduce::KERNEL_SRC),
    (false, fri_fold::KERNEL_SRC),
    (false, query_reconstruct::KERNEL_SRC),
    (false, device::TRANSFORM_KERNEL_SRC),
    (false, device::QUOTIENT_KERNEL_SRC),
    (false, device::QUOTIENT_COMMIT_KERNEL_SRC),
    (false, device::LOOKUP_KERNEL_SRC),
    (false, device::OPENING_KERNEL_SRC),
    (false, device::QUADRATIC_OPENING_KERNEL_SRC),
    (false, device::OPENING_GROUP_KERNEL_SRC),
    (false, quotient::KERNEL_SRC),
    (false, device::FRI_KERNEL_SRC),
    (false, device::GENERAL_FRI_KERNEL_SRC),
    (false, device::QUERY_KERNEL_SRC),
    (false, device::TRACE_COMMIT_KERNEL_SRC),
    (false, device::STORAGE_KERNEL_SRC),
    (false, device::WITNESS_KERNEL_SRC),
    (true, device::WALLET_KERNEL_SRC),
    (true, device::PQ_POSEIDON_KERNEL_SRC),
    (true, device::PQ_OPERATIONS_KERNEL_SRC),
    (false, device::PUBLIC_HASH_KERNEL_SRC),
    (true, device::OPERATIONS_HASH_KERNEL_SRC),
    (true, device::PQ_CRYPTO_KERNEL_SRC),
    (true, device::PQ_RAW_CRYPTO_KERNEL_SRC),
    (true, device::RESEARCH_ARITHMETIC_KERNEL_SRC),
    (true, device::OPERATIONS_ARITHMETIC_KERNEL_SRC),
    (true, device::PQ_SOURCES_KERNEL_SRC),
    (true, device::PQ_SAMPLING_KERNEL_SRC),
    (true, device::WALLET_BATCH_KERNEL_SRC),
    (false, device::PERIODIC_KERNEL_SRC),
    (true, device::HTLC_KERNEL_SRC),
    (false, device::RANDOM_KERNEL_SRC),
    #[cfg(test)]
    (false, device::RANDOM_REFERENCE_KERNEL_SRC),
    (false, device::TRANSCRIPT_KERNEL_SRC),
    (false, device::SCALARS_KERNEL_SRC),
    (false, device::COMPILER_CONSTANTS_KERNEL_SRC),
    (false, device::COMPILER_FOLDING_KERNEL_SRC),
    (false, device::EVALUATIONS_KERNEL_SRC),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Census {
    pub bytes: usize,
    pub parts: usize,
    pub tuning_bytes: usize,
}

/// Visits exact emitted bytes, including empty-part separators. No allocation.
pub(super) fn visit(
    prover_only: bool,
    prefix: &str,
    poseidon: tuning::Poseidon,
    mut emit: impl FnMut(&str),
) {
    emit(prefix);
    emit("\n");
    emit(poseidon.defines());
    for &(native, source) in SOURCES {
        if !prover_only || !native {
            emit("\n");
            emit(source);
        }
    }
    emit("\n");
    tuning::kernel_sources(!prefix.is_empty(), emit);
}

pub(super) fn census(
    prover_only: bool,
    prefix: &str,
    poseidon: tuning::Poseidon,
) -> Option<Census> {
    let mut bytes = Some(0usize);
    visit(prover_only, prefix, poseidon, |part| {
        bytes = bytes.and_then(|n| n.checked_add(part.len()));
    });
    Some(Census {
        bytes: bytes?,
        parts: SOURCES
            .iter()
            .filter(|(native, _)| !prover_only || !native)
            .count()
            + 3,
        tuning_bytes: tuning::kernel_source_len(!prefix.is_empty())?,
    })
}

pub(super) fn source(
    prover_only: bool,
    prefix: &str,
    poseidon: tuning::Poseidon,
) -> Result<String, String> {
    let plan = census(prover_only, prefix, poseidon).ok_or("GPU program source size overflow")?;
    let mut source = String::with_capacity(plan.bytes);
    visit(prover_only, prefix, poseidon, |part| source.push_str(part));
    Ok(source)
}

#[cfg(test)]
mod tests;
