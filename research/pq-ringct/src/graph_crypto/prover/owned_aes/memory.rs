//! Source storage census outside the backend's separately admitted allowance.
use super::*;
use crate::{
    execution::workflow_resources::{PhaseFailure, Retained, RetainedNative},
    graph_crypto::RequestDescriptor,
};

pub(super) fn planning_frames() -> Result<usize> {
    let total = [endpoints::SOURCE_STORE_CONSTRUCTION_FRAME_BYTES,
        bytes::<[crate::component_tree::native_shape::cohort::Request<'static>; 16]>(8)?,
        bytes::<[Option<crate::component_tree::native_shape::NativeCoreBound>; 16]>(8)?,
        bytes::<source::AesBlueprint>(8)?, bytes::<OwnedAesNodeSource>(8)?,
        bytes::<OwnedAesStep>(8)?, bytes::<OwnedAesSlotRequirements>(8)?,
        bytes::<[Option<usize>; usize::BITS as usize]>(4)?,
        bytes::<Requirements>(16)?, bytes::<Sha3_256>(4)?,
        bytes::<Vec<u64>>(4)?, bytes::<u64>(12)?,
        bytes::<Result<OwnedAesRequestPlan<'static>>>(8)?,
        bytes::<[usize; 24]>(8)?, paired_runtime::caller_bytes()?, super::execute::execution_frames()?]
        .into_iter().try_fold(0, add)?;
    #[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
    let total = add(total, operations::retaining::forwarding_bytes()?)?;
    Ok(total)
}

pub(super) fn failure_requirements() -> Result<Requirements> {
    use crate::execution::workflow_resources::OuterOwnedError;
    let host = [bytes::<PhaseFailure<PairedFailure>>(8)?, bytes::<PairedFailure>(16)?,
        bytes::<PhaseFailure<OuterOwnedError>>(8)?, bytes::<OuterOwnedError>(16)?]
        .into_iter().try_fold(0, add)?;
    requirement(Category::Report, host)
}

pub(super) fn endpoint_output() -> Result<Requirements> {
    requirement(Category::RegisteredMetadata, bytes::<Retained<OwnedAesEndpoints<'static>>>(8)?)
}

pub(super) fn endpoint_scratch(request: &Request) -> Result<Requirements> {
    let RequestDescriptor::Aes(descriptor) = request.descriptor() else {
        return Err(PairedFailure::Source);
    };
    // commit_bytes_on_gpu packs u16 limbs in a Vec<u64>. Output bytes live
    // simultaneously with output packing; no subtraction or overlap credit.
    let packing = bytes::<u64>(add(26, descriptor.output_len.div_ceil(2))?)?;
    let vectors = add(bytes::<Vec<u64>>(4)?, bytes::<Vec<u8>>(4)?)?;
    requirement(Category::PhaseScratch, add(add(packing, descriptor.output_len)?,
        add(add(vectors, bytes::<[u8; 52]>(8)?)?, paired_runtime::caller_bytes()?)?)?)
}

pub(super) fn native_requirements(request: &Request, index: usize) -> Result<(Requirements, Requirements)> {
    let (output, scratch) = operations::native::OwnedAesNativeSource::new(request, index)?
        .source_requirements()?;
    Ok((combine(&[output,
        requirement(Category::RegisteredMetadata, bytes::<RetainedNative<OwnedAesNativeOutput<'static>>>(8)?)?,
    ])?, combine(&[scratch,
        requirement(Category::PhaseScratch, paired_runtime::caller_bytes()?)?,
        crate::execution::workflow_resources::aes_native_issuer_scratch_requirements()
            .map_err(|_| PairedFailure::Resource)?,
    ])?))
}
