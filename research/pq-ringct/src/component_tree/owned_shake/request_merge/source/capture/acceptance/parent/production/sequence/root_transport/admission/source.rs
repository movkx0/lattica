//! Same fixed maintained source header semantics as B065, with no visibility
//! changes to that independent action and no dynamic header allocation.
use super::*;
use p3_field::PrimeCharacteristicRing;
use crate::component_tree::{
    commitment, words, EndpointContext, Kind, CONTEXT, CONTRACT_DOMAIN, COUNT,
    DESCRIPTOR, EXPECTED_INPUT, EXPECTED_OUTPUT, FIRST, KIND, LEVEL, REQUEST,
    STATEMENT, TOTAL,
};

pub(super) fn header(spec: &Spec, context: &EndpointContext) -> AdmissionResult<[Val; HEADER]> {
    let Kind::Shake(descriptor) = &spec.contract.kind else {
        return Err(ParentCompileError::Source);
    };
    if descriptor.input_len != 16_416 || descriptor.output_len != 137
        || spec.first != 0 || spec.count != 122 || spec.level != 3
        || spec.contract.total != 122
    {
        return Err(ParentCompileError::Source);
    }
    let descriptor_fields = [
        spec.contract.tag(),
        u64::from(spec.contract.total),
        u64::try_from(descriptor.input_len).map_err(|_| ParentCompileError::Overflow)?,
        u64::try_from(descriptor.output_len).map_err(|_| ParentCompileError::Overflow)?,
    ];
    let descriptor = commitment::hash_fields(CONTRACT_DOMAIN, &descriptor_fields)
        .map_err(|_| ParentCompileError::Source)?.map(Val::from_u64);
    let mut header = [Val::ZERO; HEADER];
    header[..8].copy_from_slice(&words(&spec.contract.profile));
    header[CONTEXT..CONTEXT + 8].copy_from_slice(&words(&context.context));
    for (offset, values) in [
        (STATEMENT, context.statement),
        (EXPECTED_INPUT, context.input),
        (EXPECTED_OUTPUT, context.output),
    ] {
        header[offset..offset + 4].copy_from_slice(&values);
    }
    for (offset, value) in [
        (KIND, spec.contract.tag()),
        (REQUEST, u64::from(spec.contract.request)),
        (FIRST, u64::from(spec.first)),
        (COUNT, u64::from(spec.count)),
        (TOTAL, u64::from(spec.contract.total)),
        (LEVEL, u64::from(spec.level)),
    ] {
        header[offset] = Val::from_u64(value);
    }
    header[DESCRIPTOR..DESCRIPTOR + 4].copy_from_slice(&descriptor);
    Ok(header)
}
