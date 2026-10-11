//! Adapter from current host-backed PCS evaluations to the bounded GPU program.
//! Row packing and canonical encoding are transfers; all quotient field
//! arithmetic (including selectors and alpha powers) runs on the device.
use super::program::Program;
use crate::{block_v2::profile::Challenge, config::Val};
use p3_field::{
    coset::TwoAdicMultiplicativeCoset, BasedVectorSpace, PrimeCharacteristicRing, PrimeField64,
};
use p3_matrix::Matrix;

/// Owned quotient inputs and output stay on GPU through the hiding commitment.
#[allow(clippy::too_many_arguments)]
pub(super) fn owned_quotient<F: crate::block_v2::gpu_hash::FriExtension>(
    session: &crate::block_v2::gpu_hash::device::DeviceSession,
    program: &std::sync::Arc<Program>,
    public_values: &[Val],
    trace_domain: impl Into<crate::block_v2::gpu_hash::device::DomainSpec>,
    quotient_domain: impl Into<crate::block_v2::gpu_hash::device::DomainSpec>,
    main: &crate::block_v2::gpu_hash::device::DeviceMatrix,
    permutation: Option<&crate::block_v2::gpu_hash::device::DeviceMatrix>,
    terminals: &[F],
    challenges: &[F],
    preprocessed: Option<&crate::block_v2::gpu_hash::device::DeviceMatrix>,
    alpha: F,
) -> Result<crate::block_v2::gpu_hash::device::DeviceMatrix, String> {
    let trace_domain = trace_domain.into();
    let quotient_domain = quotient_domain.into();
    if trace_domain.shift() != Val::ONE {
        return Err("owned quotient requires the trace subgroup".into());
    }
    if program.extension != F::DEVICE_EXTENSION
        || public_values.len() != program.layout.num_public_values
        || challenges.len() != program.layout.num_permutation_challenges
        || terminals.len() != program.layout.num_permutation_values
    {
        return Err("owned quotient parameters do not match the AIR layout".into());
    }
    let before = session.stats();
    let prepared = session.prepare_quotient(program.clone())?;
    let mut parameters: Vec<_> = public_values.iter().map(|x| x.as_canonical_u64()).collect();
    parameters.extend(challenges.iter().chain(terminals).flat_map(|x| {
        x.as_basis_coefficients_slice()
            .iter()
            .map(|v: &Val| v.as_canonical_u64())
    }));
    let alpha: &[Val] = alpha.as_basis_coefficients_slice();
    let result = session.quotient_extension_partitioned(
        &prepared,
        trace_domain.log_size() as u32,
        quotient_domain.log_size() as u32,
        quotient_domain.shift().as_canonical_u64(),
        main,
        preprocessed,
        permutation,
        &alpha
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect::<Vec<_>>(),
        &parameters,
    )?;
    let after = session.stats();
    eprintln!("bounded_owned_quotient_adapter rows={} input_matrix_upload_bytes=0 output_readback_bytes=0 program_parameter_and_root_upload_bytes={} control_download_bytes={}",
        quotient_domain.size(), after.uploaded_bytes - before.uploaded_bytes,
        after.downloaded_bytes - before.downloaded_bytes);
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn quotient_values<Mat>(
    program: &Program,
    public_values: &[Val],
    trace_domain: TwoAdicMultiplicativeCoset<Val>,
    quotient_domain: TwoAdicMultiplicativeCoset<Val>,
    main: &Mat,
    permutation: Option<&Mat>,
    terminals: &[Challenge],
    challenges: &[Challenge],
    preprocessed: Option<&Mat>,
    alpha: Challenge,
) -> Result<Vec<Challenge>, String>
where
    Mat: Matrix<Val> + Sync,
{
    if trace_domain.shift() != Val::ONE || trace_domain.log_size() > quotient_domain.log_size() {
        return Err("GPU quotient requires the reference subgroup/disjoint-coset geometry".into());
    }
    let height = quotient_domain.size();
    if main.height() != height
        || main.width() < program.layout.main_width
        || public_values.len() != program.layout.num_public_values
        || challenges.len() != program.layout.num_permutation_challenges
        || terminals.len() != program.layout.num_permutation_values
    {
        return Err("GPU quotient inputs differ from the compiled AIR layout".into());
    }
    let check = |matrix: Option<&Mat>, width: usize| -> Result<(), String> {
        if width == 0 {
            return Ok(());
        }
        if matrix.is_none_or(|m| m.height() != height || m.width() < width) {
            return Err(
                "GPU quotient auxiliary matrix dimensions differ from the compiled layout".into(),
            );
        }
        Ok(())
    };
    check(preprocessed, program.layout.preprocessed_width)?;
    check(permutation, program.layout.permutation_width * 3)?;
    let mut parameters: Vec<_> = public_values.iter().map(|v| v.as_canonical_u64()).collect();
    for value in challenges.iter().chain(terminals) {
        let coefficients: &[Val] = value.as_basis_coefficients_slice();
        parameters.extend(coefficients.iter().map(|v| v.as_canonical_u64()));
    }
    let alpha: &[Val] = alpha.as_basis_coefficients_slice();
    let next_step = height / trace_domain.size();
    crate::block_v2::gpu_hash::evaluate_cubic_quotient(
        program,
        trace_domain.log_size() as u32,
        quotient_domain.log_size() as u32,
        quotient_domain.shift().as_canonical_u64(),
        [
            alpha[0].as_canonical_u64(),
            alpha[1].as_canonical_u64(),
            alpha[2].as_canonical_u64(),
        ],
        &parameters,
        |row, out| {
            let next = (row + next_step) % height;
            let mut offset = 0;
            for (matrix, width) in [
                (Some(main), program.layout.main_width),
                (preprocessed, program.layout.preprocessed_width),
                (permutation, 3 * program.layout.permutation_width),
            ] {
                if width == 0 {
                    continue;
                }
                let matrix = matrix.ok_or("missing quotient matrix")?;
                for at in [row, next] {
                    for column in 0..width {
                        out[offset] = matrix
                            .get(at, column)
                            .ok_or("quotient matrix coordinate out of bounds")?
                            .as_canonical_u64();
                        offset += 1;
                    }
                }
            }
            debug_assert_eq!(offset, out.len());
            Ok(())
        },
    )
}
