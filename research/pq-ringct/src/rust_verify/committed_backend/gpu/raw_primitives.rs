//! Raw GPU equivalents of the fixed MatRiCT primitive schedules. All host work
//! here is public framing, bounded allocation, and scatter/copy of GPU outputs.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{SparseProfile, UniformProfile};

fn polynomials(words: Vec<u64>, count: usize) -> Result<Vec<RawPoly>, String> {
    if words.len() != count * D {
        return Err("GPU sampler polynomial count".into());
    }
    words
        .chunks_exact(D)
        .map(|words| words.try_into().map_err(|_| "GPU sampler shape".into()))
        .collect()
}

pub(super) fn parameters(
    operation: &OperationContext<'_>,
    seed: &[u8; 32],
    context: &[u8; 32],
) -> Result<primitives::Parameters, String> {
    let mut setup = seed.to_vec();
    setup.extend_from_slice(&[64, 4, 4, 4, 5, 5]);
    setup.extend_from_slice(&256u16.to_le_bytes());
    setup.extend_from_slice(&(Q as u32).to_le_bytes());
    setup.extend_from_slice(&(QHAT as u32).to_le_bytes());
    setup.push(44);
    let mut binding = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".to_vec();
    binding.extend_from_slice(&operation.shake256(&setup, 32)?);
    binding.extend_from_slice(context);
    let pp = operation
        .shake256(&binding, 32)?
        .try_into()
        .map_err(|_| "GPU parameter digest shape")?;

    let bytes = operation.aes256_ctr(seed, 0x4d617431, 0, 7648 * 4)?;
    let words = operation.uniform_coefficients(&bytes, UniformProfile::Q32, 7 * 4 * D)?;
    drop(bytes);
    let mat1 = polynomials(words, 7 * 4)?
        .chunks_exact(4)
        .map(|row| row.to_vec())
        .collect();

    let bytes = operation.aes256_ctr(seed, 0x4d617432, 0, 3366 * 4)?;
    let words =
        operation.uniform_coefficients(&bytes, UniformProfile::Q32, 4 * 2 * D + 4 * 124 * 2)?;
    drop(bytes);
    let mut cursor = words.into_iter();
    let mut mat2 = vec![vec![[0; D]; 3]; 4];
    for row in &mut mat2 {
        for poly in row.iter_mut().take(2) {
            for value in poly {
                *value = cursor.next().ok_or("GPU mat2 coefficient count")?;
            }
        }
    }
    for row in &mut mat2 {
        for k in 4..128 {
            row[2][k] = cursor.next().ok_or("GPU mat2 coefficient count")?;
            row[2][128 + k] = cursor.next().ok_or("GPU mat2 coefficient count")?;
        }
    }
    if cursor.next().is_some() {
        return Err("GPU mat2 trailing coefficients".into());
    }

    let bytes = operation.aes256_ctr(seed, 0x4d617433, 0, 37232 * 5)?;
    let words = operation.uniform_coefficients(&bytes, UniformProfile::Qhat40, 29 * 5 * D)?;
    drop(bytes);
    let mat3 = polynomials(words, 29 * 5)?
        .chunks_exact(5)
        .map(|row| row.to_vec())
        .collect();
    Ok(primitives::Parameters {
        mat1,
        mat2,
        mat3,
        pp,
    })
}

pub(super) fn sample_g(
    operation: &OperationContext<'_>,
    seed: &[u8; 32],
) -> Result<Vec<RawPoly>, String> {
    let bytes = operation.aes256_ctr(seed, 0, 0, 1197 * 4)?;
    let words = operation.uniform_coefficients(&bytes, UniformProfile::Q32, 4 * D)?;
    drop(bytes);
    polynomials(words, 4)
}

pub(super) fn expand_alpha(
    operation: &OperationContext<'_>,
    seed: &[u8; 32],
) -> Result<(Vec<RawPoly>, RawSigned), String> {
    let bytes = operation.aes256_ctr(seed, 0x4368, 0, 643 * 4)?;
    let words = operation.uniform_coefficients(&bytes, UniformProfile::Q32, 2 * D)?;
    drop(bytes);
    let canonical = polynomials(words, 2)?;
    // The native stream discards unused bytes in the last block of each call.
    let bytes = operation.aes256_ctr(seed, 0x4368, 161, 127)?;
    let signed = operation.sparse_polynomial(&bytes, SparseProfile::AlphaPrime39)?;
    Ok((canonical, signed))
}
