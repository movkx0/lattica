//! Exact public periodic evaluation: division-free sparse products and a
//! guarded-inverse fallback for equal-weight arithmetic-progression supports.
use super::*;
use crate::proving::Run;
use p3_field::{Field, TwoAdicField};

mod progression;

/// Repetition on a power-of-two subgroup is composition with x^(n / period).
/// The halves examined here total less than twice the original column length.
pub(super) fn minimal_period(mut column: &[Val]) -> &[Val] {
    while column.len() > 1 {
        let half = column.len() / 2;
        if column[..half] != column[half..] {
            break;
        }
        column = &column[..half];
    }
    column
}

/// Return None before emitting operations if dense interpolation is preferable.
/// No metadata is trusted: sparsity is checked against every public column row.
pub(super) fn sparse_value(
    b: &mut ProgramBuilder,
    column: &[Val],
    zeta: Extension,
    log_height: usize,
    run: Option<&Run>,
) -> Result<Option<Extension>, CompileError> {
    let n = column.len();
    if n == 1 {
        return Ok(Some(b.ext_constant([column[0], Val::ZERO, Val::ZERO])));
    }
    let log_n = n.ilog2() as usize;
    let mut nonzero = 0usize;
    let mut different = 0usize;
    for &value in column {
        nonzero += usize::from(value != Val::ZERO);
        different += usize::from(value != column[0]);
    }
    let (baseline, deviations) = if different < nonzero {
        (column[0], different)
    } else {
        (Val::ZERO, nonzero)
    };
    // Retain geometric products for cheap sparse columns. Otherwise try a
    // checked progression evaluator before falling back to dense Horner form.
    if deviations.saturating_mul(4 * log_n + 8) >= n {
        return progression::value(b, column, baseline, deviations, zeta, log_height, run);
    }
    let (inverse_generator, inverse_n) = Constants::cpu_work(run, || {
        (
            Val::two_adic_generator(log_n).inverse(),
            Val::from_usize(n).inverse(),
        )
    })?;
    let point = b.ext_pow(zeta, (1u64 << log_height) / n as u64);
    let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let mut value = b.ext_constant([baseline, Val::ZERO, Val::ZERO]);
    for (index, &sample) in column.iter().enumerate() {
        if sample == baseline {
            continue;
        }
        let (inverse_root, weight) = Constants::cpu_work(run, || {
            (
                inverse_generator.exp_u64(index as u64),
                (sample - baseline) * inverse_n,
            )
        })?;
        let inverse_root = b.constant(inverse_root);
        let mut power = b.ext_scale(point, inverse_root);
        let mut sum = one;
        // For n=2^m, sum_{k=0}^{n-1} y^k = product_j (1+y^(2^j)).
        // This evaluates the Lagrange basis everywhere, including subgroup
        // points, without an inverse witness or a removable singularity.
        for bit in 0..log_n {
            let factor = b.ext_add(one, power);
            sum = b.ext_mul(sum, factor);
            if bit + 1 < log_n {
                power = b.ext_mul(power, power);
            }
        }
        let weight = b.constant(weight);
        let term = b.ext_scale(sum, weight);
        value = b.ext_add(value, term);
        if let Some(error) = b.resource_failure() {
            return Err(CompileError::from_builder_admission(error, "periodic compiler allowance"));
        }
    }
    Ok(Some(value))
}
