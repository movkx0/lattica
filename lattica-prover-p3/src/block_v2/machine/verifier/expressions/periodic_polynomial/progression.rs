//! Exact equal-weight indicators for disjoint arithmetic progressions of rows.
//!
//! A progression of row indices gives geometric roots. Gaussian-binomial
//! coefficients construct its root polynomial in linear public arithmetic.
//! The rational identity is evaluated with an explicit zero branch, including
//! every subgroup root; inverse witnesses are never asked to invert zero.
use super::*;
use crate::block_v2::machine::program::{EXT_LANES, LANES};

const MAX_PARTS: usize = 8;
const MAX_DEGREE: usize = 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Progression {
    first: usize,
    step: usize,
    count: usize,
}

#[derive(Clone, Copy, Debug)]
struct Plan {
    parts: [Progression; MAX_PARTS],
    len: usize,
    deviation: Val,
}

fn order(n: usize, step: usize) -> usize {
    n >> step.trailing_zeros().min(n.ilog2())
}

/// No claimed support is accepted: inspect every column value and every gap.
/// Failure to recognize a shape only retains the previous exact evaluator.
fn plan(column: &[Val], baseline: Val, deviations: usize) -> Option<Plan> {
    let n = column.len();
    if !n.is_power_of_two() || n < 2 || deviations < 2 {
        return None;
    }
    let mut first = [0usize; MAX_PARTS + 1];
    let mut first_len = 0;
    let mut deviation = None;
    let mut actual = 0;
    for (index, &sample) in column.iter().enumerate() {
        if sample == baseline {
            continue;
        }
        let delta = sample - baseline;
        if deviation.is_some_and(|value| value != delta) {
            return None;
        }
        deviation = Some(delta);
        actual += 1;
        if first_len < first.len() {
            first[first_len] = index;
            first_len += 1;
        }
    }
    if actual != deviations {
        return None;
    }
    let mut best: Option<Plan> = None;
    for &next in &first[1..first_len] {
        let step = next - first[0];
        let mut candidate = Plan {
            parts: [Progression::default(); MAX_PARTS],
            len: 0,
            deviation: deviation?,
        };
        let mut valid = true;
        for (index, &sample) in column.iter().enumerate() {
            if sample == baseline {
                continue;
            }
            if let Some(part) = candidate.parts[..candidate.len]
                .iter_mut()
                .find(|part| part.first % step == index % step)
            {
                if part
                    .count
                    .checked_mul(step)
                    .and_then(|v| part.first.checked_add(v))
                    != Some(index)
                {
                    valid = false;
                    break;
                }
                part.count += 1;
            } else if candidate.len < MAX_PARTS {
                candidate.parts[candidate.len] = Progression {
                    first: index,
                    step,
                    count: 1,
                };
                candidate.len += 1;
            } else {
                valid = false;
                break;
            }
        }
        if !valid
            || candidate.parts[..candidate.len]
                .iter()
                .any(|part| part.count > MAX_DEGREE || part.count >= order(n, step))
        {
            continue;
        }
        // Cubic/base steps have relative row weights LANES/EXT_LANES.
        // Include generous zero-test/inversion overhead for every part. This
        // gate is only an optimization choice, never a validity assumption.
        let proposed = (2 * deviations).saturating_mul(LANES + EXT_LANES)
            + candidate.len * (400 * EXT_LANES + 5 * LANES)
            + (n.ilog2() as usize + 1) * LANES;
        let dense = (n - 1).saturating_mul(LANES + EXT_LANES);
        if proposed < dense && best.is_none_or(|old| candidate.len < old.len) {
            best = Some(candidate);
        }
    }
    best
}

/// Descending coefficients of product_t (x - a*r^t), and its derivative.
/// The second buffer first holds a batch-inversion prefix product, then the
/// derivative coefficients. The strict order check excludes q-binomial 0/0.
fn coefficients(
    n: usize,
    part: Progression,
    coefficients: &mut [Val],
    derivative: &mut [Val],
) -> Result<(), CompileError> {
    let k = part.count;
    if !n.is_power_of_two()
        || part.step == 0
        || k == 0
        || k > MAX_DEGREE
        || k >= order(n, part.step)
        || part.first >= n
        || part
            .step
            .checked_mul(k - 1)
            .and_then(|v| part.first.checked_add(v))
            .is_none_or(|last| last >= n)
        || coefficients.len() != k + 1
        || derivative.len() != k + 1
    {
        return Err(CompileError::Shape("periodic progression coefficients"));
    }
    let generator = Val::two_adic_generator(n.ilog2() as usize);
    let a = generator.exp_u64(part.first as u64);
    let ratio = generator.exp_u64(part.step as u64);
    let inverse_ratio = ratio.inverse();
    derivative[0] = Val::ONE;
    let mut power = Val::ONE;
    for j in 1..=k {
        power *= ratio;
        derivative[j] = derivative[j - 1] * (Val::ONE - power);
    }
    let last_power = power;
    let mut inverse = derivative[k]
        .try_inverse()
        .ok_or(CompileError::Shape("periodic progression root order"))?;
    for j in (1..=k).rev() {
        coefficients[j] = inverse * derivative[j - 1];
        inverse *= Val::ONE - power;
        power *= inverse_ratio;
    }
    coefficients[0] = Val::ONE;
    let mut lower_power = last_power;
    let mut upper_power = Val::ONE;
    for j in 0..k {
        coefficients[j + 1] =
            coefficients[j] * (-a) * upper_power * (Val::ONE - lower_power) * coefficients[j + 1];
        upper_power *= ratio;
        lower_power *= inverse_ratio;
    }
    for j in 0..k {
        derivative[j] = coefficients[j] * Val::from_usize(k - j);
    }
    derivative[k] = Val::ZERO;
    Ok(())
}

fn horner(b: &mut ProgramBuilder, coefficients: &[Val], point: Extension) -> Extension {
    let mut result = b.ext_constant([Val::ZERO; 3]);
    for &coefficient in coefficients {
        result = b.ext_mul(result, point);
        let constant = b.ext_constant([coefficient, Val::ZERO, Val::ZERO]);
        result = b.ext_add(result, constant);
    }
    result
}

/// Goldilocks Fermat zero test, using only already-constrained base operations.
/// x^(p-1)=(x^(2^32-1))^(2^32); zero maps to0 and nonzero maps to1.
fn base_zero(b: &mut ProgramBuilder, value: Wire) -> Wire {
    let mut power = value;
    for _ in 1..32 {
        power = b.mul(power, power);
        power = b.mul(power, value);
    }
    for _ in 0..32 {
        power = b.mul(power, power);
    }
    let one = b.constant(Val::ONE);
    b.sub(one, power)
}

fn extension_zero(b: &mut ProgramBuilder, value: Extension) -> Wire {
    let mut zero = b.constant(Val::ONE);
    for coefficient in value {
        let coefficient_zero = base_zero(b, coefficient);
        zero = b.mul(zero, coefficient_zero);
    }
    b.assert_bool(zero);
    zero
}

pub(super) fn value(
    b: &mut ProgramBuilder,
    column: &[Val],
    baseline: Val,
    deviations: usize,
    zeta: Extension,
    log_height: usize,
    run: Option<&Run>,
) -> Result<Option<Extension>, CompileError> {
    let Some(plan) = Constants::cpu_work(run, || plan(column, baseline, deviations))? else {
        return Ok(None);
    };
    let n = column.len();
    let point = b.ext_pow(zeta, (1u64 << log_height) / n as u64);
    let one = b.ext_constant([Val::ONE, Val::ZERO, Val::ZERO]);
    let point_n = b.ext_pow(point, n as u64);
    let vanishing = b.ext_sub(point_n, one);
    let inverse_n = Constants::cpu_work(run, || Val::from_usize(n).inverse())?;
    let inverse_n = b.constant(inverse_n);
    let vanishing = b.ext_scale(vanishing, inverse_n);
    let mut sum = b.ext_constant([Val::ZERO; 3]);
    for &part in &plan.parts[..plan.len] {
        let indicator = b.with_compiler_scratch(
            "periodic-progression-coefficients",
            2 * (part.count + 1),
            Val::ZERO,
            |b, scratch| {
                let (polynomial, derivative) = scratch.split_at_mut(part.count + 1);
                Constants::cpu_work(run, || coefficients(n, part, polynomial, derivative))??;
                let p = horner(b, polynomial, point);
                let derivative = horner(b, &derivative[..part.count], point);
                let zero = extension_zero(b, p);
                let mut denominator = p;
                denominator[0] = b.add(denominator[0], zero);
                // If P=0 the denominator is1; otherwise it remains P!=0.
                let inverse = b.ext_inverse(denominator);
                let xp = b.ext_mul(point, derivative);
                let count = b.constant(Val::from_usize(part.count));
                let kp = b.ext_scale(p, count);
                let numerator = b.ext_sub(xp, kp);
                let rational = b.ext_mul(vanishing, numerator);
                let rational = b.ext_mul(rational, inverse);
                // select(bit,a,b) returns a+bit*(b-a).
                Ok(b.ext_select(zero, rational, one))
            },
        )?;
        sum = b.ext_add(sum, indicator);
        if let Some(error) = b.resource_failure() {
            return Err(CompileError::from_builder_admission(error, "periodic progression allowance"));
        }
    }
    let deviation = b.constant(plan.deviation);
    let sum = b.ext_scale(sum, deviation);
    let baseline = b.ext_constant([baseline, Val::ZERO, Val::ZERO]);
    Ok(Some(b.ext_add(baseline, sum)))
}

#[cfg(test)]
mod tests;
