use super::*;
use crate::rust_verify::committed_backend::{Expression, Operation, PolyId, UnprovedRelationGraph};
use std::collections::{BTreeMap, BTreeSet};
const FIELD_MODULUS: u128 = 0xffff_ffff_0000_0001;

/// Immutable, witness-independent relation metadata. Owner identities and
/// native coefficient values are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearMapDescriptor {
    pub(super) inputs: Vec<PolynomialKind>,
    pub(super) output: PolynomialKind,
    pub(super) coefficients: Vec<[i64; D]>,
    pub(super) constant: [i64; D],
    pub(super) quotient_bound: u64,
    pub(super) bits: usize,
    pub(super) bounds: Vec<u32>,
}
fn centered(value: i128, modulus: u64) -> i64 {
    let residue = value.rem_euclid(i128::from(modulus));
    if residue > i128::from(modulus / 2) {
        (residue - i128::from(modulus)) as i64
    } else {
        residue as i64
    }
}
impl LinearMapDescriptor {
    pub fn new(
        inputs: Vec<PolynomialKind>,
        output: PolynomialKind,
        mut coefficients: Vec<[i64; D]>,
        mut constant: [i64; D],
    ) -> Result<Self, Error> {
        if inputs.is_empty() || inputs.len() > 16 || coefficients.len() != inputs.len() {
            return Err(Error::Descriptor);
        }
        let (bits, bounds, quotient_bound) = match output {
            PolynomialKind::Canonical { modulus } => {
                if !matches!(modulus, Q | QHAT) || inputs.iter().any(|kind| *kind != output) {
                    return Err(Error::Descriptor);
                }
                for coefficient in coefficients.iter_mut().flatten() {
                    *coefficient = centered(i128::from(*coefficient), modulus);
                }
                for value in &mut constant {
                    *value = centered(i128::from(*value), modulus);
                }
                let mut maximum = 0u128;
                for index in 0..D {
                    let sum = coefficients.iter().fold(
                        u128::from(constant[index].unsigned_abs()),
                        |sum, row| {
                            sum + u128::from(row[index].unsigned_abs()) * u128::from(modulus - 1)
                        },
                    );
                    maximum = maximum.max(sum);
                }
                if 2 * maximum + 2 * u128::from(modulus) >= FIELD_MODULUS {
                    return Err(Error::IntegerBound);
                }
                let bound = maximum.div_ceil(u128::from(modulus)) + 1;
                if bound > i32::MAX as u128 {
                    return Err(Error::IntegerBound);
                }
                if maximum + u128::from(modulus - 1) + bound * u128::from(modulus) >= FIELD_MODULUS
                {
                    return Err(Error::IntegerBound);
                }
                (if modulus == Q { 28 } else { 32 }, vec![], bound as u64)
            }
            PolynomialKind::Signed { bound } => {
                if bound == 0 || bound > i32::MAX as u32 {
                    return Err(Error::Descriptor);
                }
                let mut bounds = BTreeSet::from([0, bound]);
                for kind in &inputs {
                    let PolynomialKind::Signed { bound } = kind else {
                        return Err(Error::Descriptor);
                    };
                    if *bound == 0 || *bound > i32::MAX as u32 {
                        return Err(Error::Descriptor);
                    }
                    bounds.insert(*bound);
                }
                for index in 0..D {
                    let mut maximum =
                        u128::from(constant[index].unsigned_abs()) + u128::from(bound);
                    for (coefficient, kind) in coefficients.iter().zip(&inputs) {
                        let PolynomialKind::Signed { bound } = kind else {
                            unreachable!()
                        };
                        maximum = maximum
                            .checked_add(
                                u128::from(coefficient[index].unsigned_abs()) * u128::from(*bound),
                            )
                            .ok_or(Error::IntegerBound)?;
                    }
                    if maximum >= FIELD_MODULUS {
                        return Err(Error::IntegerBound);
                    }
                }
                let maximum = u64::from(*bounds.last().unwrap()) * 2 + 1;
                let bits = (64 - maximum.leading_zeros() as usize).div_ceil(4) * 4;
                (bits, bounds.into_iter().collect(), 0)
            }
        };
        Ok(Self {
            inputs,
            output,
            coefficients,
            constant,
            quotient_bound,
            bits,
            bounds,
        })
    }
    pub fn inputs(&self) -> &[PolynomialKind] {
        &self.inputs
    }
    pub fn output(&self) -> PolynomialKind {
        self.output
    }
}

pub struct GraphLinearMap {
    pub descriptor: LinearMapDescriptor,
    pub inputs: Vec<PolyId>,
    pub output: PolyId,
}
#[derive(Clone)]
struct Form {
    terms: BTreeMap<PolyId, i128>,
    constant: i128,
    bound: Option<u32>,
}
impl Form {
    fn normalize(&mut self, modulus: Option<u64>) {
        if let Some(modulus) = modulus {
            self.constant = i128::from(centered(self.constant, modulus));
            for value in self.terms.values_mut() {
                *value = i128::from(centered(*value, modulus));
            }
        }
    }
}
fn expression(
    graph: &UnprovedRelationGraph,
    id: usize,
    index: usize,
    modulus: Option<u64>,
) -> Result<Form, Error> {
    let node = graph.expressions().get(id).ok_or(Error::Descriptor)?;
    let mut form = match node {
        Expression::CanonicalInput {
            polynomial,
            index: source,
        } if modulus.is_some() && *source == index => {
            if graph.polynomial(*polynomial).kind
                != (PolynomialKind::Canonical {
                    modulus: modulus.unwrap(),
                })
            {
                return Err(Error::Descriptor);
            }
            Form {
                terms: BTreeMap::from([(*polynomial, 1)]),
                constant: 0,
                bound: None,
            }
        }
        Expression::SignedInput {
            polynomial,
            index: source,
        } if modulus.is_none() && *source == index => {
            let PolynomialKind::Signed { bound } = graph.polynomial(*polynomial).kind else {
                return Err(Error::Descriptor);
            };
            Form {
                terms: BTreeMap::from([(*polynomial, 1)]),
                constant: 0,
                bound: Some(bound),
            }
        }
        Expression::CanonicalConstant { modulus: q, value } if modulus == Some(*q) => Form {
            terms: BTreeMap::new(),
            constant: i128::from(*value),
            bound: None,
        },
        Expression::Add {
            left,
            right,
            modulus: q,
        }
        | Expression::Sub {
            left,
            right,
            modulus: q,
        } if modulus == Some(*q) => {
            let mut left = expression(graph, *left, index, modulus)?;
            let right = expression(graph, *right, index, modulus)?;
            let sign = if matches!(node, Expression::Add { .. }) {
                1
            } else {
                -1
            };
            for (id, value) in right.terms {
                *left.terms.entry(id).or_default() += sign * value;
            }
            left.constant += sign * right.constant;
            left
        }
        Expression::Scale {
            input,
            factor,
            modulus: q,
        } if modulus == Some(*q) => {
            let mut form = expression(graph, *input, index, modulus)?;
            for value in form.terms.values_mut() {
                *value *= i128::from(*factor);
            }
            form.constant *= i128::from(*factor);
            form
        }
        Expression::SignedNeg { input, bound } if modulus.is_none() => {
            let mut form = expression(graph, *input, index, modulus)?;
            if form.bound != Some(*bound) {
                return Err(Error::Descriptor);
            }
            for value in form.terms.values_mut() {
                *value = -*value;
            }
            form.constant = -form.constant;
            form
        }
        Expression::SignedSub { left, right, bound } if modulus.is_none() => {
            let mut left = expression(graph, *left, index, modulus)?;
            let right = expression(graph, *right, index, modulus)?;
            if left.bound.unwrap().checked_add(right.bound.unwrap()) != Some(*bound) {
                return Err(Error::Descriptor);
            }
            for (id, value) in right.terms {
                *left.terms.entry(id).or_default() -= value;
            }
            left.constant -= right.constant;
            left.bound = Some(*bound);
            left
        }
        _ => return Err(Error::Descriptor),
    };
    form.normalize(modulus);
    Ok(form)
}

/// Recognize exact coefficientwise linear semantics. Permutations and other
/// unsupported expressions fail closed and need their own registered AIR.
pub fn graph_operation(
    graph: &UnprovedRelationGraph,
    position: usize,
) -> Result<GraphLinearMap, Error> {
    let (kind, inputs, expressions, output, modulus) =
        match graph.operations().get(position).ok_or(Error::Descriptor)? {
            Operation::CanonicalMap {
                modulus,
                inputs,
                expressions,
                output,
            } => (
                PolynomialKind::Canonical { modulus: *modulus },
                inputs,
                expressions,
                *output,
                Some(*modulus),
            ),
            Operation::SignedMap {
                bound,
                inputs,
                expressions,
                output,
            } => (
                PolynomialKind::Signed { bound: *bound },
                inputs,
                expressions,
                *output,
                None,
            ),
            _ => return Err(Error::Descriptor),
        };
    if graph.polynomial(output).kind != kind {
        return Err(Error::Descriptor);
    }
    let mut coefficients = vec![[0; D]; inputs.len()];
    let mut constant = [0; D];
    for (index, &id) in expressions.iter().enumerate() {
        let form = expression(graph, id, index, modulus)?;
        if let PolynomialKind::Signed { bound } = kind {
            if form.bound.is_none_or(|actual| actual > bound) {
                return Err(Error::Descriptor);
            }
        }
        constant[index] = form.constant.try_into().map_err(|_| Error::IntegerBound)?;
        for (input, value) in form.terms {
            let position = inputs
                .iter()
                .position(|id| *id == input)
                .ok_or(Error::Descriptor)?;
            coefficients[position][index] = value.try_into().map_err(|_| Error::IntegerBound)?;
        }
    }
    let descriptor = LinearMapDescriptor::new(
        inputs.iter().map(|id| graph.polynomial(*id).kind).collect(),
        kind,
        coefficients,
        constant,
    )?;
    Ok(GraphLinearMap {
        descriptor,
        inputs: inputs.clone(),
        output,
    })
}
