//! Exact shape recognition only; never evidence that a graph edge is proved.
use super::*;
use crate::rust_verify::committed_backend::{
    Expression, Operation, PolyId, PolynomialKind, UnprovedRelationGraph,
};

pub fn graph_operation(
    graph: &UnprovedRelationGraph,
    position: usize,
) -> Result<(PermutationKind, PolyId, PolyId), Error> {
    let operation = graph.operations().get(position).ok_or(Error::Descriptor)?;
    match operation {
        Operation::AutomorphismQ { input, output } => {
            if graph.polynomial(*input).kind != (PolynomialKind::Canonical { modulus: Q })
                || graph.polynomial(*output).kind != (PolynomialKind::Canonical { modulus: Q })
            {
                return Err(Error::Descriptor);
            }
            Ok((PermutationKind::AutomorphismQ, *input, *output))
        }
        Operation::SignedMap {
            bound: 1,
            inputs,
            expressions,
            output,
        } if inputs.len() == 1 => {
            let input = inputs[0];
            if graph.polynomial(input).kind != (PolynomialKind::Signed { bound: 1 })
                || graph.polynomial(*output).kind != (PolynomialKind::Signed { bound: 1 })
            {
                return Err(Error::Descriptor);
            }
            for (index, &expression) in expressions.iter().enumerate() {
                let mut expression = graph
                    .expressions()
                    .get(expression)
                    .ok_or(Error::Descriptor)?;
                if (86..171).contains(&index) {
                    let Expression::SignedNeg { input, bound: 1 } = expression else {
                        return Err(Error::Descriptor);
                    };
                    expression = graph.expressions().get(*input).ok_or(Error::Descriptor)?;
                }
                if !matches!(expression, Expression::SignedInput { polynomial, index: source }
                    if *polynomial == input && *source == 3 * index % D)
                {
                    return Err(Error::Descriptor);
                }
            }
            Ok((PermutationKind::InverseChallenge, input, *output))
        }
        _ => Err(Error::Descriptor),
    }
}
