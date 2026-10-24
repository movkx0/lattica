//! Exact operation adapters. Descriptors and roots come exclusively from the
//! already registered graph; each adapter emits its real verifier before
//! recording coverage. Input producers may be proved later, but their pending
//! node flags cannot be cleared merely by consuming a root here.
use super::*;
use crate::{
    affine_air::{AffineBatchProof, AffineKind, PendingAffine, RegisteredAffineAir},
    g_bound_air::join::{GBoundArtifact, RegisteredGBoundAir},
    linear_map_air::{LinearMapProof, PendingLinearMap, RegisteredLinearMapAir},
    ntt_air::{NttBatchProof, NttRootRequest, RegisteredNttAir},
    permutation_air::{
        PendingPermutation, PermutationKind, PermutationProof, RegisteredPermutationAir,
    },
    poly_air::{MulBatchProof, MulRootRequest, RegisteredMulAir},
};
mod crypto;

fn component_error(e: crate::crypto_join::Error) -> Error {
    Error(e.to_string())
}

impl SourceBinding<'_, '_, '_> {
    fn pending(&self, index: usize) -> Result<&Operation> {
        let operation = self
            .graph
            .operations
            .get(index)
            .ok_or_else(|| error("operation index"))?;
        if self.operation_bound[index] {
            return Err(error("operation already discharged"));
        }
        Ok(operation)
    }
    fn ordered_pending(&self, indices: &[usize]) -> Result<()> {
        if indices.is_empty() || indices.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(error(
                "operation batch must be nonempty, unique and ordered",
            ));
        }
        for &index in indices {
            self.pending(index)?;
        }
        Ok(())
    }
    fn typed_root(&self, id: PolyId, kind: PolynomialKind) -> Result<[Wire; 4]> {
        if self.graph.polynomial(id).kind != kind {
            return Err(error("operation polynomial kind/bound"));
        }
        Ok(self.polynomial_roots[id.index()])
    }
    fn output_root(&self, operation: usize, id: PolyId, kind: PolynomialKind) -> Result<[Wire; 4]> {
        if self.graph.polynomial(id).source != (Source::Derived { operation }) {
            return Err(error("operation output producer mismatch"));
        }
        self.typed_root(id, kind)
    }
    fn permutation_request(&self, index: usize) -> Result<(PendingPermutation, usize)> {
        self.pending(index)?;
        let (kind, input, output) =
            crate::permutation_air::graph::graph_operation(self.graph, index)
                .map_err(|e| Error(format!("permutation graph descriptor: {e:?}")))?;
        let polynomial_kind = match kind {
            PermutationKind::AutomorphismQ => PolynomialKind::Canonical { modulus: Q },
            PermutationKind::InverseChallenge => PolynomialKind::Signed { bound: 1 },
        };
        Ok((
            PendingPermutation {
                kind,
                input_commitment: self.typed_root(input, polynomial_kind)?,
                output_commitment: self.output_root(index, output, polynomial_kind)?,
            },
            output.index(),
        ))
    }
    pub fn verify_permutation(&mut self, index: usize, artifact: &PermutationProof) -> Result<()> {
        let (request, output) = self.permutation_request(index)?;
        RegisteredPermutationAir::new(request.kind)
            .compile_join(self.builder, self.inputs, &request, artifact)
            .map_err(component_error)?;
        self.operation_bound[index] = true;
        self.polynomial_bound[output] = true;
        Ok(())
    }
    fn linear_map_request(&self, index: usize) -> Result<(PendingLinearMap, usize)> {
        self.pending(index)?;
        let relation = crate::linear_map_air::graph_operation(self.graph, index)
            .map_err(|e| Error(format!("linear map graph descriptor: {e:?}")))?;
        if relation.inputs.len() != relation.descriptor.inputs().len() {
            return Err(error("linear map ordered input kinds"));
        }
        let input_commitments = relation
            .inputs
            .iter()
            .zip(relation.descriptor.inputs())
            .map(|(&input, &kind)| self.typed_root(input, kind))
            .collect::<Result<Vec<_>>>()?;
        let output_commitment =
            self.output_root(index, relation.output, relation.descriptor.output())?;
        Ok((
            PendingLinearMap {
                descriptor: relation.descriptor,
                input_commitments,
                output_commitment,
            },
            relation.output.index(),
        ))
    }
    pub fn verify_linear_map(&mut self, index: usize, artifact: &LinearMapProof) -> Result<()> {
        let (request, output) = self.linear_map_request(index)?;
        RegisteredLinearMapAir::new(request.descriptor.clone())
            .compile_join(self.builder, self.inputs, &request, artifact)
            .map_err(component_error)?;
        self.operation_bound[index] = true;
        self.polynomial_bound[output] = true;
        Ok(())
    }
    fn affine_requests(
        &self,
        indices: &[usize],
    ) -> Result<(AffineKind, u64, Vec<PendingAffine>, Vec<usize>)> {
        self.ordered_pending(indices)?;
        let mut descriptor = None;
        let mut requests = Vec::with_capacity(indices.len());
        let mut outputs = Vec::with_capacity(indices.len());
        for &index in indices {
            let (kind, modulus, left, right, output) = match *self.pending(index)? {
                Operation::Add {
                    modulus,
                    left,
                    right,
                    output,
                } => (AffineKind::Add, modulus, left, Some(right), output),
                Operation::Sub {
                    modulus,
                    left,
                    right,
                    output,
                } => (AffineKind::Sub, modulus, left, Some(right), output),
                Operation::SignedToCanonical {
                    bound,
                    modulus,
                    input,
                    output,
                } => (
                    AffineKind::SignedToCanonical { bound },
                    modulus,
                    input,
                    None,
                    output,
                ),
                _ => return Err(error("operation is not a supported affine predicate")),
            };
            if descriptor
                .replace((kind, modulus))
                .is_some_and(|old| old != (kind, modulus))
            {
                return Err(error("heterogeneous affine batch"));
            }
            let canonical = PolynomialKind::Canonical { modulus };
            let left_kind = match kind {
                AffineKind::SignedToCanonical { bound } => PolynomialKind::Signed { bound },
                AffineKind::Add | AffineKind::Sub => canonical,
            };
            requests.push(PendingAffine {
                kind,
                modulus,
                left_commitment: self.typed_root(left, left_kind)?,
                right_commitment: right.map(|id| self.typed_root(id, canonical)).transpose()?,
                output_commitment: self.output_root(index, output, canonical)?,
            });
            outputs.push(output.index());
        }
        let (kind, modulus) = descriptor.expect("nonempty checked");
        Ok((kind, modulus, requests, outputs))
    }
    pub fn verify_affine_batch(
        &mut self,
        indices: &[usize],
        artifact: &AffineBatchProof,
    ) -> Result<()> {
        let (kind, modulus, requests, outputs) = self.affine_requests(indices)?;
        let key =
            RegisteredAffineAir::new(kind, modulus, indices.len()).map_err(component_error)?;
        key.compile_join(self.builder, self.inputs, &requests, artifact)
            .map_err(component_error)?;
        for &index in indices {
            self.operation_bound[index] = true;
        }
        for index in outputs {
            self.polynomial_bound[index] = true;
        }
        Ok(())
    }
    fn ntt_requests(&self, indices: &[usize]) -> Result<(u64, Vec<NttRootRequest>, Vec<usize>)> {
        self.ordered_pending(indices)?;
        let mut modulus = None;
        let mut requests = Vec::with_capacity(indices.len());
        let mut outputs = Vec::with_capacity(indices.len());
        for &index in indices {
            let Operation::Ntt {
                modulus: q,
                input,
                output,
            } = *self.pending(index)?
            else {
                return Err(error("operation is not NTT"));
            };
            if modulus.replace(q).is_some_and(|old| old != q) {
                return Err(error("heterogeneous NTT batch"));
            }
            let kind = PolynomialKind::Canonical { modulus: q };
            requests.push(NttRootRequest {
                modulus: q,
                input_commitment: self.typed_root(input, kind)?,
                output_commitment: self.output_root(index, output, kind)?,
            });
            outputs.push(output.index());
        }
        Ok((modulus.expect("nonempty checked"), requests, outputs))
    }
    pub fn verify_ntt_batch(&mut self, indices: &[usize], artifact: &NttBatchProof) -> Result<()> {
        let (modulus, requests, outputs) = self.ntt_requests(indices)?;
        let key = RegisteredNttAir::new(modulus, indices.len()).map_err(component_error)?;
        key.compile_root_join(self.builder, self.inputs, &requests, artifact)
            .map_err(component_error)?;
        for &index in indices {
            self.operation_bound[index] = true;
        }
        for index in outputs {
            self.polynomial_bound[index] = true;
        }
        Ok(())
    }
    fn mul_requests(&self, indices: &[usize]) -> Result<(u64, Vec<MulRootRequest>, Vec<usize>)> {
        self.ordered_pending(indices)?;
        let mut modulus = None;
        let mut requests = Vec::with_capacity(indices.len());
        let mut outputs = Vec::with_capacity(indices.len());
        for &index in indices {
            let Operation::Mul {
                modulus: q,
                left,
                right,
                output,
            } = *self.pending(index)?
            else {
                return Err(error("operation is not polynomial product"));
            };
            if modulus.replace(q).is_some_and(|old| old != q) {
                return Err(error("heterogeneous product batch"));
            }
            let kind = PolynomialKind::Canonical { modulus: q };
            requests.push(MulRootRequest {
                modulus: q,
                left_commitment: self.typed_root(left, kind)?,
                right_commitment: self.typed_root(right, kind)?,
                output_commitment: self.output_root(index, output, kind)?,
            });
            outputs.push(output.index());
        }
        Ok((modulus.expect("nonempty checked"), requests, outputs))
    }
    pub fn verify_mul_batch(&mut self, indices: &[usize], artifact: &MulBatchProof) -> Result<()> {
        let (modulus, requests, outputs) = self.mul_requests(indices)?;
        let key = RegisteredMulAir::new(modulus, indices.len()).map_err(component_error)?;
        key.compile_root_join(self.builder, self.inputs, &requests, artifact)
            .map_err(component_error)?;
        for &index in indices {
            self.operation_bound[index] = true;
        }
        for index in outputs {
            self.polynomial_bound[index] = true;
        }
        Ok(())
    }
    pub fn verify_g_bound(&mut self, index: usize, artifact: &GBoundArtifact) -> Result<()> {
        let Operation::GBound { f, x, bound } = *self.pending(index)? else {
            return Err(error("operation is not GBound"));
        };
        let PolynomialKind::Signed { .. } = self.graph.polynomial(f).kind else {
            return Err(error("GBound f must be signed"));
        };
        let f_root = self.polynomial_roots[f.index()];
        let x_root = self.typed_root(x, PolynomialKind::Signed { bound: 1 })?;
        let key = RegisteredGBoundAir::new(bound).map_err(component_error)?;
        key.compile_join(self.builder, self.inputs, &f_root, &x_root, artifact)
            .map_err(component_error)?;
        self.operation_bound[index] = true;
        Ok(())
    }
    /// Equal commitments under the same typed, canonical encoding constrain
    /// equality. Neither operand's source/producer obligation is cleared here.
    pub fn constrain_equality(&mut self, index: usize) -> Result<()> {
        let (left, right) = match *self.pending(index)? {
            Operation::EqualBytes { left, right } => {
                self.graph.byte_string(left);
                self.graph.byte_string(right);
                (
                    self.byte_roots[left.index()],
                    self.byte_roots[right.index()],
                )
            }
            Operation::EqualSigned { left, right } => {
                if !matches!(
                    self.graph.polynomial(left).kind,
                    PolynomialKind::Signed { .. }
                ) || !matches!(
                    self.graph.polynomial(right).kind,
                    PolynomialKind::Signed { .. }
                ) {
                    return Err(error("signed equality requires signed roots"));
                }
                (
                    self.polynomial_roots[left.index()],
                    self.polynomial_roots[right.index()],
                )
            }
            _ => return Err(error("operation is not typed equality")),
        };
        for i in 0..4 {
            self.builder.assert_equal(left[i], right[i]);
        }
        self.operation_bound[index] = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
