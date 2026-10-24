//! Complete producer adapters. A sampler, hash receipt, or transcript commitment
//! alone cannot discharge any of these composite graph operations.
use super::*;
use crate::{
    obligation_manifest::ContextWires,
    producer_branch::{Artifact as BranchArtifact, Role as BranchRole},
    request_bridge::{AesRequest, ShakeRequest},
    sampler_bridge,
    sparse_air::join::SparseArtifact,
    transcript_air::{join::TranscriptArtifact, PartKind, TranscriptAir},
    transcript_bridge,
    uniform_air::join::UniformArtifact,
};

impl SourceBinding<'_, '_, '_> {
    fn bytes_output_root(&self, operation: usize, id: BytesId) -> Result<[Wire; 4]> {
        if self.graph.byte_string(id).source != (Source::Derived { operation }) {
            return Err(error("byte operation output producer mismatch"));
        }
        Ok(self.byte_roots[id.index()])
    }
    fn transcript_request(
        &self,
        parts: &[TranscriptPart],
    ) -> Result<(TranscriptAir, Vec<[Wire; 4]>)> {
        let mut kinds = Vec::with_capacity(parts.len());
        let mut roots = Vec::with_capacity(parts.len());
        for part in parts {
            match *part {
                TranscriptPart::Bytes(id) => {
                    self.graph.byte_string(id);
                    kinds.push(PartKind::Bytes32);
                    roots.push(self.byte_roots[id.index()]);
                }
                TranscriptPart::Polynomial(id) => {
                    let kind = self.graph.polynomial(id).kind;
                    kinds.push(match kind {
                        PolynomialKind::Canonical { modulus: Q } => PartKind::PolynomialQ,
                        PolynomialKind::Canonical { modulus: QHAT } => PartKind::PolynomialQhat,
                        _ => return Err(error("noncanonical transcript input")),
                    });
                    roots.push(self.typed_root(id, kind)?);
                }
            }
        }
        Ok((TranscriptAir::new(kinds).map_err(error)?, roots))
    }
    pub fn verify_sample_g<'a>(
        &mut self,
        index: usize,
        aes: impl Into<AesRequest<'a>>,
        sampler: &UniformArtifact,
    ) -> Result<()> {
        let Operation::SampleG { seed, output } = *self.pending(index)? else {
            return Err(error("operation is not SampleG"));
        };
        let seed_value = self.graph.byte_string(seed).values;
        let mut roots = Vec::with_capacity(4);
        for id in output {
            roots.push(self.output_root(index, id, PolynomialKind::Canonical { modulus: Q })?);
        }
        let roots = roots
            .try_into()
            .map_err(|_| error("SampleG output width"))?;
        sampler_bridge::verify_sample_g(
            self.builder,
            self.inputs,
            &self.byte_roots[seed.index()],
            &seed_value,
            &roots,
            aes,
            sampler,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        for id in output {
            self.polynomial_bound[id.index()] = true;
        }
        Ok(())
    }
    pub fn verify_expand_alpha<'a>(
        &mut self,
        index: usize,
        uniform_aes: impl Into<AesRequest<'a>>,
        uniform: &UniformArtifact,
        sparse_aes: impl Into<AesRequest<'a>>,
        sparse: &SparseArtifact,
    ) -> Result<()> {
        let Operation::ExpandAlpha {
            seed,
            canonical,
            signed,
        } = *self.pending(index)?
        else {
            return Err(error("operation is not ExpandAlpha"));
        };
        let seed_value = self.graph.byte_string(seed).values;
        let roots = [
            self.output_root(
                index,
                canonical[0],
                PolynomialKind::Canonical { modulus: Q },
            )?,
            self.output_root(
                index,
                canonical[1],
                PolynomialKind::Canonical { modulus: Q },
            )?,
        ];
        let signed_root = self.output_root(index, signed, PolynomialKind::Signed { bound: 1 })?;
        sampler_bridge::verify_expand_alpha(
            self.builder,
            self.inputs,
            &self.byte_roots[seed.index()],
            &seed_value,
            &roots,
            &signed_root,
            uniform_aes,
            uniform,
            sparse_aes,
            sparse,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        for id in canonical {
            self.polynomial_bound[id.index()] = true;
        }
        self.polynomial_bound[signed.index()] = true;
        Ok(())
    }
    /// Both branches authenticate complete producers. Coverage remains atomic:
    /// seed openings and all three graph outputs are joined before discharge.
    pub fn verify_expand_alpha_branches(
        &mut self,
        index: usize,
        context: &ContextWires,
        node_manifest: &[Wire; 4],
        uniform: BranchArtifact<'_>,
        sparse: BranchArtifact<'_>,
    ) -> Result<()> {
        let Operation::ExpandAlpha {
            seed,
            canonical,
            signed,
        } = *self.pending(index)?
        else {
            return Err(error("operation is not ExpandAlpha"));
        };
        let seed_value = self.graph.byte_string(seed).values;
        let roots = [
            self.output_root(
                index,
                canonical[0],
                PolynomialKind::Canonical { modulus: Q },
            )?,
            self.output_root(
                index,
                canonical[1],
                PolynomialKind::Canonical { modulus: Q },
            )?,
        ];
        let signed_root = self.output_root(index, signed, PolynomialKind::Signed { bound: 1 })?;
        let uniform_roots = uniform
            .compile_roots(
                self.builder,
                self.inputs,
                index,
                BranchRole::AlphaUniform,
                None,
                context,
                node_manifest,
            )
            .map_err(|e| Error(e.to_string()))?;
        let sparse_roots = sparse
            .compile_roots(
                self.builder,
                self.inputs,
                index,
                BranchRole::AlphaSparse,
                None,
                context,
                node_manifest,
            )
            .map_err(|e| Error(e.to_string()))?;
        let expected_inputs = sampler_bridge::bind_key_request_pair(
            self.builder,
            self.inputs,
            &self.byte_roots[seed.index()],
            &seed_value,
            [
                crate::aes_air::Descriptor {
                    domain: 0x4368,
                    start_counter: 0,
                    output_len: 2572,
                },
                crate::aes_air::Descriptor {
                    domain: 0x4368,
                    start_counter: 161,
                    output_len: 127,
                },
            ],
        )
        .map_err(component_error)?;
        for (branch_roots, expected) in [uniform_roots, sparse_roots]
            .into_iter()
            .zip(expected_inputs)
        {
            for i in 0..4 {
                self.builder.assert_equal(branch_roots[0][i], expected[i]);
            }
        }
        let uniform_bundle = crate::uniform_air::join::bundle_wires(
            self.builder,
            crate::uniform_air::Kind::ExpandAlpha2,
            &roots,
        )
        .map_err(|e| Error(format!("{e:?}")))?;
        for i in 0..4 {
            self.builder
                .assert_equal(uniform_roots[1][i], uniform_bundle[i]);
            self.builder
                .assert_equal(sparse_roots[1][i], signed_root[i]);
        }
        self.operation_bound[index] = true;
        for id in canonical {
            self.polynomial_bound[id.index()] = true;
        }
        self.polynomial_bound[signed.index()] = true;
        Ok(())
    }
    /// The typed branch proves serialization and the complete SHAKE request;
    /// this leaf retains the native sparse sampler and exact graph joins.
    pub fn verify_hash_x_branch(
        &mut self,
        index: usize,
        context: &ContextWires,
        node_manifest: &[Wire; 4],
        branch: BranchArtifact<'_>,
        sampler: &SparseArtifact,
    ) -> Result<()> {
        let Operation::HashX { parts, output } = self.pending(index)?.clone() else {
            return Err(error("operation is not HashX"));
        };
        let (air, roots) = self.transcript_request(&parts)?;
        let output_root = self.output_root(index, output, PolynomialKind::Signed { bound: 1 })?;
        let branch_roots = branch
            .compile_roots(
                self.builder,
                self.inputs,
                index,
                BranchRole::HashXTranscriptShake,
                Some(&air),
                context,
                node_manifest,
            )
            .map_err(|e| Error(e.to_string()))?;
        let source_bundle = crate::transcript_air::join::bundle_wires(self.builder, &air, &roots)
            .map_err(|e| Error(format!("{e:?}")))?;
        for i in 0..4 {
            self.builder
                .assert_equal(branch_roots[0][i], source_bundle[i]);
        }
        crate::sparse_air::join::verify_sampler(
            self.builder,
            self.inputs,
            crate::sparse_air::Kind::ChallengeX44,
            &branch_roots[1],
            &output_root,
            sampler,
        )
        .map_err(|e| Error(format!("{e:?}")))?;
        self.operation_bound[index] = true;
        self.polynomial_bound[output.index()] = true;
        Ok(())
    }
    pub fn verify_parameters_pp<'a>(
        &mut self,
        index: usize,
        shake: impl Into<ShakeRequest<'a>>,
    ) -> Result<()> {
        let Operation::ParametersPp {
            setup_seed,
            context,
            output,
        } = *self.pending(index)?
        else {
            return Err(error("operation is not ParametersPp"));
        };
        if setup_seed != self.graph.setup_seed || context.index() != self.plan.context {
            return Err(error(
                "parameter setup/context is not the registered source",
            ));
        }
        let context_value = self.graph.byte_string(context).values;
        let output_value = self.graph.byte_string(output).values;
        let output_root = self.bytes_output_root(index, output)?;
        transcript_bridge::verify_parameters_pp(
            self.builder,
            self.inputs,
            &setup_seed,
            &self.byte_roots[context.index()],
            &context_value,
            &output_root,
            &output_value,
            shake,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        self.byte_bound[output.index()] = true;
        Ok(())
    }
    pub fn verify_hash_alpha<'a>(
        &mut self,
        index: usize,
        transcript: &TranscriptArtifact,
        shake: impl Into<ShakeRequest<'a>>,
    ) -> Result<()> {
        let Operation::HashAlpha { parts, output } = self.pending(index)?.clone() else {
            return Err(error("operation is not HashAlpha"));
        };
        let (air, roots) = self.transcript_request(&parts)?;
        let output_value = self.graph.byte_string(output).values;
        let output_root = self.bytes_output_root(index, output)?;
        transcript_bridge::verify_hash_alpha(
            self.builder,
            self.inputs,
            &air,
            &roots,
            transcript,
            &output_root,
            &output_value,
            shake,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        self.byte_bound[output.index()] = true;
        Ok(())
    }
    pub fn verify_hash_x<'a>(
        &mut self,
        index: usize,
        transcript: &TranscriptArtifact,
        shake: impl Into<ShakeRequest<'a>>,
        sampler: &SparseArtifact,
    ) -> Result<()> {
        let Operation::HashX { parts, output } = self.pending(index)?.clone() else {
            return Err(error("operation is not HashX"));
        };
        let (air, roots) = self.transcript_request(&parts)?;
        let output_root = self.output_root(index, output, PolynomialKind::Signed { bound: 1 })?;
        transcript_bridge::verify_hash_x(
            self.builder,
            self.inputs,
            &air,
            &roots,
            transcript,
            &output_root,
            shake,
            sampler,
        )
        .map_err(component_error)?;
        self.operation_bound[index] = true;
        self.polynomial_bound[output.index()] = true;
        Ok(())
    }
}
