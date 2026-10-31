//! Complete HashAlpha/HashX joins over original transcript and sampler borrows.
use super::*;
use lattica_prover_p3::block_v2::{native_transcript_proof::NativeTranscriptProof,
    native_sparse_proof::NativeSparseProof};

impl SourceBinding<'_, '_, '_> {
    fn transcript_roots_owned(&self, air: &TranscriptAir, parts: &[TranscriptPart])
        -> Result<Vec<[Wire; 4]>>
    {
        if parts.len() != air.parts().len() || parts.is_empty() || parts.len() > 256 {
            return Err(error("owned transcript part count"));
        }
        let mut roots = Vec::with_capacity(parts.len());
        for (part, expected) in parts.iter().zip(air.parts()) {
            let (kind, root) = match *part {
                TranscriptPart::Bytes(id) => {
                    self.graph.byte_string(id);
                    (PartKind::Bytes32, self.byte_roots[id.index()])
                }
                TranscriptPart::Polynomial(id) => {
                    let kind = self.graph.polynomial(id).kind;
                    let part_kind = match kind {
                        PolynomialKind::Canonical { modulus: Q } => PartKind::PolynomialQ,
                        PolynomialKind::Canonical { modulus: QHAT } => PartKind::PolynomialQhat,
                        _ => return Err(error("noncanonical transcript input")),
                    };
                    (part_kind, self.typed_root(id, kind)?)
                }
            };
            if kind != *expected { return Err(error("owned transcript ordered part kind")); }
            roots.push(root);
        }
        Ok(roots)
    }

    pub(crate) fn verify_hash_alpha_owned<'a>(&mut self, index: usize, air: &TranscriptAir,
        transcript: &NativeTranscriptProof, shake: impl Into<ShakeRequest<'a>>) -> Result<()>
    {
        let (roots, output) = {
            let Operation::HashAlpha { parts, output } = self.pending(index)? else {
                return Err(error("operation is not HashAlpha"));
            };
            (self.transcript_roots_owned(air, parts)?, *output)
        };
        let output_value = self.graph.byte_string(output).values;
        let output_root = self.bytes_output_root(index, output)?;
        transcript_bridge::owned_transcript::verify_hash_alpha(self.builder, self.inputs,
            air, &roots, transcript, &output_root, &output_value, shake).map_err(component_error)?;
        self.operation_bound[index] = true;
        self.byte_bound[output.index()] = true;
        Ok(())
    }

    pub(crate) fn verify_hash_x_owned<'a>(&mut self, index: usize, air: &TranscriptAir,
        transcript: &NativeTranscriptProof, shake: impl Into<ShakeRequest<'a>>,
        sampler: &NativeSparseProof) -> Result<()>
    {
        let (roots, output) = {
            let Operation::HashX { parts, output } = self.pending(index)? else {
                return Err(error("operation is not HashX"));
            };
            (self.transcript_roots_owned(air, parts)?, *output)
        };
        let output_root = self.output_root(index, output, PolynomialKind::Signed { bound: 1 })?;
        transcript_bridge::owned_transcript::verify_hash_x(self.builder, self.inputs,
            air, &roots, transcript, &output_root, shake, sampler).map_err(component_error)?;
        self.operation_bound[index] = true;
        self.polynomial_bound[output.index()] = true;
        Ok(())
    }
}
