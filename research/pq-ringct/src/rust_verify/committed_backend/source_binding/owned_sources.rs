//! Exact registered source coverage using bounded native child verifiers.
//! Root/serial/alpha/norm joins and constraint order match legacy source leaves.
use super::*;
use lattica_prover_p3::block_v2::native_graph_source_proof::{NativePrivateProof, NativeStatementProof};

impl SourceBinding<'_, '_, '_> {
    pub(crate) fn verify_statement_owned(&mut self, artifact: &NativeStatementProof) -> Result<()> {
        if self.statement_verified { return Err(error("statement source already verified")); }
        let roots = self.plan.statement.map(|index| self.polynomial_roots[index]);
        let mut serial_words = Vec::with_capacity(16);
        for &index in &self.plan.serials {
            serial_words.extend(self.inputs.bases(self.builder,
                &native_words(&self.graph.bytes[index].values))?);
        }
        let serial_words: [Wire; 16] = serial_words.try_into().unwrap();
        statement_air::bundle::owned::verify_bounded(self.builder, self.inputs,
            self.graph.setup_seed, self.expected_statement, &roots, &serial_words, artifact)?;
        for (&index, words) in self.plan.serials.iter().zip(serial_words.chunks_exact(8)) {
            bind_words(self.builder, words.try_into().unwrap(), self.byte_roots[index])?;
        }
        for index in self.plan.statement { self.polynomial_bound[index] = true; }
        for index in self.plan.serials { self.byte_bound[index] = true; }
        self.statement_verified = true;
        Ok(())
    }

    pub(crate) fn verify_private_owned(&mut self, artifact: &NativePrivateProof) -> Result<()> {
        if self.proof_verified { return Err(error("private proof source already verified")); }
        let roots = self.plan.proof.map(|index| self.polynomial_roots[index]);
        let alpha: [Wire; 8] = self.inputs.bases(self.builder,
            &native_words(&self.graph.bytes[self.plan.alpha].values))?.try_into().unwrap();
        proof_air::join::owned::verify_bounded(self.builder, self.inputs, &roots, &alpha, artifact)?;
        bind_words(self.builder, &alpha, self.byte_roots[self.plan.alpha])?;
        for index in self.plan.proof { self.polynomial_bound[index] = true; }
        self.byte_bound[self.plan.alpha] = true;
        for index in self.plan.norms { self.operation_bound[index] = true; }
        self.proof_verified = true;
        Ok(())
    }
}
