//! Source endpoint hints from existing graph roots and GPU hash compression.
use super::*;
use crate::{
    native_packet::STATEMENT_BYTES,
    rust_verify::{
        committed_backend::{PolynomialKind, PolynomialValues},
        D, Q, QHAT,
    },
};
use lattica_prover_p3::block_v2::native_gpu::OperationContext;
use p3_field::PrimeField64;

impl<'a> SourceFactory<'a> {
    pub(super) fn new_on_gpu(
        plan: &Plan,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &'a [u8],
        proof: &[u8],
        memory_budget: u64,
        operations: &OperationContext<'_>,
    ) -> Result<Self> {
        require(memory_budget != 0, "zero source proof memory budget")?;
        require(statement.len() == STATEMENT_BYTES, "statement length")?;
        require(
            plan.node_manifest_hint_on_gpu(graph, operations)
                .map_err(err)?
                == context.node_manifest,
            "source graph manifest mismatch",
        )?;
        let setup_seed: [u8; 32] = statement[..32].try_into().map_err(err)?;
        require(
            setup_seed == graph.setup_seed(),
            "source statement setup mismatch",
        )?;
        let private = ProofValues::from_proof(&Proof::decode(proof).map_err(err)?).map_err(err)?;
        require(
            private.polynomials.len() == proof_air::POLYNOMIALS,
            "private polynomial count",
        )?;

        // Raw equality binds the caller's source bytes to existing graph nodes.
        // Roots are not recomputed here; the native source AIR and recursive
        // joins still independently constrain every root and canonical value.
        let mut statement_roots = [None; statement_air::POLYNOMIALS];
        let mut proof_roots = [None; proof_air::POLYNOMIALS];
        for node in graph.polynomials() {
            match node.source {
                Source::StatementPolynomial { position } => {
                    let slot = statement_roots
                        .get_mut(position)
                        .ok_or_else(|| Error("source statement polynomial position".into()))?;
                    require(slot.is_none(), "duplicate source statement polynomial")?;
                    require(
                        node.kind == PolynomialKind::Canonical { modulus: Q },
                        "source statement polynomial kind",
                    )?;
                    let PolynomialValues::Canonical(values) = &node.values else {
                        return Err(Error("source statement polynomial values".into()));
                    };
                    let encoded = &statement[32 + position * 1024..32 + (position + 1) * 1024];
                    for (&value, bytes) in values.iter().zip(encoded.chunks_exact(4)) {
                        require(
                            value == u64::from(u32::from_le_bytes(bytes.try_into().map_err(err)?)),
                            "source statement polynomial values mismatch",
                        )?;
                    }
                    *slot = Some(node.commitment);
                }
                Source::ProofPolynomial { position } => {
                    let slot = proof_roots
                        .get_mut(position)
                        .ok_or_else(|| Error("source private polynomial position".into()))?;
                    require(slot.is_none(), "duplicate source private polynomial")?;
                    let expected = &private.polynomials[position];
                    let class = proof_air::class(position);
                    if class < 2 {
                        let modulus = if class == 0 { Q } else { QHAT };
                        require(
                            node.kind == PolynomialKind::Canonical { modulus },
                            "source private canonical kind",
                        )?;
                        let PolynomialValues::Canonical(values) = &node.values else {
                            return Err(Error("source private canonical values".into()));
                        };
                        for (&value, &expected) in values.iter().zip(expected) {
                            require(
                                i64::try_from(value).map_err(err)? == expected,
                                "source private canonical values mismatch",
                            )?;
                        }
                    } else {
                        require(
                            node.kind
                                == PolynomialKind::Signed {
                                    bound: proof_air::OFFSETS[class],
                                },
                            "source private signed kind",
                        )?;
                        let PolynomialValues::Signed(values) = &node.values else {
                            return Err(Error("source private signed values".into()));
                        };
                        require(values == expected, "source private signed values mismatch")?;
                    }
                    *slot = Some(node.commitment);
                }
                _ => {}
            }
        }
        require(
            statement_roots.iter().all(Option::is_some),
            "missing source statement polynomial",
        )?;
        require(
            proof_roots.iter().all(Option::is_some),
            "missing source private polynomial",
        )?;
        for node in graph.bytes() {
            let expected = match node.source {
                Source::Context => context.context,
                Source::StatementSeed => setup_seed,
                Source::ProofAlpha => private.alpha,
                Source::StatementSerial { position } if position < 2 => statement
                    [STATEMENT_BYTES - 64 + position * 32..STATEMENT_BYTES - 32 + position * 32]
                    .try_into()
                    .map_err(err)?,
                Source::StatementSerial { .. } => {
                    return Err(Error("source serial position".into()))
                }
                _ => continue,
            };
            require(node.values == expected, "source bytes mismatch")?;
        }

        let digest_count = 1 + statement.len().div_ceil(4);
        operations.admit_field_chunks(digest_count).map_err(err)?;
        let mut fields = Vec::with_capacity(digest_count);
        fields.push(statement.len() as u64);
        fields.extend(
            statement
                .chunks_exact(4)
                .map(|word| u64::from(u32::from_le_bytes(word.try_into().unwrap()))),
        );
        let digest = operations
            .commit_field_chunks(
                [
                    crate::recursive_aggregation::STATEMENT_DOMAIN,
                    digest_count as u64,
                    0,
                    0,
                ],
                &fields,
            )
            .map_err(err)?
            .map(Val::from_u64);
        drop(fields);
        require(
            digest == context.statement,
            "source statement digest mismatch",
        )?;

        let statement_words = 8 + statement_air::POLYNOMIALS * 4 + 16;
        operations
            .admit_field_chunks(statement_words)
            .map_err(err)?;
        let mut fields = Vec::with_capacity(statement_words);
        fields.extend(
            setup_seed
                .chunks_exact(4)
                .map(|word| u64::from(u32::from_le_bytes(word.try_into().unwrap()))),
        );
        fields.extend(
            statement_roots
                .into_iter()
                .flatten()
                .flatten()
                .map(|v| v.as_canonical_u64()),
        );
        fields.extend(
            statement[STATEMENT_BYTES - 64..]
                .chunks_exact(4)
                .map(|word| u64::from(u32::from_le_bytes(word.try_into().unwrap()))),
        );
        let bundle = operations
            .commit_field_chunks(
                [
                    statement_air::BUNDLE_DOMAIN,
                    Q,
                    D as u64,
                    statement_air::POLYNOMIALS as u64,
                ],
                &fields,
            )
            .map_err(err)?
            .map(Val::from_u64);
        drop(fields);

        let proof_words = proof_air::POLYNOMIALS * 4 + 8;
        operations.admit_field_chunks(proof_words).map_err(err)?;
        let mut fields = Vec::with_capacity(proof_words);
        fields.extend(
            proof_roots
                .into_iter()
                .flatten()
                .flatten()
                .map(|v| v.as_canonical_u64()),
        );
        fields.extend(
            private
                .alpha
                .chunks_exact(4)
                .map(|word| u64::from(u32::from_le_bytes(word.try_into().unwrap()))),
        );
        let expected_private = operations
            .commit_field_chunks(
                [
                    proof_air::BUNDLE_DOMAIN,
                    proof_air::POLYNOMIALS as u64,
                    8,
                    1,
                ],
                &fields,
            )
            .map_err(err)?
            .map(Val::from_u64);
        let mut expected_statement = [Val::ZERO; 8];
        expected_statement[..4].copy_from_slice(&digest);
        expected_statement[4..].copy_from_slice(&bundle);
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/native-source-factory/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(plan.label());
        hash.update(context.context);
        hash.update(statement);
        hash.update(proof);
        Ok(Self {
            statement,
            private,
            setup_seed,
            expected_statement,
            expected_private,
            identity: hash.finalize().into(),
            memory_budget,
        })
    }
}
