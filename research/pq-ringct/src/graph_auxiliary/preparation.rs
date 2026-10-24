//! GPU preparation of raw sampler streams and auxiliary commitment endpoints.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::OperationContext;
use p3_field::PrimeCharacteristicRing;

fn commit_bytes_on_gpu(
    operations: &OperationContext<'_>,
    domain: u64,
    bytes: &[u8],
) -> Result<[Val; 4]> {
    operations
        .admit_field_chunks(bytes.len().div_ceil(2))
        .map_err(err)?;
    let words: Vec<u64> = bytes
        .chunks(2)
        .map(|pair| u64::from(pair[0]) | (u64::from(*pair.get(1).unwrap_or(&0)) << 8))
        .collect();
    operations
        .commit_field_chunks([domain, bytes.len() as u64, 0, 0], &words)
        .map(|root| root.map(Val::from_u64))
        .map_err(err)
}

fn uniform_bundle_on_gpu(
    operations: &OperationContext<'_>,
    kind: uniform_air::Kind,
    roots: &[[Val; 4]],
) -> Result<[Val; 4]> {
    require(roots.len() == kind.polynomials(), "uniform root count")?;
    operations
        .admit_field_chunks(roots.len() * 4)
        .map_err(err)?;
    let words: Vec<_> = roots
        .iter()
        .flatten()
        .map(|v| v.as_canonical_u64())
        .collect();
    operations
        .commit_field_chunks(
            UniformAir::new(kind)
                .bundle_initial()
                .map(|v| v.as_canonical_u64()),
            &words,
        )
        .map(|root| root.map(Val::from_u64))
        .map_err(err)
}

fn transcript_bundle_on_gpu(
    operations: &OperationContext<'_>,
    air: &TranscriptAir,
    roots: &[[Val; 4]],
) -> Result<[Val; 4]> {
    require(
        roots.len() == air.parts().len(),
        "transcript ordered root count",
    )?;
    operations
        .admit_field_chunks(roots.len() * 8)
        .map_err(err)?;
    let mut words = Vec::with_capacity(roots.len() * 8);
    for (index, (&kind, root)) in air.parts().iter().zip(roots).enumerate() {
        let tag = match kind {
            transcript_air::PartKind::Bytes32 => 1,
            transcript_air::PartKind::PolynomialQ => 2,
            transcript_air::PartKind::PolynomialQhat => 3,
        };
        words.extend_from_slice(&[tag, kind.byte_len() as u64, index as u64, 0]);
        words.extend(root.iter().map(|v| v.as_canonical_u64()));
    }
    operations
        .commit_field_chunks(
            [
                transcript_air::BUNDLE_DOMAIN,
                roots.len() as u64,
                air.byte_len() as u64,
                1,
            ],
            &words,
        )
        .map(|root| root.map(Val::from_u64))
        .map_err(err)
}

impl AuxiliaryFactory {
    pub(super) fn new_on_gpu(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        context: &graph_tree::GraphContext,
        memory_budget: u64,
        operations: &OperationContext<'_>,
    ) -> Result<Self> {
        require(memory_budget > 0, "zero auxiliary memory budget")?;
        require(
            tree.node_manifest_hint_on_gpu(graph, operations)
                .map_err(err)?
                == context.node_manifest,
            "auxiliary graph manifest mismatch",
        )?;
        for node in graph.bytes() {
            match node.source {
                Source::Context => require(
                    node.values == context.context,
                    "auxiliary graph context mismatch",
                )?,
                Source::StatementSeed => require(
                    node.values == graph.setup_seed(),
                    "auxiliary setup seed mismatch",
                )?,
                _ => {}
            }
        }
        let crypto = graph_crypto::Plan::new_with_operations(
            tree,
            graph,
            graph_crypto::Policy::default(),
            operations,
        )
        .map_err(err)?;
        let stream = |operation: usize, subrequest: u32| -> Result<Vec<u8>> {
            crypto
                .requests()
                .iter()
                .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
                .ok_or_else(|| Error("missing exact graph crypto request".into()))?
                .output_bytes_hint_on_gpu(operations)
                .map_err(err)
        };
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/matrict/graph-auxiliary-factory/v1");
        identity.update(crate::graph_proofs::compiled_source_fingerprint());
        identity.update(tree.label());
        identity.update(context.context);
        for value in context.statement.iter().chain(&context.node_manifest) {
            identity.update(value.as_canonical_u64().to_le_bytes());
        }
        let identity: [u8; 32] = identity.finalize().into();
        let root = |operation: usize, id, kind| -> Result<[Val; 4]> {
            let node = graph.polynomial(id);
            require(
                node.source == Source::Derived { operation } && node.kind == kind,
                "auxiliary polynomial producer/kind mismatch",
            )?;
            Ok(node.commitment)
        };
        let mut requests = Vec::new();
        let mut push = |operation, role, payload, expected| -> Result<()> {
            requests.push(AuxiliaryRequest::new(
                identity,
                operation,
                role,
                payload,
                expected,
                memory_budget,
            )?);
            Ok(())
        };
        for (index, operation) in graph.operations().iter().enumerate() {
            match operation {
                Operation::SampleG { output, .. } => {
                    let kind = uniform_air::Kind::SampleG4;
                    let bytes = stream(index, 0)?;
                    let roots = output
                        .iter()
                        .map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q }))
                        .collect::<Result<Vec<_>>>()?;
                    let expected = combined(
                        commit_bytes_on_gpu(
                            operations,
                            crate::aes_lane_air::AES_OUTPUT_DOMAIN,
                            &bytes,
                        )?,
                        uniform_bundle_on_gpu(operations, kind, &roots)?,
                    );
                    push(
                        index,
                        Role::SampleGUniform,
                        Payload::Uniform(kind, bytes),
                        expected,
                    )?;
                }
                Operation::ExpandAlpha {
                    canonical, signed, ..
                } => {
                    let kind = uniform_air::Kind::ExpandAlpha2;
                    let bytes = stream(index, 0)?;
                    let roots = canonical
                        .iter()
                        .map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q }))
                        .collect::<Result<Vec<_>>>()?;
                    let expected = combined(
                        commit_bytes_on_gpu(
                            operations,
                            crate::aes_lane_air::AES_OUTPUT_DOMAIN,
                            &bytes,
                        )?,
                        uniform_bundle_on_gpu(operations, kind, &roots)?,
                    );
                    push(
                        index,
                        Role::AlphaUniform,
                        Payload::Uniform(kind, bytes),
                        expected,
                    )?;
                    let bytes = stream(index, 1)?;
                    let expected = combined(
                        commit_bytes_on_gpu(
                            operations,
                            crate::aes_lane_air::AES_OUTPUT_DOMAIN,
                            &bytes,
                        )?,
                        root(index, *signed, PolynomialKind::Signed { bound: 1 })?,
                    );
                    push(
                        index,
                        Role::AlphaSparse,
                        Payload::Sparse(sparse_air::Kind::AlphaPrime39, bytes),
                        expected,
                    )?;
                }
                Operation::HashAlpha { .. } | Operation::HashX { .. } => {
                    // This helper copies node values and roots and constructs
                    // public descriptors; it does not hash or evaluate hints.
                    let (air, values, roots) =
                        TranscriptAir::from_graph_operation(graph, operation).map_err(err)?;
                    let input = air.serialize(&values).map_err(err)?;
                    let expected = combined(
                        transcript_bundle_on_gpu(operations, &air, &roots)?,
                        commit_bytes_on_gpu(operations, SHAKE_INPUT_DOMAIN, &input)?,
                    );
                    let role = if matches!(operation, Operation::HashAlpha { .. }) {
                        Role::HashAlphaTranscript
                    } else {
                        Role::HashXTranscript
                    };
                    push(index, role, Payload::Transcript(air, values), expected)?;
                    if let Operation::HashX { output, .. } = operation {
                        let bytes = stream(index, 0)?;
                        let expected = combined(
                            commit_bytes_on_gpu(operations, SHAKE_OUTPUT_DOMAIN, &bytes)?,
                            root(index, *output, PolynomialKind::Signed { bound: 1 })?,
                        );
                        push(
                            index,
                            Role::HashXSparse,
                            Payload::Sparse(sparse_air::Kind::ChallengeX44, bytes),
                            expected,
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(Self { requests })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_prover_p3::block_v2::commitment;
    use p3_symmetric::Permutation;

    #[test]
    #[ignore = "real GPU field-chain framing parity and rejection; exclusive admitted OpenCL session"]
    fn gpu_field_chunks_match_cpu_padding_and_reject_noncanonical_words() {
        assert!(!cfg!(debug_assertions));
        let execution = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 4096,
        })
        .unwrap();
        execution
            .with_witness_preparation(1 << 20, |operations| {
                for count in [
                    0, 1, 2, 3, 4, 5, 7, 8, 9, 63, 64, 65, 1025, 4095, 4096, 4097,
                ] {
                    let words: Vec<_> = (0..count)
                        .map(|i| [0, 1, commitment::MODULUS - 1, i as u64][i % 4])
                        .collect();
                    let initial = [0x4454_4553_5431, count as u64, 7, 9];
                    let mut expected = initial.map(Val::from_u64);
                    for chunk in words.chunks(4) {
                        let mut state = [Val::ZERO; 8];
                        state[..4].copy_from_slice(&expected);
                        for (dst, &word) in state[4..].iter_mut().zip(chunk) {
                            *dst = Val::from_u64(word);
                        }
                        p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut state);
                        expected.copy_from_slice(&state[..4]);
                    }
                    assert_eq!(
                        operations.commit_field_chunks(initial, &words)?,
                        expected.map(|v| v.as_canonical_u64())
                    );
                    let bytes: Vec<_> = (0..count).map(|i| (i * 31 + 7) as u8).collect();
                    assert_eq!(
                        commit_bytes_on_gpu(operations, SHAKE_INPUT_DOMAIN, &bytes)
                            .map_err(|e| e.to_string())?,
                        commit_bytes(SHAKE_INPUT_DOMAIN, &bytes),
                    );
                }
                Ok(())
            })
            .unwrap();
        for (initial, words) in [
            ([commitment::MODULUS, 0, 0, 0], vec![]),
            ([0; 4], vec![commitment::MODULUS]),
            ([0; 4], vec![1, 2, 3, 4, u64::MAX]),
        ] {
            assert!(execution
                .with_witness_preparation(8192, |operations| {
                    assert!(operations.commit_field_chunks(initial, &words).is_err());
                    Ok(())
                })
                .is_err());
        }
        assert!(execution
            .with_witness_preparation(8, |operations| {
                assert!(operations.admit_field_chunks(0).is_err());
                Ok(())
            })
            .is_err());
        drop(execution);
    }
}
