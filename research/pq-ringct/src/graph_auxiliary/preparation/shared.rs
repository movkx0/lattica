use super::*;
use crate::graph_tree::commitment_batches::FieldBatch;

enum Root { Ready([Val; 4]), Pending(usize) }
impl Root {
    fn resolve(self, values: &[[Val; 4]]) -> [Val; 4] {
        match self { Self::Ready(root) => root, Self::Pending(index) => values[index] }
    }
}
struct Pending { operation: usize, role: Role, payload: Payload, left: Root, right: Root }
pub(crate) const FRAME_BYTES: usize = 8 * (7 * (core::mem::size_of::<Pending>()
    + core::mem::size_of::<AuxiliaryRequest>() + core::mem::size_of::<[Val; 8]>()) + 4096);

fn bytes(hashes: &mut FieldBatch<'_, '_>, operations: &OperationContext<'_>, domain: u64, bytes: &[u8]) -> Result<Root> {
    operations.admit_field_chunks(bytes.len().div_ceil(2)).map_err(err)?;
    let words = bytes.chunks(2).map(|pair| u64::from(pair[0]) | (u64::from(*pair.get(1).unwrap_or(&0)) << 8)).collect();
    Ok(Root::Pending(hashes.push([domain, bytes.len() as u64, 0, 0], words).map_err(err)?))
}
fn uniform(hashes: &mut FieldBatch<'_, '_>, operations: &OperationContext<'_>, kind: uniform_air::Kind, roots: &[[Val; 4]]) -> Result<Root> {
    require(roots.len() == kind.polynomials(), "uniform root count")?;
    operations.admit_field_chunks(roots.len() * 4).map_err(err)?;
    let words = roots.iter().flatten().map(|v| v.as_canonical_u64()).collect();
    Ok(Root::Pending(hashes.push(UniformAir::new(kind).bundle_initial().map(|v| v.as_canonical_u64()), words).map_err(err)?))
}
fn transcript(hashes: &mut FieldBatch<'_, '_>, operations: &OperationContext<'_>, air: &TranscriptAir, roots: &[[Val; 4]]) -> Result<Root> {
    require(roots.len() == air.parts().len(), "transcript ordered root count")?;
    operations.admit_field_chunks(roots.len() * 8).map_err(err)?;
    let mut words = Vec::with_capacity(roots.len() * 8);
    for (index, (&kind, root)) in air.parts().iter().zip(roots).enumerate() {
        let tag = match kind { transcript_air::PartKind::Bytes32 => 1, transcript_air::PartKind::PolynomialQ => 2,
            transcript_air::PartKind::PolynomialQhat => 3 };
        words.extend([tag, kind.byte_len() as u64, index as u64, 0]);
        words.extend(root.iter().map(|v| v.as_canonical_u64()));
    }
    Ok(Root::Pending(hashes.push([transcript_air::BUNDLE_DOMAIN, roots.len() as u64, air.byte_len() as u64, 1], words).map_err(err)?))
}
impl AuxiliaryFactory {
    pub(super) fn prepare_shared(tree: &graph_tree::Plan, graph: &UnprovedRelationGraph,
        context: &graph_tree::GraphContext, memory_budget: u64, operations: &OperationContext<'_>, crypto: &graph_crypto::Plan) -> Result<Self> {
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/matrict/graph-auxiliary-factory/v1");
        identity.update(crate::graph_proofs::compiled_source_fingerprint());
        identity.update(tree.label()); identity.update(context.context);
        for value in context.statement.iter().chain(&context.node_manifest) { identity.update(value.as_canonical_u64().to_le_bytes()); }
        let identity: [u8; 32] = identity.finalize().into();
        let request = |operation, subrequest| crypto.requests().iter()
            .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
            .ok_or_else(|| Error("missing exact graph crypto request".into()));
        let stream = |operation, subrequest, domain| -> Result<(Vec<u8>, Option<[Val; 4]>)> {
            let request = request(operation, subrequest)?;
            if let Some((bytes, root)) = request.take_prepared_output(context, domain).map_err(err)? {
                Ok((bytes, Some(root)))
            } else { Ok((request.output_bytes_hint_on_gpu(operations).map_err(err)?, None)) }
        };
        let root = |operation, id, kind| -> Result<[Val; 4]> {
            let node = graph.polynomial(id);
            require(node.source == Source::Derived { operation } && node.kind == kind, "auxiliary polynomial producer/kind mismatch")?;
            Ok(node.commitment)
        };
        let mut hashes = FieldBatch::new(operations, 14, crate::preparation_options::field_batches()).map_err(err)?;
        let mut pending = Vec::with_capacity(7);
        for (index, operation) in graph.operations().iter().enumerate() {
            let additional = match operation { Operation::SampleG { .. } | Operation::HashAlpha { .. } => 1,
                Operation::ExpandAlpha { .. } | Operation::HashX { .. } => 2, _ => 0 };
            require(pending.len() + additional <= 7, "auxiliary request capacity")?;
            match operation {
                Operation::SampleG { output: ids, .. } => {
                    let kind = uniform_air::Kind::SampleG4;
                    let (output, cached) = stream(index, 0, crate::aes_lane_air::AES_OUTPUT_DOMAIN)?;
                    let roots = ids.iter().map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q })).collect::<Result<Vec<_>>>()?;
                    let left = match cached { Some(root) => Root::Ready(root), None => bytes(&mut hashes, operations, crate::aes_lane_air::AES_OUTPUT_DOMAIN, &output)? };
                    let right = uniform(&mut hashes, operations, kind, &roots)?;
                    pending.push(Pending { operation: index, role: Role::SampleGUniform, payload: Payload::Uniform(kind, output), left, right });
                }
                Operation::ExpandAlpha { canonical, signed, .. } => {
                    let kind = uniform_air::Kind::ExpandAlpha2;
                    let (output, cached) = stream(index, 0, crate::aes_lane_air::AES_OUTPUT_DOMAIN)?;
                    let roots = canonical.iter().map(|&id| root(index, id, PolynomialKind::Canonical { modulus: Q })).collect::<Result<Vec<_>>>()?;
                    let left = match cached { Some(root) => Root::Ready(root), None => bytes(&mut hashes, operations, crate::aes_lane_air::AES_OUTPUT_DOMAIN, &output)? };
                    let right = uniform(&mut hashes, operations, kind, &roots)?;
                    pending.push(Pending { operation: index, role: Role::AlphaUniform, payload: Payload::Uniform(kind, output), left, right });
                    let (output, cached) = stream(index, 1, crate::aes_lane_air::AES_OUTPUT_DOMAIN)?;
                    let left = match cached { Some(root) => Root::Ready(root), None => bytes(&mut hashes, operations, crate::aes_lane_air::AES_OUTPUT_DOMAIN, &output)? };
                    pending.push(Pending { operation: index, role: Role::AlphaSparse, payload: Payload::Sparse(sparse_air::Kind::AlphaPrime39, output), left,
                        right: Root::Ready(root(index, *signed, PolynomialKind::Signed { bound: 1 })?) });
                }
                Operation::HashAlpha { .. } | Operation::HashX { .. } => {
                    let (air, values, roots) = TranscriptAir::from_graph_operation(graph, operation).map_err(err)?;
                    let input = air.serialize(&values).map_err(err)?;
                    let left = transcript(&mut hashes, operations, &air, &roots)?;
                    let right = match request(index, 0)?.prepared_input(context, SHAKE_INPUT_DOMAIN, &input).map_err(err)? {
                        Some(root) => Root::Ready(root), None => bytes(&mut hashes, operations, SHAKE_INPUT_DOMAIN, &input)?,
                    };
                    let role = if matches!(operation, Operation::HashAlpha { .. }) { Role::HashAlphaTranscript } else { Role::HashXTranscript };
                    pending.push(Pending { operation: index, role, payload: Payload::Transcript(air, values), left, right });
                    if let Operation::HashX { output, .. } = operation {
                        let (stream, cached) = stream(index, 0, SHAKE_OUTPUT_DOMAIN)?;
                        let left = match cached { Some(root) => Root::Ready(root), None => bytes(&mut hashes, operations, SHAKE_OUTPUT_DOMAIN, &stream)? };
                        pending.push(Pending { operation: index, role: Role::HashXSparse, payload: Payload::Sparse(sparse_air::Kind::ChallengeX44, stream), left,
                            right: Root::Ready(root(index, *output, PolynomialKind::Signed { bound: 1 })?) });
                    }
                }
                _ => {}
            }
            require(pending.len() <= 7, "auxiliary request capacity")?;
        }
        let roots = hashes.finish().map_err(err)?;
        let requests = pending.into_iter().map(|item| AuxiliaryRequest::new(identity, item.operation, item.role, item.payload,
            combined(item.left.resolve(&roots), item.right.resolve(&roots)), memory_budget)).collect::<Result<_>>()?;
        Ok(Self { requests })
    }
}
