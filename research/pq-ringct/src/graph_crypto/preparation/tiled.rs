//! Borrow endpoint payloads and stream their commitments through one fixed
//! device window. Output buffers retain the same source-phase ownership.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::operations_batch::{FieldStream, FieldStreamInput};

impl Plan {
    pub(super) fn prepare_tiled_endpoint_facts(&mut self, context: &graph_tree::GraphContext,
        operations: &OperationContext<'_>) -> Result<()> {
        // Fixed local backing fits ENDPOINT_FRAME_BYTES; large SHAKE inputs
        // remain borrowed and each GPU output is created only once.
        let mut outputs: [Option<Vec<u8>>; 7] = core::array::from_fn(|_| None);
        let mut aes_inputs = [[0u8; 52]; 7];
        let mut streams = [FieldStream { initial: [0; 4], input: FieldStreamInput::Bytes(&[]) }; 14];
        for (index, request) in self.requests.iter().enumerate() {
            require(request.prepared_endpoints.is_none(), "endpoint facts already attempted")?;
            if let (Payload::Aes(key), RequestDescriptor::Aes(d)) = (&request.payload, request.descriptor) {
                let bytes = d.input_bytes(key);
                require(bytes.len() == aes_inputs[index].len(), "AES endpoint input framing")?;
                aes_inputs[index].copy_from_slice(&bytes);
            }
            outputs[index] = Some(request.output_bytes_hint_on_gpu(operations)?);
        }
        for (index, request) in self.requests.iter().enumerate() {
            let (input, input_domain, output_domain) = match (&request.payload, request.descriptor) {
                (Payload::Aes(_), RequestDescriptor::Aes(_)) =>
                    (aes_inputs[index].as_slice(), aes_lane_air::AES_INPUT_DOMAIN, aes_lane_air::AES_OUTPUT_DOMAIN),
                (Payload::Shake(input), RequestDescriptor::Shake(_)) =>
                    (input.as_slice(), shake_air::SHAKE_INPUT_DOMAIN, shake_air::SHAKE_OUTPUT_DOMAIN),
                _ => return Err(Error("endpoint payload/descriptor mismatch".into())),
            };
            let output = outputs[index].as_deref().ok_or_else(|| Error("missing endpoint output".into()))?;
            for (slot, domain, bytes) in [(0, input_domain, input), (1, output_domain, output)] {
                streams[2 * index + slot] = FieldStream { initial: [domain, bytes.len() as u64, 0, 0],
                    input: FieldStreamInput::Bytes(bytes) };
            }
        }
        let roots = operations.commit_field_streams(&streams).map_err(err)?;
        require(roots.len() == 14, "endpoint root count")?;
        for (index, request) in self.requests.iter_mut().enumerate() {
            request.prepared_endpoints = Some(PreparedEndpoints { context: context.clone(),
                endpoints: crate::component_tree::EndpointContext { context: context.context, statement: context.statement,
                    input: roots[2 * index].map(Val::from_u64), output: roots[2 * index + 1].map(Val::from_u64) },
                output: std::sync::Mutex::new(outputs[index].take()), published: false });
        }
        Ok(())
    }
}
