//! Explicit GPU witness preparation. CPU reference helpers remain verification
//! oracles and legacy CPU entry points, never GPU-context preparation fallbacks.
use super::*;
use crate::execution::ProvingContext;
#[cfg(feature = "opencl")]
use lattica_prover_p3::block_v2::native_gpu::OperationContext;
use lattica_prover_p3::proving::Policy as BackendPolicy;
#[cfg(feature = "opencl")]
use p3_field::PrimeCharacteristicRing;

#[cfg(feature = "opencl")]
fn commit_bytes_on_gpu(
    operations: &OperationContext<'_>,
    domain: u64,
    bytes: &[u8],
) -> Result<[Val; 4]> {
    operations
        .admit_field_chunks(bytes.len().div_ceil(2))
        .map_err(err)?;
    // Packing little-endian limbs is marshaling, not Poseidon evaluation.
    let words = bytes
        .chunks(2)
        .map(|pair| u64::from(pair[0]) | (u64::from(*pair.get(1).unwrap_or(&0)) << 8))
        .collect::<Vec<_>>();
    operations
        .commit_field_chunks([domain, bytes.len() as u64, 0, 0], &words)
        .map(|root| root.map(Val::from_u64))
        .map_err(err)
}

impl Plan {
    pub fn new_with_context(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        policy: Policy,
        execution: Option<&ProvingContext>,
    ) -> Result<Self> {
        let Some(execution) = execution.filter(|e| e.policy() == BackendPolicy::GpuRequired) else {
            return Self::new(tree, graph, policy);
        };
        #[cfg(not(feature = "opencl"))]
        {
            let _ = execution;
            Err(Error("GPU crypto preparation requires OpenCL".into()))
        }
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(policy.child_memory_budget_bytes.min(execution.host_bytes()))
                    .map_err(err)?;
            let (plan, _) = execution
                .with_witness_preparation(host, |operations| {
                    Self::new_with_operations(tree, graph, policy, operations)
                        .map_err(|e| e.to_string())
                })
                .map_err(err)?;
            Ok(plan)
        }
    }

    #[cfg(feature = "opencl")]
    pub fn new_with_operations(
        tree: &graph_tree::Plan,
        graph: &UnprovedRelationGraph,
        policy: Policy,
        operations: &OperationContext<'_>,
    ) -> Result<Self> {
        let _ = tree
            .node_manifest_hint_on_gpu(graph, operations)
            .map_err(err)?;
        Self::from_bound_metadata(tree, graph, policy, operations)
    }
    #[cfg(feature = "opencl")]
    pub(crate) fn new_prepared(binding: &crate::graph_tree::preparation::PreparedBindings<'_, '_, '_>, policy: Policy) -> Result<Self> {
        binding.check().map_err(err)?;
        Self::from_bound_metadata(binding.tree(), binding.graph(), policy, binding.operations())
    }
    #[cfg(feature = "opencl")]
    fn from_bound_metadata(tree: &graph_tree::Plan, graph: &UnprovedRelationGraph,
        policy: Policy, operations: &OperationContext<'_>) -> Result<Self> {
        Self::from_trusted_metadata(tree, graph, policy, |seed, context| {
            let mut setup = seed.to_vec();
            setup.extend([64, 4, 4, 4, 5, 5]);
            setup.extend(256u16.to_le_bytes());
            setup.extend((crate::rust_verify::Q as u32).to_le_bytes());
            setup.extend((crate::rust_verify::QHAT as u32).to_le_bytes());
            setup.push(44);
            let mut input = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".to_vec();
            input.extend(operations.shake256(&setup, 32).map_err(err)?);
            input.extend(context);
            Ok(input)
        })
    }
}

impl Request {
    #[cfg(feature = "opencl")]
    pub fn output_bytes_hint_on_gpu(&self, operations: &OperationContext<'_>) -> Result<Vec<u8>> {
        match (&self.payload, self.descriptor) {
            (Payload::Aes(key), RequestDescriptor::Aes(d)) => operations
                .aes256_ctr(key, d.domain, d.start_counter, d.output_len)
                .map_err(err),
            (Payload::Shake(input), RequestDescriptor::Shake(d)) => {
                operations.shake256(input, d.output_len).map_err(err)
            }
            _ => Err(Error("crypto request partition/payload mismatch".into())),
        }
    }

    pub fn output_bytes_hint_with_context(
        &self,
        execution: Option<&ProvingContext>,
    ) -> Result<Vec<u8>> {
        let Some(execution) = execution.filter(|e| e.policy() == BackendPolicy::GpuRequired) else {
            return Ok(self.output_bytes_hint());
        };
        #[cfg(not(feature = "opencl"))]
        {
            let _ = execution;
            Err(Error("GPU crypto preparation requires OpenCL".into()))
        }
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(self.memory_budget.min(execution.host_bytes())).map_err(err)?;
            let (output, _) = execution
                .with_witness_preparation(host, |operations| {
                    self.output_bytes_hint_on_gpu(operations)
                        .map_err(|e| e.to_string())
                })
                .map_err(err)?;
            Ok(output)
        }
    }

    #[cfg(feature = "opencl")]
    pub fn endpoint_context_hint_on_gpu(
        &self,
        context: &graph_tree::GraphContext,
        operations: &OperationContext<'_>,
    ) -> Result<crate::component_tree::EndpointContext> {
        let (input, output_domain) = match (&self.payload, self.descriptor) {
            (Payload::Aes(key), RequestDescriptor::Aes(d)) => (
                commit_bytes_on_gpu(
                    operations,
                    aes_lane_air::AES_INPUT_DOMAIN,
                    &d.input_bytes(key),
                )?,
                aes_lane_air::AES_OUTPUT_DOMAIN,
            ),
            (Payload::Shake(input), RequestDescriptor::Shake(_)) => (
                commit_bytes_on_gpu(operations, shake_air::SHAKE_INPUT_DOMAIN, input)?,
                shake_air::SHAKE_OUTPUT_DOMAIN,
            ),
            _ => return Err(Error("crypto request partition/payload mismatch".into())),
        };
        let output = self.output_bytes_hint_on_gpu(operations)?;
        Ok(crate::component_tree::EndpointContext {
            context: context.context,
            statement: context.statement,
            input,
            output: commit_bytes_on_gpu(operations, output_domain, &output)?,
        })
    }

    pub fn endpoint_context_hint_with_context(
        &self,
        context: &graph_tree::GraphContext,
        execution: Option<&ProvingContext>,
    ) -> Result<crate::component_tree::EndpointContext> {
        let Some(execution) = execution.filter(|e| e.policy() == BackendPolicy::GpuRequired) else {
            return Ok(self.endpoint_context_hint(context));
        };
        #[cfg(not(feature = "opencl"))]
        {
            let _ = execution;
            Err(Error("GPU crypto preparation requires OpenCL".into()))
        }
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(self.memory_budget.min(execution.host_bytes())).map_err(err)?;
            let (endpoints, _) = execution
                .with_witness_preparation(host, |operations| {
                    self.endpoint_context_hint_on_gpu(context, operations)
                        .map_err(|e| e.to_string())
                })
                .map_err(err)?;
            Ok(endpoints)
        }
    }
}

// Facts stay inside their immutable request. The temporary stream is consumed
// only by auxiliary construction; publication drops every unused byte buffer.
// A completed source-preparation scope, not merely successful individual
// hashes, is required before a later constructor can adopt these facts.
#[cfg(feature = "opencl")]
pub(super) struct PreparedEndpoints {
    context: graph_tree::GraphContext,
    endpoints: crate::component_tree::EndpointContext,
    output: std::sync::Mutex<Option<Vec<u8>>>,
    published: bool,
}
#[cfg(feature = "opencl")]
pub(crate) const ENDPOINT_FRAME_BYTES: usize = 8 * (
    7 * (core::mem::size_of::<PreparedEndpoints>() + core::mem::size_of::<[usize; 2]>()
        + core::mem::size_of::<Option<Vec<u8>>>() + core::mem::size_of::<[Val; 4]>()) + 4096);

#[cfg(feature = "opencl")]
impl Plan {
    pub(crate) fn prepare_endpoint_facts(&mut self, context: &graph_tree::GraphContext,
        operations: &OperationContext<'_>, batched: bool) -> Result<()> {
        require(self.requests.len() == 7, "prepared endpoint request catalog")?;
        let mut hashes = graph_tree::commitment_batches::FieldBatch::new(operations, 14, batched).map_err(err)?;
        let mut indices = [[0usize; 2]; 7];
        for (index, request) in self.requests.iter_mut().enumerate() {
            require(request.prepared_endpoints.is_none(), "endpoint facts already attempted")?;
            let (input, domain) = match (&request.payload, request.descriptor) {
                (Payload::Aes(key), RequestDescriptor::Aes(d)) => (d.input_bytes(key).to_vec(), aes_lane_air::AES_INPUT_DOMAIN),
                (Payload::Shake(input), RequestDescriptor::Shake(_)) => (input.clone(), shake_air::SHAKE_INPUT_DOMAIN),
                _ => return Err(Error("endpoint payload/descriptor mismatch".into())),
            };
            let output = request.output_bytes_hint_on_gpu(operations)?;
            let output_domain = match request.descriptor { RequestDescriptor::Aes(_) => aes_lane_air::AES_OUTPUT_DOMAIN,
                RequestDescriptor::Shake(_) => shake_air::SHAKE_OUTPUT_DOMAIN };
            for (slot, domain, bytes) in [(0, domain, input.as_slice()), (1, output_domain, output.as_slice())] {
                operations.admit_field_chunks(bytes.len().div_ceil(2)).map_err(err)?;
                let words = bytes.chunks(2).map(|pair| u64::from(pair[0]) | (u64::from(*pair.get(1).unwrap_or(&0)) << 8)).collect();
                indices[index][slot] = hashes.push([domain, bytes.len() as u64, 0, 0], words).map_err(err)?;
            }
            request.prepared_endpoints = Some(PreparedEndpoints { context: context.clone(),
                endpoints: crate::component_tree::EndpointContext { context: context.context, statement: context.statement,
                    input: [Val::ZERO; 4], output: [Val::ZERO; 4] },
                output: std::sync::Mutex::new(Some(output)), published: false });
        }
        let roots = hashes.finish().map_err(err)?;
        for (request, [input, output]) in self.requests.iter_mut().zip(indices) {
            let prepared = request.prepared_endpoints.as_mut().unwrap();
            prepared.endpoints.input = roots[input]; prepared.endpoints.output = roots[output];
        }
        Ok(())
    }
    pub(crate) fn publish_endpoint_facts(&mut self, context: &graph_tree::GraphContext) -> Result<()> {
        for request in &mut self.requests {
            if let Some(facts) = &mut request.prepared_endpoints {
                require(&facts.context == context && !facts.published, "endpoint publication binding")?;
                drop(facts.output.get_mut().map_err(err)?.take());
                facts.published = true;
            }
        }
        Ok(())
    }
}
#[cfg(feature = "opencl")]
impl Request {
    pub(crate) fn take_prepared_output(&self, context: &graph_tree::GraphContext, domain: u64)
        -> Result<Option<(Vec<u8>, [Val; 4])>> {
        let Some(facts) = &self.prepared_endpoints else { return Ok(None); };
        let expected = match self.descriptor { RequestDescriptor::Aes(_) => aes_lane_air::AES_OUTPUT_DOMAIN,
            RequestDescriptor::Shake(_) => shake_air::SHAKE_OUTPUT_DOMAIN };
        require(&facts.context == context && !facts.published && domain == expected, "prepared output binding")?;
        let bytes = facts.output.lock().map_err(err)?.take().ok_or_else(|| Error("prepared output already consumed".into()))?;
        Ok(Some((bytes, facts.endpoints.output)))
    }
    pub(crate) fn prepared_input(&self, context: &graph_tree::GraphContext, domain: u64, bytes: &[u8]) -> Result<Option<[Val; 4]>> {
        let Some(facts) = &self.prepared_endpoints else { return Ok(None); };
        require(&facts.context == context && !facts.published, "prepared input context")?;
        match (&self.payload, self.descriptor) {
            (Payload::Shake(input), RequestDescriptor::Shake(_)) => require(domain == shake_air::SHAKE_INPUT_DOMAIN && bytes == input, "prepared input framing")?,
            (Payload::Aes(key), RequestDescriptor::Aes(d)) => require(domain == aes_lane_air::AES_INPUT_DOMAIN && bytes == d.input_bytes(key), "prepared input framing")?,
            _ => return Err(Error("prepared input descriptor".into())),
        }
        Ok(Some(facts.endpoints.input))
    }
    pub(crate) fn prepared_endpoint_context(&self, context: &graph_tree::GraphContext) -> Result<Option<crate::component_tree::EndpointContext>> {
        let Some(facts) = &self.prepared_endpoints else { return Ok(None); };
        require(facts.published && &facts.context == context, "unpublished or foreign endpoint facts")?;
        Ok(Some(facts.endpoints.clone()))
    }
}
