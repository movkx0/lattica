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
