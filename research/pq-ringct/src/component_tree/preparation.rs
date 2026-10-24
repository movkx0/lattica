//! Explicit endpoint preparation; the legacy CPU path remains an independent
//! reference. Host verifier construction only emits constrained operations.
use super::*;
use crate::execution::ProvingContext;
use lattica_prover_p3::proving::Policy;

type EndpointHasher<'a> = dyn Fn(&Contract, &[Val]) -> Result<[Val; 4]> + 'a;

pub(super) fn with_endpoint_preparation<T>(
    execution: Option<&ProvingContext>,
    compile: impl FnOnce(&EndpointHasher<'_>) -> Result<T>,
) -> Result<T> {
    let Some(execution) = execution.filter(|e| e.policy() == Policy::GpuRequired) else {
        return compile(&endpoint_root);
    };
    #[cfg(not(feature = "opencl"))]
    {
        let _ = execution;
        Err(Error("GPU endpoint preparation requires OpenCL".into()))
    }
    #[cfg(feature = "opencl")]
    {
        let host = usize::try_from(execution.host_bytes()).map_err(err)?;
        let (compiled, _) = execution
            .with_witness_preparation(host, |operations| {
                compile(&|contract, values| endpoint_root_on_gpu(contract, values, operations))
                    .map_err(|e| e.to_string())
            })
            .map_err(err)?;
        Ok(compiled)
    }
}

#[cfg(feature = "opencl")]
fn endpoint_root_on_gpu(
    contract: &Contract,
    values: &[Val],
    operations: &lattica_prover_p3::block_v2::native_gpu::OperationContext<'_>,
) -> Result<[Val; 4]> {
    require(
        values.len() == contract.boundary_width(),
        "endpoint field width",
    )?;
    let count = values
        .len()
        .checked_add(2)
        .ok_or_else(|| Error("endpoint field count overflow".into()))?;
    operations.admit_field_chunks(count).map_err(err)?;
    let mut fields = Vec::with_capacity(count);
    fields.extend([contract.tag(), values.len() as u64]);
    fields.extend(values.iter().map(|v| v.as_canonical_u64()));
    operations
        .commit_field_chunks([ENDPOINT_DOMAIN, count as u64, 0, 0], &fields)
        .map(|root| root.map(Val::from_u64))
        .map_err(err)
}
