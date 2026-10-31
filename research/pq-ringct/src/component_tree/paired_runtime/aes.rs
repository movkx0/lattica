//! Bounded unchanged AES wrapper construction under an owned operation epoch.
//! Native proof and independently verified receipt remain with their original
//! owner in the enclosing AES compile operation throughout this call.
use super::*;
use lattica_prover_p3::block_v2::{native_aes_proof::NativeAesProof, native_gpu::OperationContext};
use p3_air::BaseAir;

pub(crate) fn compile_aes<'request>(request: &'request Request, context: &GraphContext,
    endpoints: &EndpointContext, index: usize, source: ComponentSourceFacts,
    child: &NativeAesProof, access: &ExecutionAccess<'_>, operations: &OperationContext<'_>)
    -> Result<PairedCompiled<'request>> {
    if access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired {
        return Err(PairedFailure::Authority);
    }
    let contract = request.contract().map_err(|_| PairedFailure::Source)?;
    let Kind::Aes(descriptor) = contract.kind else { return Err(PairedFailure::Source); };
    let segment = request.segments().get(index).ok_or(PairedFailure::Coverage)?;
    let first = u32::try_from(segment.first_unit).map_err(|_| PairedFailure::Overflow)?;
    let count = u32::try_from(segment.units).map_err(|_| PairedFailure::Overflow)?;
    let spec = contract.span(first, count).map_err(|_| PairedFailure::Coverage)?;
    let air = aes_lane_air::AesLaneAir::segment(descriptor, segment.first_unit, segment.units)
        .map_err(|_| PairedFailure::Source)?;
    if air.height != segment.height || air.width() != segment.width
        || air.num_periodic_columns() != 31 || air.num_public_values() != 12 {
        return Err(PairedFailure::SourceDrift);
    }
    let started = Instant::now();
    let node = preparation::with_endpoint_operations(operations, |endpoint_root| {
        let mut public = header(&spec, endpoints)?;
        public[HEADER..HEADER + 4].copy_from_slice(&endpoint_root(&contract,
            &child.public_values[aes_lane_air::OUTPUT_START..aes_lane_air::OUTPUT_START + 4])?);
        public[HEADER + 4..].copy_from_slice(&endpoint_root(&contract,
            &child.public_values[aes_lane_air::OUTPUT_END..aes_lane_air::OUTPUT_END + 4])?);
        let mut builder = ProgramBuilder::new_with_construction_limits(source::PUBLICS, source::construction())
            .map_err(err)?;
        let outer = public_wires(&mut builder, &spec)?;
        let mut inputs = ProofInputs::default();
        let wires = inputs.bases(&mut builder, &child.public_values).map_err(err)?;
        let columns = air.periodic_columns();
        require(columns.len() == 31 && columns.iter().all(|column| column.len() == 64),
            "owned AES periodic geometry")?;
        verifier::uni::verify_bounded(&mut builder, &mut inputs, &air, air.height, &wires,
            &child.proof, &columns, verifier::uni::BoundedSymbolicAllowance::REQUIRED).map_err(err)?;
        for i in 0..4 {
            builder.assert_equal(wires[aes_lane_air::INPUT_COMMITMENT + i], outer[EXPECTED_INPUT + i]);
        }
        bind_endpoints(&mut builder, &spec, &outer,
            &wires[aes_lane_air::OUTPUT_START..aes_lane_air::OUTPUT_START + 4],
            &wires[aes_lane_air::OUTPUT_END..aes_lane_air::OUTPUT_END + 4]);
        Ok(CompiledNode { spec, program: Arc::new(builder.finish(None).map_err(err)?),
            public, witness: inputs.values })
    }).map_err(|_| PairedFailure::Compilation)?;
    compiled(node, request, context, endpoints, ComponentSpan { first, count, level: 0 },
        source, started.elapsed().as_nanos())
}
