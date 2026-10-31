//! The original wide SHAKE AIR behind the same authenticated endpoint contract.
//!
//! This layout can reduce native trace cells at the cost of larger recursive
//! openings. It does not change the proof profile or the request semantics.
use super::*;
use crate::crypto_join::ShakeSegmentProof;

fn trusted_air(contract: &Contract, first: u32, count: u32) -> Result<(Spec, shake_air::ShakeAir)> {
    let Kind::Shake(descriptor) = contract.kind else {
        return Err(Error("wide SHAKE proof used for non-SHAKE contract".into()));
    };
    let spec = contract.span(first, count)?;
    let air = shake_air::ShakeAir::new(descriptor, first as usize, count as usize).map_err(err)?;
    Ok((spec, air))
}

/// Compile the full hiding STARK verifier for an exact wide SHAKE segment.
/// The contract and interval are trusted registration data; proof fields never
/// select a descriptor, AIR, height, phase schedule, or request identity.
pub fn compile_wide_shake(
    contract: &Contract,
    first: u32,
    count: u32,
    context: &EndpointContext,
    proof: &ShakeSegmentProof,
) -> Result<CompiledNode> {
    compile_wide_shake_with_context(contract, first, count, context, proof, None)
}
pub fn compile_wide_shake_with_context(
    contract: &Contract,
    first: u32,
    count: u32,
    context: &EndpointContext,
    proof: &ShakeSegmentProof,

    execution: Option<&crate::execution::ProvingContext>,
) -> Result<CompiledNode> {
    with_endpoint_preparation(execution, |endpoint_root| {
        let (spec, air) = trusted_air(contract, first, count)?;
        let indices = shake_indices();
        let mut public = header(&spec, context)?;
        for (offset, index) in [(HEADER, &indices[0]), (HEADER + 4, &indices[1])] {
            let values: Vec<_> = index.iter().map(|&i| proof.public_values[i]).collect();
            public[offset..offset + 4].copy_from_slice(&endpoint_root(contract, &values)?);
        }
        let mut b = ProgramBuilder::new(spec.width()).map_err(err)?;
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let child = inputs.bases(&mut b, &proof.public_values).map_err(err)?;
        verifier::uni::verify(&mut b, &mut inputs, &air, air.height, &child, &proof.proof)
            .map_err(err)?;
        let endpoints = indices
            .each_ref()
            .map(|index| index.iter().map(|&i| child[i]).collect::<Vec<_>>());
        bind_endpoints(&mut b, &spec, &outer, &endpoints[0], &endpoints[1]);
        Ok(CompiledNode {
            spec,
            program: Arc::new(b.finish(None).map_err(err)?),
            public,
            witness: inputs.values,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_registration_pins_descriptor_interval_and_phase_schedule() {
        let descriptor = shake_air::Descriptor {
            input_len: 273,
            output_len: 137,
        };
        let contract = Contract::shake([5; 32], 9, descriptor).unwrap();
        assert_eq!(contract.total, 4);
        // Unlike the serial homogeneous batch, a wide segment may cross the
        // absorb/pad/squeeze boundary: the fixed periodic schedule enforces it.
        let (spec, air) = trusted_air(&contract, 1, 3).unwrap();
        assert_eq!((spec.first, spec.count, spec.level), (1, 3, 0));
        assert_eq!(air.descriptor, descriptor);
        assert_eq!(
            (air.first_permutation, air.permutations, air.height),
            (1, 3, 128)
        );
        assert!(trusted_air(&contract, 0, 0).is_err());
        assert!(trusted_air(&contract, 3, 2).is_err());
        assert!(trusted_air(&contract, u32::MAX, 2).is_err());
        let aes = Contract::aes(
            [5; 32],
            9,
            aes_lane_air::Descriptor {
                domain: 1,
                start_counter: 0,
                output_len: 16,
            },
        )
        .unwrap();
        assert!(trusted_air(&aes, 0, 1).is_err());
    }
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
#[path = "wide/proof_tests.rs"]
mod proof_tests;
