//! Complete requests using the original wide AES AIR and unchanged profile.
//!
//! This AIR exposes only complete input/output commitments. It cannot supply
//! cumulative intermediate endpoints, so this adapter has no partial-span API.
use super::*;
use crate::aes_air;

pub struct WideAesProof {
    pub public_values: [Val; aes_air::PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}

fn trusted_air(contract: &Contract) -> Result<(Spec, aes_air::AesAir)> {
    let Kind::Aes(descriptor) = contract.kind else {
        return Err(Error("wide AES proof used for non-AES contract".into()));
    };
    let spec = contract.span(0, contract.total)?;
    let air = aes_air::AesAir::new(descriptor).map_err(err)?;
    Ok((spec, air))
}

/// Emit the full native verifier for exactly the complete trusted request.
/// Descriptor, profile, request index and context come from registration, not
/// proof-selected metadata. Input equality and complete output are constrained.
pub fn compile_wide_aes(
    contract: &Contract,
    context: &EndpointContext,
    proof: &WideAesProof,
) -> Result<CompiledNode> {
    compile_wide_aes_with_context(contract, context, proof, None)
}
pub fn compile_wide_aes_with_context(
    contract: &Contract,
    context: &EndpointContext,
    proof: &WideAesProof,

    execution: Option<&crate::execution::ProvingContext>,
) -> Result<CompiledNode> {
    with_endpoint_preparation(execution, |endpoint_root| {
        let (spec, air) = trusted_air(contract)?;
        let start = [
            Val::from_u64(aes_air::AES_OUTPUT_DOMAIN),
            Val::from_usize(air.descriptor.output_len),
            Val::ZERO,
            Val::ZERO,
        ];
        let mut public = header(&spec, context)?;
        public[HEADER..HEADER + 4].copy_from_slice(&endpoint_root(contract, &start)?);
        public[HEADER + 4..HEADER + 8]
            .copy_from_slice(&endpoint_root(contract, &proof.public_values[4..8])?);
        let mut b = ProgramBuilder::new(spec.width()).map_err(err)?;
        let outer = public_wires(&mut b, &spec)?;
        let mut inputs = ProofInputs::default();
        let child = inputs.bases(&mut b, &proof.public_values).map_err(err)?;
        verifier::uni::verify(&mut b, &mut inputs, &air, air.height, &child, &proof.proof)
            .map_err(err)?;
        for i in 0..4 {
            b.assert_equal(child[i], outer[EXPECTED_INPUT + i]);
        }
        let start = start.map(|value| b.constant(value));
        bind_endpoints(&mut b, &spec, &outer, &start, &child[4..8]);
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
    fn whole_wide_aes_registration_pins_complete_descriptor_and_span() {
        for (output_len, start_counter, expected_blocks, height) in [
            (31, u32::MAX, 2, 32),
            (2572, 0, 161, 4096),
            (4788, 0, 300, 8192),
        ] {
            let descriptor = aes_air::Descriptor {
                domain: 0x4368,
                start_counter,
                output_len,
            };
            let contract = Contract::aes([5; 32], 9, descriptor).unwrap();
            let (spec, air) = trusted_air(&contract).unwrap();
            assert_eq!(
                (spec.first, spec.count, spec.level),
                (0, expected_blocks, 0)
            );
            assert_eq!(spec.end(), spec.contract.total);
            assert_eq!(air.descriptor, descriptor);
            assert_eq!(air.height, height);
        }
        let shake = Contract::shake(
            [5; 32],
            9,
            shake_air::Descriptor {
                input_len: 1,
                output_len: 1,
            },
        )
        .unwrap();
        assert!(trusted_air(&shake).is_err());
    }
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod proof_tests;
