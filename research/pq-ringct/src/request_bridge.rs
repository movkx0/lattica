//! Authenticate an entire AES/SHAKE request through direct children or a
//! registered recursive component tree. Tree endpoints are constrained to the
//! caller's roots after verifying the child, its exact descriptor and context.
use crate::{
    aes_lane_air,
    component_tree::{NodeKey, NodeProof},
    crypto_join::Error,
    obligation_manifest::{ContextWires, CryptoShape},
    sampler_bridge::AesArtifacts,
    shake_air,
    transcript_bridge::ShakeArtifacts,
};
use lattica_prover_p3::block_v2::machine::{
    program::{ScopedProgramBuilder, Wire},
    verifier::ProofInputs,
};

/// `index` and `context` must come from the caller's registered plan and
/// authenticated public header. They are not claims supplied by a child proof.
pub struct TreeArtifacts<'a> {
    pub key: &'a NodeKey,
    pub proof: &'a NodeProof,
    pub context: &'a ContextWires,
    pub index: u32,
}
pub enum AesRequest<'a> {
    Direct(AesArtifacts<'a>),
    Tree(TreeArtifacts<'a>),
}
pub enum ShakeRequest<'a> {
    Direct(ShakeArtifacts<'a>),
    Tree(TreeArtifacts<'a>),
}
impl<'a> From<AesArtifacts<'a>> for AesRequest<'a> {
    fn from(value: AesArtifacts<'a>) -> Self {
        Self::Direct(value)
    }
}
impl<'a> From<ShakeArtifacts<'a>> for ShakeRequest<'a> {
    fn from(value: ShakeArtifacts<'a>) -> Self {
        Self::Direct(value)
    }
}
impl<'a> From<TreeArtifacts<'a>> for AesRequest<'a> {
    fn from(value: TreeArtifacts<'a>) -> Self {
        Self::Tree(value)
    }
}
impl<'a> From<TreeArtifacts<'a>> for ShakeRequest<'a> {
    fn from(value: TreeArtifacts<'a>) -> Self {
        Self::Tree(value)
    }
}

fn require_shape(actual: &CryptoShape, expected: &CryptoShape) -> Result<(), Error> {
    if actual != expected {
        return Err(Error::Shape(
            "substituted recursive request descriptor or index",
        ));
    }
    Ok(())
}
impl TreeArtifacts<'_> {
    fn verify(
        self,
        b: &mut ScopedProgramBuilder<'_>,
        inputs: &mut ProofInputs,
        shape: CryptoShape,
        input: &[Wire; 4],
        output: &[Wire; 4],
    ) -> Result<(), Error> {
        let actual = self
            .key
            .manifest_shape()
            .map_err(|e| Error::Tree(e.to_string()))?;
        require_shape(&actual, &shape)?;
        let roots = self
            .key
            .compile_manifest_record(b, inputs, self.proof, self.context)
            .map_err(|e| Error::Tree(e.to_string()))?;
        for (actual, expected) in roots.iter().zip([input, output]) {
            for i in 0..4 {
                b.assert_equal(actual[i], expected[i]);
            }
        }
        Ok(())
    }
}
pub(crate) fn verify_aes_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    descriptor: aes_lane_air::Descriptor,
    input: &[Wire; 4],
    output: &[Wire; 4],
    request: AesRequest<'_>,
) -> Result<(), Error> {
    match request {
        AesRequest::Direct(a) => aes_lane_air::join::verify_committed_request(
            b,
            inputs,
            descriptor,
            input,
            output,
            a.partition,
            a.proofs,
        ),
        AesRequest::Tree(a) => {
            let shape = CryptoShape::Aes {
                index: a.index,
                domain: descriptor.domain,
                start_counter: descriptor.start_counter,
                output_len: descriptor.output_len,
            };
            a.verify(b, inputs, shape, input, output)
        }
    }
}
pub(crate) fn verify_shake_request(
    b: &mut ScopedProgramBuilder<'_>,
    inputs: &mut ProofInputs,
    descriptor: shake_air::Descriptor,
    input: &[Wire; 4],
    output: &[Wire; 4],
    request: ShakeRequest<'_>,
) -> Result<(), Error> {
    match request {
        ShakeRequest::Direct(a) => shake_air::lane::batch::verify_committed_batched_request(
            b,
            inputs,
            descriptor,
            input,
            output,
            a.partition,
            a.proofs,
        ),
        ShakeRequest::Tree(a) => {
            let shape = CryptoShape::Shake {
                index: a.index,
                input_len: descriptor.input_len,
                output_len: descriptor.output_len,
            };
            a.verify(b, inputs, shape, input, output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_request_shape_rejects_family_index_counter_domain_and_length_changes() {
        let expected = CryptoShape::Aes {
            index: 11,
            domain: 0x4368,
            start_counter: 161,
            output_len: 127,
        };
        assert!(require_shape(&expected, &expected).is_ok());
        for wrong in [
            CryptoShape::Aes {
                index: 12,
                domain: 0x4368,
                start_counter: 161,
                output_len: 127,
            },
            CryptoShape::Aes {
                index: 11,
                domain: 0,
                start_counter: 161,
                output_len: 127,
            },
            CryptoShape::Aes {
                index: 11,
                domain: 0x4368,
                start_counter: 160,
                output_len: 127,
            },
            CryptoShape::Aes {
                index: 11,
                domain: 0x4368,
                start_counter: 161,
                output_len: 128,
            },
            CryptoShape::Shake {
                index: 11,
                input_len: 32,
                output_len: 127,
            },
        ] {
            assert!(require_shape(&wrong, &expected).is_err());
        }
        let expected = CryptoShape::Shake {
            index: 7,
            input_len: 230496,
            output_len: 32,
        };
        assert!(require_shape(&expected, &expected).is_ok());
        for wrong in [
            CryptoShape::Shake {
                index: 6,
                input_len: 230496,
                output_len: 32,
            },
            CryptoShape::Shake {
                index: 7,
                input_len: 230495,
                output_len: 32,
            },
            CryptoShape::Shake {
                index: 7,
                input_len: 230496,
                output_len: 137,
            },
        ] {
            assert!(require_shape(&wrong, &expected).is_err());
        }
    }

    #[test]
    #[ignore = "actual SHAKE request outer proof and constrained consumer; exclusive 32GiB window"]
    fn actual_pp_request_tree_and_constrained_consumer() {
        use crate::{
            component_tree::{self, Contract, EndpointContext},
            rust_verify::{committed_backend::BYTES32_DOMAIN, primitives},
            shake_air::{
                commit_bytes,
                lane::{LaneShakeAir, LaneShakeProof},
            },
            transcript_bridge::{pp_input_bytes, verify_parameters_pp},
        };
        use lattica_prover_p3::block_v2::{
            machine::{
                pq_bytes::{SHAKE_INPUT_DOMAIN, SHAKE_OUTPUT_DOMAIN},
                program::Val,
                MachineAir, ProgramBuilder,
            },
            profile,
        };
        use p3_field::PrimeCharacteristicRing;

        let setup = [43; 32];
        let context = [61; 32];
        let profile_label = [79; 32];
        let data = pp_input_bytes(&setup, &context);
        let pp: [u8; 32] = primitives::shake(&data, 32).try_into().unwrap();
        let descriptor = shake_air::Descriptor {
            input_len: data.len(),
            output_len: 32,
        };
        assert_eq!(descriptor.permutations().unwrap(), 1);
        let contract = Contract::shake(profile_label, 14, descriptor).unwrap();
        let endpoint = EndpointContext {
            context,
            statement: [Val::from_u32(23); 4],
            input: commit_bytes(SHAKE_INPUT_DOMAIN, &data),
            output: commit_bytes(SHAKE_OUTPUT_DOMAIN, &pp),
        };
        let air = LaneShakeAir::new(descriptor, 0).unwrap();
        let witness = air.generate(&data).unwrap();
        let config = profile::make_config();
        let child = LaneShakeProof {
            proof: p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values),
            public_values: witness.public_values,
        };
        let compiled = component_tree::compile_shake(&contract, 0, &endpoint, &child).unwrap();
        compiled.evaluate().unwrap();
        let geometry = compiled.geometry().unwrap();
        eprintln!(
            "actual PP request tree: active_rows={} height={} wires={} retained_lde_bytes={}",
            geometry.active_rows, geometry.padded_rows, geometry.wires, geometry.retained_lde_bytes
        );
        let prepared = compiled.prepare(32_u64 << 30).unwrap();
        let key = prepared.key();
        let mut proof = prepared.prove().unwrap();
        drop(prepared);
        key.verify_request(&proof, &endpoint).unwrap();

        // Public values authenticate the caller's complete transaction context
        // and graph byte roots. Every one must be linked by the compiled join.
        let words = |bytes: &[u8; 32]| -> [Val; 8] {
            core::array::from_fn(|i| {
                Val::from_u32(u32::from_le_bytes(
                    bytes[4 * i..4 * i + 4].try_into().unwrap(),
                ))
            })
        };
        let mut public = words(&profile_label).to_vec();
        public.extend(words(&context));
        public.extend(endpoint.statement);
        public.extend(commit_bytes(BYTES32_DOMAIN, &context));
        public.extend(commit_bytes(BYTES32_DOMAIN, &pp));
        let compile = |proof: &NodeProof, index: u32| -> Result<(MachineAir, ProofInputs), Error> {
            let mut b = ProgramBuilder::new(28).unwrap();
            let expected = ContextWires {
                profile: core::array::from_fn(|i| b.public(i).unwrap()),
                context: core::array::from_fn(|i| b.public(8 + i).unwrap()),
                statement: core::array::from_fn(|i| b.public(16 + i).unwrap()),
            };
            let context_root = core::array::from_fn(|i| b.public(20 + i).unwrap());
            let pp_root = core::array::from_fn(|i| b.public(24 + i).unwrap());
            let mut inputs = ProofInputs::default();
            verify_parameters_pp(
                &mut b,
                &mut inputs,
                &setup,
                &context_root,
                &context,
                &pp_root,
                &pp,
                TreeArtifacts {
                    key: &key,
                    proof,
                    context: &expected,
                    index,
                },
            )?;
            Ok((MachineAir::new(b.finish(None).unwrap()), inputs))
        };
        assert!(compile(&proof, 15).is_err());
        let (machine, inputs) = compile(&proof, 14).unwrap();
        machine.trace(&public, &inputs.values).unwrap();
        eprintln!(
            "PP request-tree consumer: active_rows={} height={} wires={}",
            machine.program().active_rows(),
            machine.program().height(),
            machine.program().wire_count()
        );
        for i in 0..public.len() {
            public[i] += Val::ONE;
            assert!(
                machine.trace(&public, &inputs.values).is_err(),
                "unbound public field {i}"
            );
            public[i] -= Val::ONE;
        }
        drop(machine);
        drop(inputs);
        proof.proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += profile::Challenge::ONE;
        assert!(key.verify_request(&proof, &endpoint).is_err());
        if let Ok((machine, inputs)) = compile(&proof, 14) {
            assert!(machine.trace(&public, &inputs.values).is_err());
        }
    }
}
