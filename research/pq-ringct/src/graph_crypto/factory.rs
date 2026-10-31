use super::*;
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256,
};
use p3_field::PrimeCharacteristicRing;

// Independent endpoint verification uses fixed-size buffers, never a trace.
fn aes_lane_expected_public(air: &aes_lane_air::AesLaneAir, key: &[u8; 32]) -> [Val; 12] {
    let descriptor = air.descriptor;
    let input =
        shake_air::commit_bytes(aes_lane_air::AES_INPUT_DOMAIN, &descriptor.input_bytes(key));
    let mut output = [
        Val::from_u64(aes_lane_air::AES_OUTPUT_DOMAIN),
        Val::from_usize(descriptor.output_len),
        Val::ZERO,
        Val::ZERO,
    ];
    let mut public = [Val::ZERO; 12];
    public[..4].copy_from_slice(&input);
    let cipher = Aes256::new(key.into());
    for block in 0..air.first_block + air.blocks {
        if block == air.first_block {
            public[4..8].copy_from_slice(&output);
        }
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(
            &descriptor
                .start_counter
                .wrapping_add(block as u32)
                .to_le_bytes(),
        );
        bytes[8..].copy_from_slice(&descriptor.domain.to_le_bytes());
        let mut encrypted = bytes.into();
        cipher.encrypt_block(&mut encrypted);
        let take = (descriptor.output_len - block * 16).min(16);
        for chunk in encrypted[..take].chunks(8) {
            shake_air::absorb_commitment(&mut output, chunk);
        }
    }
    public[8..].copy_from_slice(&output);
    public
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    #[test]
    fn aes_segment_endpoints_match_cpu_trace_with_counter_wrap() {
        let key = core::array::from_fn(|i| (i * 13 + 7) as u8);
        for (output_len, first_block, blocks) in [(1, 0, 1), (16, 0, 1), (17, 0, 2), (49, 1, 3)] {
            let air = aes_lane_air::AesLaneAir::segment(
                crate::aes_air::Descriptor {
                    domain: 0x1020304050607080,
                    start_counter: u32::MAX,
                    output_len,
                },
                first_block,
                blocks,
            )
            .unwrap();
            assert_eq!(
                aes_lane_expected_public(&air, &key),
                air.generate(key).unwrap().public_values,
                "output={output_len} first={first_block} blocks={blocks}",
            );
        }
    }
}

impl Request {
    pub fn prove_segment_with_context(
        &self,
        index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<SegmentArtifact> {
        let Some(execution) = execution else {
            return self.prove_segment(index);
        };
        if execution.policy() != lattica_prover_p3::proving::Policy::GpuRequired {
            return execution
                .with_native_cpu(|| self.prove_segment(index).map_err(|e| e.to_string()))
                .map_err(err);
        }
        self.admit(index)?;
        #[cfg(not(feature = "opencl"))]
        return Err(Error("crypto GPU proving requires OpenCL feature".into()));
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(self.memory_budget.min(execution.host_bytes())).map_err(err)?;
            self.prove_admitted_segment_on_gpu(index, execution, host)
        }
    }

    /// Use a caller's remaining host allowance after it has reserved all
    /// retained siblings and other external owners. No CPU or cache fallback.
    /// This is requested-capacity admission, not a whole-process peak bound.
    pub fn prove_segment_with_context_and_host_allowance(
        &self,
        index: usize,
        execution: &crate::execution::ProvingContext,
        remaining_host_bytes: u64,
    ) -> Result<SegmentArtifact> {
        require(
            execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired,
            "bounded native proving requires GpuRequired",
        )?;
        require(
            remaining_host_bytes != 0 && remaining_host_bytes <= execution.host_bytes(),
            "bounded native remaining host allowance",
        )?;
        let info = self.admit(index)?;
        let host = self.memory_budget.min(remaining_host_bytes);
        require(
            info.estimated_peak_bytes <= host,
            "crypto segment exceeds remaining registered estimate allowance",
        )?;
        #[cfg(not(feature = "opencl"))]
        {
            let _ = host;
            Err(Error("crypto GPU proving requires OpenCL feature".into()))
        }
        #[cfg(feature = "opencl")]
        self.prove_admitted_segment_on_gpu(index, execution, usize::try_from(host).map_err(err)?)
    }

    #[cfg(feature = "opencl")]
    fn prove_admitted_segment_on_gpu(
        &self,
        index: usize,
        execution: &crate::execution::ProvingContext,
        host: usize,
    ) -> Result<SegmentArtifact> {
        let artifact = match (&self.partition, &self.payload) {
            (Partition::Aes(partition), Payload::Aes(key)) => {
                let air = &partition.segments()[index];
                let proved = execution
                    .prove_native_on_gpu(
                        "pq_aes_lane_native",
                        air,
                        air,
                        air.height,
                        host,
                        |context| air.generate_gpu(context, key),
                    )
                    .map_err(err)?;
                SegmentArtifact::Aes(AesLaneSegmentProof {
                    public_values: proved
                        .public_values
                        .try_into()
                        .map_err(|_| Error("AES GPU public width".into()))?,
                    proof: proved.proof,
                })
            }
            (Partition::Shake(partition), Payload::Shake(input)) => {
                let air = &partition.segments()[index];
                let proved = execution
                    .prove_native_on_gpu(
                        "pq_shake_segment_native",
                        air,
                        air,
                        air.height(),
                        host,
                        |context| air.generate_gpu(context, input),
                    )
                    .map_err(err)?;
                SegmentArtifact::Shake(LaneShakeProof {
                    public_values: proved
                        .public_values
                        .try_into()
                        .map_err(|_| Error("SHAKE GPU public width".into()))?,
                    proof: proved.proof,
                })
            }
            _ => return Err(Error("crypto request partition/payload mismatch".into())),
        };
        self.verify_segment(index, &artifact)?;
        Ok(artifact)
    }
    fn admit(&self, index: usize) -> Result<&SegmentInfo> {
        let info = self
            .segments
            .get(index)
            .ok_or_else(|| Error("crypto segment index".into()))?;
        require(
            info.estimated_peak_bytes <= self.memory_budget,
            "crypto segment exceeds registered estimate budget",
        )?;
        Ok(info)
    }
    /// Native output bytes for sampler/transcript witness generation only.
    pub fn output_bytes_hint(&self) -> Vec<u8> {
        match (&self.payload, self.descriptor) {
            (Payload::Aes(key), RequestDescriptor::Aes(d)) => {
                let cipher = Aes256::new(key.into());
                let mut output = Vec::with_capacity(d.output_len);
                for block in 0..d.blocks() {
                    let mut input = [0u8; 16];
                    input[..4]
                        .copy_from_slice(&d.start_counter.wrapping_add(block as u32).to_le_bytes());
                    input[8..].copy_from_slice(&d.domain.to_le_bytes());
                    let mut encrypted = input.into();
                    cipher.encrypt_block(&mut encrypted);
                    output.extend_from_slice(&encrypted[..(d.output_len - output.len()).min(16)]);
                }
                output
            }
            (Payload::Shake(input), RequestDescriptor::Shake(d)) => {
                crate::rust_verify::primitives::shake(input, d.output_len)
            }
            _ => {
                unreachable!("private request construction preserves its descriptor/payload family")
            }
        }
    }
    /// Unproved public endpoint hints. The component tree and the full graph
    /// source/producer joins must constrain these roots before acceptance.
    pub fn endpoint_context_hint(
        &self,
        context: &graph_tree::GraphContext,
    ) -> crate::component_tree::EndpointContext {
        let (input_domain, input, output_domain) = match (&self.payload, self.descriptor) {
            (Payload::Aes(key), RequestDescriptor::Aes(d)) => (
                aes_lane_air::AES_INPUT_DOMAIN,
                d.input_bytes(key).to_vec(),
                aes_lane_air::AES_OUTPUT_DOMAIN,
            ),
            (Payload::Shake(input), RequestDescriptor::Shake(_)) => (
                shake_air::SHAKE_INPUT_DOMAIN,
                input.clone(),
                shake_air::SHAKE_OUTPUT_DOMAIN,
            ),
            _ => unreachable!("private request family"),
        };
        crate::component_tree::EndpointContext {
            context: context.context,
            statement: context.statement,
            input: shake_air::commit_bytes(input_domain, &input),
            output: shake_air::commit_bytes(output_domain, &self.output_bytes_hint()),
        }
    }
    /// Produce exactly one native child, under the unchanged security profile.
    /// Estimated admission is not a memory guarantee; use a process-level cap
    /// when benchmarking unmeasured batches. Never calls a full-request loop.
    pub fn prove_segment(&self, index: usize) -> Result<SegmentArtifact> {
        self.admit(index)?;
        let config = profile::make_cpu_config();
        let artifact = match (&self.partition, &self.payload) {
            (Partition::Aes(partition), Payload::Aes(key)) => {
                let air = &partition.segments()[index];
                let witness = air.generate(*key).map_err(err)?;
                let proof =
                    p3_uni_stark::prove(&config, air, witness.trace, &witness.public_values);
                p3_uni_stark::verify(&config, air, &proof, &witness.public_values).map_err(err)?;
                SegmentArtifact::Aes(AesLaneSegmentProof {
                    public_values: witness.public_values,
                    proof,
                })
            }
            (Partition::Shake(partition), Payload::Shake(input)) => {
                let air = &partition.segments()[index];
                let witness = air.generate(input).map_err(err)?;
                let proof =
                    p3_uni_stark::prove(&config, air, witness.trace, &witness.public_values);
                p3_uni_stark::verify(&config, air, &proof, &witness.public_values).map_err(err)?;
                SegmentArtifact::Shake(LaneShakeProof {
                    public_values: witness.public_values,
                    proof,
                })
            }
            _ => return Err(Error("crypto request partition/payload mismatch".into())),
        };
        require(
            artifact.proof().degree_bits == self.segments[index].height.ilog2() as usize + 1,
            "crypto child logical trace height",
        )?;
        Ok(artifact)
    }
    /// Independent CPU checks authenticate cache contents, never graph coverage. Public
    /// endpoints are independently regenerated from the fixed request hints;
    /// actual proof verification is still required in every consuming circuit.
    pub fn verify_segment(&self, index: usize, artifact: &SegmentArtifact) -> Result<()> {
        let info = self.admit(index)?;
        require(
            artifact.proof().degree_bits == info.height.ilog2() as usize + 1,
            "crypto child logical trace height",
        )?;
        let config = profile::make_cpu_config();
        match (&self.partition, &self.payload, artifact) {
            (Partition::Aes(partition), Payload::Aes(key), SegmentArtifact::Aes(proof)) => {
                let air = &partition.segments()[index];
                let expected = aes_lane_expected_public(air, key);
                require(
                    proof.public_values == expected,
                    "AES cached child endpoint mismatch",
                )?;
                p3_uni_stark::verify(&config, air, &proof.proof, &proof.public_values).map_err(err)
            }
            (Partition::Shake(partition), Payload::Shake(input), SegmentArtifact::Shake(proof)) => {
                let air = &partition.segments()[index];
                let RequestDescriptor::Shake(descriptor) = self.descriptor else {
                    return Err(Error("SHAKE descriptor family".into()));
                };
                let expected = shake_air::ShakeAir::new(
                    descriptor,
                    air.first_permutation(),
                    air.permutations(),
                )
                .map_err(err)?
                .expected_public_values(input)
                .map_err(err)?;
                require(
                    proof.public_values == expected,
                    "SHAKE cached child endpoint mismatch",
                )?;
                p3_uni_stark::verify(&config, air, &proof.proof, &proof.public_values).map_err(err)
            }
            _ => Err(Error("crypto child artifact family mismatch".into())),
        }
    }
    /// Compile the real child verifier into a registered component-tree leaf.
    /// Native checking below only reports errors early; it is not the predicate.
    pub fn compile_segment_leaf(
        &self,
        index: usize,
        context: &graph_tree::GraphContext,
        artifact: &SegmentArtifact,
    ) -> Result<crate::component_tree::CompiledNode> {
        let endpoints = self.endpoint_context_hint(context);
        self.compile_segment_leaf_with_endpoints(index, &endpoints, artifact, None)
    }
    pub(super) fn compile_segment_leaf_with_endpoints(
        &self,
        index: usize,
        endpoints: &crate::component_tree::EndpointContext,
        artifact: &SegmentArtifact,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<crate::component_tree::CompiledNode> {
        self.verify_segment(index, artifact)?;
        let info = &self.segments[index];
        let contract = self.contract()?;
        match artifact {
            SegmentArtifact::Aes(proof) => crate::component_tree::compile_aes_with_context(
                &contract,
                u32::try_from(info.first_unit).map_err(err)?,
                u32::try_from(info.units).map_err(err)?,
                endpoints,
                proof,
                execution,
            ),
            SegmentArtifact::Shake(proof) => {
                crate::component_tree::compile_shake_batch_with_context(
                    &contract,
                    u32::try_from(info.first_unit).map_err(err)?,
                    u32::try_from(info.units).map_err(err)?,
                    endpoints,
                    proof,
                    execution,
                )
            }
        }
        .map_err(err)
    }
}
