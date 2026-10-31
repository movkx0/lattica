//! Exact wide SHAKE child provisioning for the same registered graph requests.
//! Admission uses an uncalibrated memory estimate and still requires external
//! process guards. Neither cache checks nor planning discharge graph coverage.
use super::*;
use crate::crypto_join::{ShakePartition, ShakeSegmentProof};

pub struct WideShakeFactory<'a> {
    request: &'a Request,
    partition: ShakePartition,
    geometries: Vec<LayoutGeometry>,
    memory_budget: u64,
}

impl Request {
    /// Choose an explicit partition of the existing wide AIR. A segment which
    /// exceeds the estimated worker budget is rejected, not silently resized.
    /// Whole HashAlpha therefore does not fit an 8/64 GiB estimate; an explicit
    /// smaller partition is a separate, unmeasured production candidate.
    pub fn wide_shake(
        &self,
        maximum_permutations: usize,
        child_memory_budget_bytes: u64,
    ) -> Result<WideShakeFactory<'_>> {
        let RequestDescriptor::Shake(descriptor) = self.descriptor else {
            return Err(Error(
                "wide SHAKE factory requires a registered SHAKE request".into(),
            ));
        };
        require(
            child_memory_budget_bytes != 0,
            "zero wide SHAKE worker budget",
        )?;
        let partition = ShakePartition::new(descriptor, maximum_permutations).map_err(err)?;
        let geometries = partition
            .segments()
            .iter()
            .map(|air| LayoutGeometry::new(air.width(), air.height))
            .collect::<Result<Vec<_>>>()?;
        require(
            geometries
                .iter()
                .all(|g| g.uncalibrated_peak_estimate_bytes <= child_memory_budget_bytes),
            "wide SHAKE segment exceeds estimated worker budget",
        )?;
        Ok(WideShakeFactory {
            request: self,
            partition,
            geometries,
            memory_budget: child_memory_budget_bytes,
        })
    }
}

impl WideShakeFactory<'_> {
    pub(super) fn request(&self) -> &Request {
        self.request
    }
    pub fn segments(&self) -> &[shake_air::ShakeAir] {
        self.partition.segments()
    }
    pub fn segment_count(&self) -> usize {
        self.segments().len()
    }
    pub fn partition(&self) -> &ShakePartition {
        &self.partition
    }
    pub fn geometry(&self, index: usize) -> Result<LayoutGeometry> {
        self.geometries
            .get(index)
            .copied()
            .ok_or_else(|| Error("wide SHAKE segment index".into()))
    }
    fn admit(&self, index: usize) -> Result<&shake_air::ShakeAir> {
        let geometry = self.geometry(index)?;
        require(
            geometry.uncalibrated_peak_estimate_bytes <= self.memory_budget,
            "wide SHAKE segment exceeds registered estimate budget",
        )?;
        self.segments()
            .get(index)
            .ok_or_else(|| Error("wide SHAKE segment index".into()))
    }
    fn input(&self) -> &[u8] {
        let Payload::Shake(input) = &self.request.payload else {
            unreachable!("private wide factory construction requires a SHAKE request")
        };
        input
    }
    /// A separate namespace prevents serial and wide proof layouts from
    /// becoming interchangeable cache hits, even with equal endpoint roots.
    pub fn cache_key(&self, index: usize) -> Result<[u8; 32]> {
        let air = self.admit(index)?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/wide-shake-child-cache/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(self.request.profile);
        hash.update(self.request.index.to_le_bytes());
        for field in [
            air.descriptor.input_len,
            air.descriptor.output_len,
            index,
            air.first_permutation,
            air.permutations,
            air.width(),
            air.height,
        ] {
            hash.update((field as u64).to_le_bytes());
        }
        hash.update((self.input().len() as u64).to_le_bytes());
        hash.update(self.input());
        Ok(hash.finalize().into())
    }
    /// Prove exactly one native segment under the unchanged security profile.
    /// A full request is not accepted until every segment and join is proved.
    pub fn prove_segment(&self, index: usize) -> Result<ShakeSegmentProof> {
        let air = self.admit(index)?;
        let witness = air.generate(self.input()).map_err(err)?;
        let config = profile::make_cpu_config();
        let proof = p3_uni_stark::prove(&config, air, witness.trace, &witness.public_values);
        require(
            proof.degree_bits == air.height.ilog2() as usize + 1,
            "wide SHAKE child logical trace height",
        )?;
        p3_uni_stark::verify(&config, air, &proof, &witness.public_values).map_err(err)?;
        Ok(ShakeSegmentProof {
            public_values: witness.public_values,
            proof,
        })
    }
    pub fn prove_segment_with_context(
        &self,
        index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<ShakeSegmentProof> {
        let Some(execution) = execution else {
            return self.prove_segment(index);
        };
        if execution.policy() != lattica_prover_p3::proving::Policy::GpuRequired {
            return execution
                .with_native_cpu(|| self.prove_segment(index).map_err(|e| e.to_string()))
                .map_err(err);
        }
        let air = self.admit(index)?;
        #[cfg(not(feature = "opencl"))]
        {
            let _ = air;
            Err(Error(
                "wide SHAKE GPU proving requires OpenCL feature".into(),
            ))
        }
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(self.memory_budget.min(execution.host_bytes())).map_err(err)?;
            let proved = execution
                .prove_native_on_gpu(
                    "pq_shake_wide_native",
                    air,
                    air,
                    air.height,
                    host,
                    |context| air.generate_gpu(context, self.input()),
                )
                .map_err(err)?;
            let artifact = ShakeSegmentProof {
                public_values: proved
                    .public_values
                    .try_into()
                    .map_err(|_| Error("wide SHAKE GPU public width".into()))?,
                proof: proved.proof,
            };
            self.verify_segment(index, &artifact)?;
            Ok(artifact)
        }
    }
    /// Independently verify on CPU against this request's exact native
    /// payload, then verify the actual proof. This is not recursive acceptance.
    pub fn verify_segment(&self, index: usize, artifact: &ShakeSegmentProof) -> Result<()> {
        let air = self.admit(index)?;
        require(
            artifact.proof.degree_bits == air.height.ilog2() as usize + 1,
            "wide SHAKE child logical trace height",
        )?;
        let expected = air.expected_public_values(self.input()).map_err(err)?;
        require(
            artifact.public_values == expected,
            "wide SHAKE cached child endpoint mismatch",
        )?;
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(err)
    }
    /// The descriptor, profile and request identity come only from the trusted
    /// graph plan. The returned node emits the full registered child verifier.
    pub fn compile_segment_leaf(
        &self,
        index: usize,
        context: &graph_tree::GraphContext,
        artifact: &ShakeSegmentProof,
    ) -> Result<crate::component_tree::CompiledNode> {
        let endpoints = self.request.endpoint_context_hint(context);
        self.compile_segment_leaf_with_endpoints(index, &endpoints, artifact, None)
    }
    pub(super) fn compile_segment_leaf_with_endpoints(
        &self,
        index: usize,
        endpoints: &crate::component_tree::EndpointContext,
        artifact: &ShakeSegmentProof,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<crate::component_tree::CompiledNode> {
        self.verify_segment(index, artifact)?;
        let air = self.admit(index)?;
        crate::component_tree::compile_wide_shake_with_context(
            &self.request.contract()?,
            u32::try_from(air.first_permutation).map_err(err)?,
            u32::try_from(air.permutations).map_err(err)?,
            endpoints,
            artifact,
            execution,
        )
        .map_err(err)
    }
}
