//! Whole-request provisioning with the original unchanged wide AES AIR.
//! Native verification is required on every cache reuse; recursive graph
//! acceptance additionally verifies the actual complete component-tree proof.
use super::*;
use crate::aes_air;

pub struct WideAesFactory<'a> {
    request: &'a Request,
    air: aes_air::AesAir,
    geometry: LayoutGeometry,
    memory_budget: u64,
    // Lazily evaluated independent CPU verifier oracle. Construction and GPU
    // endpoint preparation do not execute this reference computation.
    expected_public: std::sync::OnceLock<[Val; aes_air::PUBLIC_VALUES]>,
}

impl Request {
    /// Select the complete original wide AES AIR. The estimate is admission
    /// only, not a bound on peak RSS; an external process guard is still needed.
    /// No partitioning or security-profile change is performed here.
    pub fn wide_aes(&self, child_memory_budget_bytes: u64) -> Result<WideAesFactory<'_>> {
        let (RequestDescriptor::Aes(descriptor), Payload::Aes(_)) =
            (self.descriptor, &self.payload)
        else {
            return Err(Error(
                "wide AES factory requires a registered AES request".into(),
            ));
        };
        require(
            child_memory_budget_bytes != 0,
            "zero wide AES worker budget",
        )?;
        let air = aes_air::AesAir::new(descriptor).map_err(err)?;
        let geometry = LayoutGeometry::new(air.width(), air.height)?;
        require(
            geometry.uncalibrated_peak_estimate_bytes <= child_memory_budget_bytes,
            "whole wide AES request exceeds estimated worker budget",
        )?;
        Ok(WideAesFactory {
            request: self,
            air,
            geometry,
            memory_budget: child_memory_budget_bytes,
            expected_public: std::sync::OnceLock::new(),
        })
    }
}

impl WideAesFactory<'_> {
    fn expected_public_cpu(&self) -> &[Val; aes_air::PUBLIC_VALUES] {
        self.expected_public.get_or_init(|| {
            let mut expected = [Val::default(); aes_air::PUBLIC_VALUES];
            expected[..4].copy_from_slice(&shake_air::commit_bytes(
                aes_air::AES_INPUT_DOMAIN,
                &self.air.descriptor.input_bytes(self.key()),
            ));
            expected[4..].copy_from_slice(&shake_air::commit_bytes(
                aes_air::AES_OUTPUT_DOMAIN,
                &self.request.output_bytes_hint(),
            ));
            expected
        })
    }
    pub(super) fn request(&self) -> &Request {
        self.request
    }
    pub fn descriptor(&self) -> aes_air::Descriptor {
        self.air.descriptor
    }
    pub fn geometry(&self) -> LayoutGeometry {
        self.geometry
    }
    fn admit(&self) -> Result<&aes_air::AesAir> {
        require(
            self.geometry.uncalibrated_peak_estimate_bytes <= self.memory_budget,
            "whole wide AES request exceeds registered estimate budget",
        )?;
        Ok(&self.air)
    }
    fn key(&self) -> &[u8; 32] {
        let Payload::Aes(key) = &self.request.payload else {
            unreachable!("private wide factory construction requires an AES request")
        };
        key
    }
    /// Whole-wide, serial and SHAKE identities cannot collide by layout alias.
    /// Native proofs do not contain graph context; the typed outer leaf binds
    /// that context and its statement to this exact registered request contract.
    pub fn cache_key(&self) -> Result<[u8; 32]> {
        let air = self.admit()?;
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/whole-wide-aes-child-cache/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(self.request.profile);
        hash.update(self.request.index.to_le_bytes());
        for field in [
            air.descriptor.domain,
            u64::from(air.descriptor.start_counter),
            air.descriptor.output_len as u64,
            air.descriptor.blocks() as u64,
            air.width() as u64,
            air.height as u64,
        ] {
            hash.update(field.to_le_bytes());
        }
        hash.update(self.key());
        Ok(hash.finalize().into())
    }
    pub fn prove(&self) -> Result<WideAesProof> {
        let air = self.admit()?;
        let witness = air.generate(*self.key()).map_err(err)?;
        require(
            witness.public_values == *self.expected_public_cpu(),
            "whole wide AES witness commitment mismatch",
        )?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = WideAesProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify(&artifact)?;
        Ok(artifact)
    }
    pub fn prove_with_context(
        &self,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<WideAesProof> {
        let Some(execution) = execution else {
            return self.prove();
        };
        if execution.policy() != lattica_prover_p3::proving::Policy::GpuRequired {
            return execution
                .with_native_cpu(|| self.prove().map_err(|e| e.to_string()))
                .map_err(err);
        }
        let air = self.admit()?;
        #[cfg(not(feature = "opencl"))]
        {
            let _ = air;
            Err(Error("wide AES GPU proving requires OpenCL feature".into()))
        }
        #[cfg(feature = "opencl")]
        {
            let host =
                usize::try_from(self.memory_budget.min(execution.host_bytes())).map_err(err)?;
            let proved = execution
                .prove_native_on_gpu(
                    "pq_aes_wide_native",
                    air,
                    air,
                    air.height,
                    host,
                    |context| air.generate_gpu(context, self.key()),
                )
                .map_err(err)?;
            let artifact = WideAesProof {
                public_values: proved
                    .public_values
                    .try_into()
                    .map_err(|_| Error("wide AES GPU public width".into()))?,
                proof: proved.proof,
            };
            self.verify(&artifact)?;
            Ok(artifact)
        }
    }
    /// Independent CPU proof verification and lazily cached endpoint oracle.
    /// This does not prepare GPU witnesses or allocate a native trace.
    pub fn verify(&self, artifact: &WideAesProof) -> Result<()> {
        let air = self.admit()?;
        require(
            artifact.proof.degree_bits == air.height.ilog2() as usize + 1,
            "whole wide AES child logical trace height",
        )?;
        require(
            artifact.public_values == *self.expected_public_cpu(),
            "whole wide AES cached child commitment mismatch",
        )?;
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            air,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(err)
    }
    pub fn compile_leaf(
        &self,
        context: &graph_tree::GraphContext,
        artifact: &WideAesProof,
    ) -> Result<crate::component_tree::CompiledNode> {
        let endpoints = self.request.endpoint_context_hint(context);
        self.compile_leaf_with_endpoints(&endpoints, artifact, None)
    }
    pub(super) fn compile_leaf_with_endpoints(
        &self,
        endpoints: &crate::component_tree::EndpointContext,
        artifact: &WideAesProof,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<crate::component_tree::CompiledNode> {
        self.verify(artifact)?;
        crate::component_tree::compile_wide_aes_with_context(
            &self.request.contract()?,
            endpoints,
            artifact,
            execution,
        )
        .map_err(err)
    }
}

#[cfg(test)]
mod tests;
