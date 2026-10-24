//! Actual existing typed AES endpoint recursion; native child proving stays CPU.
use super::*;
use crate::{
    aes_air,
    component_tree::{self, CompiledNode, Contract, EndpointContext, WideAesProof},
};
use p3_uni_stark::StarkGenericConfig;

pub(super) struct Prepared {
    compiled: CompiledNode,
    context: EndpointContext,
    rows: usize,
    native_seconds: f64,
}

pub(super) fn prepare(limits: Limits) -> Result<Prepared, String> {
    let descriptor = aes_air::Descriptor {
        domain: 0x4368,
        start_counter: 0,
        output_len: 16,
    };
    let air = aes_air::AesAir::new(descriptor).map_err(err)?;
    limits.check_rows(air.height)?;
    let started = Instant::now();
    let generated = air
        .generate(core::array::from_fn(|i| i as u8))
        .map_err(err)?;
    let config = profile::make_config();
    require(config.is_zk() == 1, "native AES hiding disabled")?;
    // make_config is the original CPU configuration, independent of selected
    // proving switches. No GPU initialization has occurred in this process.
    let proof = p3_uni_stark::prove(&config, &air, generated.trace, &generated.public_values);
    p3_uni_stark::verify(&config, &air, &proof, &generated.public_values).map_err(err)?;
    let native_seconds = started.elapsed().as_secs_f64();
    let context = EndpointContext {
        context: [73; 32],
        statement: [Val::from_u64(0x5041_4553); 4],
        input: generated.public_values[..4].try_into().map_err(err)?,
        output: generated.public_values[4..].try_into().map_err(err)?,
    };
    let contract = Contract::aes(profile::CANDIDATE_PROFILE_ID, 0, descriptor).map_err(err)?;
    let child = WideAesProof {
        public_values: generated.public_values,
        proof,
    };
    // This constructor emits every native verifier check and binds the exact
    // input/output commitments, descriptor, context and complete request span.
    let compiled = component_tree::compile_wide_aes(&contract, &context, &child).map_err(err)?;
    drop(child);
    let rows = compiled.program().height();
    limits.check_rows(rows)?;
    Ok(Prepared {
        compiled,
        context,
        rows,
        native_seconds,
    })
}

impl Prepared {
    pub(super) fn prove(self, limits: Limits) -> Result<Value, String> {
        let prepared = self.compiled.prepare(limits.host_bytes).map_err(err)?;
        let key = prepared.key(); // trusted locally registered program/cap only
        let started = Instant::now();
        let mut proof = prepared.prove().map_err(err)?;
        let proving_seconds = started.elapsed().as_secs_f64();
        drop(prepared);
        key.verify_request(&proof, &self.context).map_err(err)?;
        let original = proof.public[component_tree::EXPECTED_OUTPUT];
        proof.public[component_tree::EXPECTED_OUTPUT] += Val::ONE;
        // Check cryptographic rejection, not merely an expected-header mismatch.
        require(
            key.verify(&proof).is_err(),
            "changed AES output commitment accepted",
        )?;
        proof.public[component_tree::EXPECTED_OUTPUT] = original;
        let opening = lookup_opening_mut(&mut proof.proof)?;
        let original = *opening;
        *opening += profile::Challenge::ONE;
        require(
            key.verify(&proof).is_err(),
            "changed AES recursive proof accepted",
        )?;
        *lookup_opening_mut(&mut proof.proof)? = original;
        key.verify_request(&proof, &self.context).map_err(err)?;
        Ok(
            json!({"scope": "Full typed recursive verifier of the existing one-block AES-256-CTR component",
            "recursive_component": true, "rows": self.rows, "native_child_backend": "cpu",
            "native_child_generation_and_verification_seconds": self.native_seconds,
            "proving_seconds": proving_seconds, "proof_json_bytes": serde_json::to_vec(&proof.proof).map_err(err)?.len(),
            "complete_request_verified": true, "complete_matrict_graph_verified": false}),
        )
    }
}
