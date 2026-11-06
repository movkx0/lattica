//! Explicit CPU paired compilation/proving. GPU ownership is never bypassed.
use super::*;
use crate::execution::ProvingContext;
use lattica_prover_p3::proving::Policy;
use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Timings {
    pub registration_ns: u128,
    pub proving_ns: u128,
    pub verification_ns: u128,
}

pub(crate) fn compile_pair(
    request: &crate::graph_crypto::Request,
    context: &crate::graph_tree::GraphContext,
    first: usize,
    children: &[crate::graph_crypto::SegmentArtifact],
) -> Result<CompiledNode> {
    require((1..=2).contains(&children.len()), "CPU paired group size")?;
    let schedule = request
        .shake_wrapper_schedule(crate::graph_crypto::ShakeWrapperLayout::PairedV1)
        .map_err(err)?;
    let span = schedule
        .groups()
        .find(|s| s.first_segment == first)
        .ok_or_else(|| err("CPU group is not a canonical paired interval"))?;
    require(
        span.segment_count == children.len(),
        "CPU paired group coverage",
    )?;
    let mut members = Vec::with_capacity(2);
    for (offset, child) in children.iter().enumerate() {
        request.verify_segment(first + offset, child).map_err(err)?;
        let crate::graph_crypto::SegmentArtifact::Shake(proof) = child else {
            return Err(err("CPU paired SHAKE received AES proof"));
        };
        let segment = &request.segments()[first + offset];
        members.push(ShakeGroupMember {
            first: segment.first_unit.try_into().map_err(err)?,
            count: segment.units.try_into().map_err(err)?,
            proof,
        });
    }
    let endpoints = request.endpoint_context_hint(context);
    let limits = ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: lattica_prover_p3::block_v2::machine::program::MAX_WIRES,
        max_input_values: 1 << 20,
    };
    match compile_shake_group_bounded_with_context(
        &request.contract().map_err(err)?,
        &members,
        &endpoints,
        None,
        limits,
        512 << 20,
    )? {
        ShakeGroupCompileOutcome::Compiled(node) => Ok(node),
        ShakeGroupCompileOutcome::ResourceRefused(_) => {
            Err(err("CPU paired compiler resource refusal"))
        }
    }
}

impl CompiledNode {
    pub(crate) fn cpu_output_bytes(&self) -> Result<u64> {
        output_bytes(
            &self.program,
            self.public.capacity(),
            self.witness.capacity(),
        )
    }
    /// Admission uses CPU matrix geometry, not device reservations. This is a
    /// conservative research estimate; the external cgroup remains the hard cap.
    pub(crate) fn cpu_admission_bytes(&self) -> Result<u64> {
        admission(&self.geometry()?)
    }
    pub(crate) fn cpu_identity(&self) -> Result<[u8; 32]> {
        use sha3::{Digest, Sha3_256};
        let mut hash = Sha3_256::new();
        hash.update(b"ringct-cpu-prepared-program-v1");
        self.program
            .visit_manifest_fields(&mut |word| {
                hash.update(word.to_le_bytes());
                Ok(())
            })
            .map_err(err)?;
        Ok(hash.finalize().into())
    }
    pub(crate) fn prove_cpu(
        self,
        execution: &ProvingContext,
    ) -> Result<(NodeKey, NodeProof, Timings)> {
        require(
            execution.policy() == Policy::CpuRequired,
            "CPU paired proof requires CpuRequired",
        )?;
        require(
            self.cpu_admission_bytes()? <= execution.host_bytes(),
            "CPU proof admission estimate exceeds allowance",
        )?;
        let Self {
            spec,
            program,
            public,
            witness,
        } = self;
        let start = Instant::now();
        execution
            .with_registered_shared(program, |registered| {
                let registration_ns = start.elapsed().as_nanos();
                let key = NodeKey {
                    spec,
                    height: registered.air().program().height(),
                    cap: registered.preprocessing_cap().roots().to_vec(),
                    verifier: registered.verifier(),
                };
                let start = Instant::now();
                let proof = registered.prove(&public, &witness)?;
                let proving_ns = start.elapsed().as_nanos();
                let start = Instant::now();
                key.verifier.verify(&proof, &public)?;
                let verification_ns = start.elapsed().as_nanos();
                Ok((
                    key,
                    NodeProof { public, proof },
                    Timings {
                        registration_ns,
                        proving_ns,
                        verification_ns,
                    },
                ))
            })
            .map_err(err)
    }
}

pub(crate) fn output_bytes(
    program: &Program,
    public_capacity: usize,
    witness_capacity: usize,
) -> Result<u64> {
    let values = public_capacity
        .checked_add(witness_capacity)
        .and_then(|n| n.checked_mul(std::mem::size_of::<Val>()))
        .ok_or_else(|| err("CPU input capacity overflow"))?;
    let bytes = program
        .construction_host_bytes()
        .checked_add(values)
        .and_then(|n| n.checked_add(1 << 20))
        .ok_or_else(|| err("CPU output capacity overflow"))?;
    require(
        program.construction_host_bytes() > 0 && bytes <= (2 << 30) + (32 << 20),
        "CPU compiled output exceeds original claim",
    )?;
    u64::try_from(bytes).map_err(err)
}

pub(crate) fn admission(g: &Geometry) -> Result<u64> {
    let rows = (g.padded_rows as u64)
        .checked_mul(32)
        .ok_or_else(|| err("CPU rows overflow"))?;
    // Source inventory: hiding PCS retains all LDEs, four salts per
    // matrix, five commitment forests, and the opening/FRI workspaces.
    // Quotient-domain views borrow committed matrices (generator coset).
    // The original program/input storage is charged separately by the DAG.
    // This remains a research estimate, not an allocation-derived bound.
    let matrices = (g.quotient_chunks as u64)
        .checked_add(4)
        .ok_or_else(|| err("CPU matrix count"))?;
    let salts = rows
        .checked_mul(matrices)
        .and_then(|n| n.checked_mul(4 * 8));
    let trees = rows.checked_mul(5 * 2 * 4 * 8);
    let opening = rows.checked_mul(8 + 8 * 24 + 4 * 24 + 4 * 4 * 8);
    let max_width = g
        .preprocessed_width
        .max(g.main_width + 4)
        .max(g.permutation_width_base + 4) as u64;
    let natural = rows
        .checked_mul(max_width)
        .and_then(|n| n.checked_mul(8))
        .map(|n| n / 8);
    let mut bytes = g.retained_lde_bytes;
    for value in [salts, trees, opening, natural, Some(512 << 20)] {
        bytes = bytes
            .checked_add(value.ok_or_else(|| err("CPU memory estimate overflow"))?)
            .ok_or_else(|| err("CPU memory estimate overflow"))?;
    }
    eprintln!(
        "CPU_PROOF_GEOMETRY {}",
        serde_json::json!({"active_rows":g.active_rows,
            "padded_rows":g.padded_rows,"preprocessed_width":g.preprocessed_width,
            "main_width":g.main_width,"permutation_width_base":g.permutation_width_base,
            "quotient_chunks":g.quotient_chunks,"retained_lde_bytes":g.retained_lde_bytes,
            "salt_bytes":salts,"merkle_bytes":trees,"opening_bytes":opening,
            "estimated_work_bytes":bytes,"program_and_inputs_separately_charged":true})
    );
    Ok(bytes)
}
