//! Audited numeric compiler dependency envelope, shared by both build roots.
//! Conservative CPU compiler/protocol module subtrees include helper additions.
//! Research entries cover every native AIR, descriptor encoding and arithmetic
//! dependency. Core entries also cover registered-machine AIRs and storage types.
//! GPU kernels, transaction/proof drivers, C transaction generation and standalone
//! tests cannot affect numeric CPU compilation. Inline tests remain hashed with
//! their production module. New cross-module dependencies require this audit;
//! edits to a selected import/module declaration already invalidate existing rows.
//! The full workflow proof-cache digest remains deliberately broader.
const INPUTS: &[&str] = &[
    "core:lattica-prover-p3/src/block_v2/",
    "core:lattica-prover-p3/src/lib.rs",
    "core:lattica-prover-p3/src/config.rs",
    "core:lattica-prover-p3/src/domains.rs",
    "core:lattica-prover-p3/src/poseidon2_air.rs",
    "core:lattica-prover-p3/src/poseidon2_air/",
    "core:lattica-prover-p3/src/batch_common.rs",
    "core:lattica-prover-p3/src/batch_common/",
    "core:lattica-prover-p3/src/joinsplit_air.rs",
    "core:lattica-prover-p3/src/joinsplit_air/",
    "core:lattica-prover-p3/src/htlc_air.rs",
    "core:lattica-prover-p3/src/htlc_air/",
    "core:lattica-prover-p3/src/batch_joinsplit_air.rs",
    "core:lattica-prover-p3/src/batch_joinsplit_air/",
    "core:lattica-prover-p3/src/batch_htlc_air.rs",
    "core:lattica-prover-p3/src/batch_htlc_air/",
    "core:lattica-prover-p3/src/spend_common.rs",
    "core:lattica-prover-p3/src/proving.rs",
    "core:lattica-prover-p3/src/proving/",
    "core:lattica-prover-p3/src/ringct_research_quota.rs",
    "core:lattica-prover-p3/src/ringct_research_quota/",
    "core:lattica-prover-p3/src/host_memory.rs",
    "core:lattica-prover-p3/src/gpu_constants.rs",
    "core:lattica-prover-p3/src/gpu_hiding.rs",
    "core:lattica-prover-p3/src/gpu_matrix.rs",
    "core:lattica-prover-p3/src/transcript_limits.rs",
    "core:lattica-prover-p3/src/spill_alloc.rs",
    "core:lattica-prover-p3/vendor/",
    "core:lattica-prover-p3/Cargo.toml",
    "core:lattica-prover-p3/Cargo.lock",
    "core:lattica-prover-p3/build.rs",
    "core:lattica-prover-p3/metadata_sources.rs",
    "core:research/pq-ringct/Cargo.lock",
    "native:research/pq-ringct/src/lib.rs",
    "native:research/pq-ringct/src/graph_proofs.rs",
    "native:research/pq-ringct/src/rust_verify/",
    "native:research/pq-ringct/src/component_tree/native_shape.rs",
    "native:research/pq-ringct/src/component_tree/native_shape/",
    "native:research/pq-ringct/Cargo.toml",
    "native:research/pq-ringct/Cargo.lock",
    "native:research/pq-ringct/build.rs",
    "native:research/pq-ringct/graph_proof_sources.rs",
    "native:research/pq-ringct/src/aes_air.rs",
    "native:research/pq-ringct/src/aes_air/",
    "native:research/pq-ringct/src/aes_lane_air.rs",
    "native:research/pq-ringct/src/aes_lane_air/",
    "native:research/pq-ringct/src/shake_air.rs",
    "native:research/pq-ringct/src/shake_air/",
    "native:research/pq-ringct/src/transcript_air.rs",
    "native:research/pq-ringct/src/transcript_air/",
    "native:research/pq-ringct/src/sparse_air.rs",
    "native:research/pq-ringct/src/sparse_air/",
    "native:research/pq-ringct/src/uniform_air.rs",
    "native:research/pq-ringct/src/uniform_air/",
    "native:research/pq-ringct/src/statement_air.rs",
    "native:research/pq-ringct/src/statement_air/",
    "native:research/pq-ringct/src/proof_air.rs",
    "native:research/pq-ringct/src/proof_air/",
    "native:research/pq-ringct/src/affine_air.rs",
    "native:research/pq-ringct/src/affine_air/",
    "native:research/pq-ringct/src/ntt_air.rs",
    "native:research/pq-ringct/src/ntt_air/",
    "native:research/pq-ringct/src/poly_air.rs",
    "native:research/pq-ringct/src/poly_air/",
    "native:research/pq-ringct/src/g_bound_air.rs",
    "native:research/pq-ringct/src/g_bound_air/",
    "native:research/pq-ringct/src/permutation_air.rs",
    "native:research/pq-ringct/src/permutation_air/",
    "native:research/pq-ringct/src/linear_map_air.rs",
    "native:research/pq-ringct/src/linear_map_air/",
];
pub fn selected(label: &str, native: bool) -> bool {
    if label.ends_with("/precomputed/data.rs") {
        return false;
    }
    let name = label.rsplit('/').next().unwrap();
    if name == "tests.rs" || name.ends_with("_tests.rs") || label.split('/').any(|p| p == "tests") {
        return false;
    }
    if !(label.ends_with(".rs") || name == "Cargo.toml" || name == "Cargo.lock") {
        return false;
    }
    INPUTS.iter().any(|entry| {
        let (scope, path) = entry.split_once(':').unwrap();
        (native || scope == "core")
            && (label == path || path.ends_with('/') && label.starts_with(path))
    })
}
