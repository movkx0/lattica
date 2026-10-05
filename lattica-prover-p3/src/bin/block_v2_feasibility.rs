//! Local, allocation-safe feasibility report. Exit 2 means the block gate is
//! incomplete/blocked, NOT a successful aggregate proof. No files are persisted.

use std::process::ExitCode;
use std::time::Instant;

use lattica_prover_p3::block_v2::{commitment::Context, feasibility::*, leaf, profile};
use lattica_prover_p3::{config, joinsplit_air as js, recursion::aggregation as agg};

fn run() -> Result<(), String> {
    println!("candidate_status=inactive");
    println!("budgets ram_bytes={RAM_BUDGET_BYTES} vram_bytes={VRAM_BUDGET_BYTES} scratch_bytes={SCRATCH_BUDGET_BYTES}");
    let ctx = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: [0x5a; 32],
    };
    let witness = js::demo_witness();
    let pis = js::public_values(&witness);
    let started = Instant::now();
    let proof =
        leaf::prove_joinsplit_research(&witness, &ctx).map_err(|e| format!("leaf prove: {e:?}"))?;
    let prove_ms = started.elapsed().as_millis();
    let started = Instant::now();
    leaf::verify_joinsplit_research(&proof, &ctx, &pis)
        .map_err(|e| format!("leaf verify: {e:?}"))?;
    println!(
        "candidate_leaf proof_bytes={} prove_ms={prove_ms} verify_ms={}",
        proof.len(),
        started.elapsed().as_millis()
    );
    let security = leaf::security().map_err(|e| format!("leaf security: {e:?}"))?;
    println!("candidate_leaf_security {security:?}");
    println!(
        "composition proof_statements={} union_loss_bits=8 recursive_air_bound=UNAVAILABLE",
        profile::MAX_TREE_PROOF_STATEMENTS
    );

    // Real q96 binary-FRI inputs for the inherited backend. This backend is Fp2,
    // not the candidate's Fp3; do NOT feed v2 proofs to it or label this a v2 merge.
    println!("inherited_backend profile=v1-binary-q96-fp2 operation=geometry-only");
    let first = p3_uni_stark::prove(
        &config::make_recursion_binary_config(),
        &js::JoinSplitAir,
        js::build_trace(&witness),
        &pis,
    );
    let second = p3_uni_stark::prove(
        &config::make_recursion_binary_config(),
        &js::JoinSplitAir,
        js::build_trace(&witness),
        &pis,
    );
    let first = postcard::to_allocvec(&first).map_err(|e| e.to_string())?;
    let second = postcard::to_allocvec(&second).map_err(|e| e.to_string())?;
    let plan = agg::plan_joinsplit_aggregate_production(
        &[
            agg::JoinSplitAggregateInput {
                proof_bytes: &first,
                public_values: &pis,
            },
            agg::JoinSplitAggregateInput {
                proof_bytes: &second,
                public_values: &pis,
            },
        ],
        agg::ProductionAggregationOptions::binary_recursion(),
    )
    .map_err(|e| format!("inherited planning: {e:?}"))?;
    let footprint = CommitFootprint::for_geometry(
        plan.aggregate_trace.height as u64,
        plan.aggregate_trace.width as u64,
    )
    .map_err(|e| format!("footprint: {e:?}"))?;
    let inherited = plan
        .stream_spill_estimate()
        .map_err(|e| format!("inherited spill estimate: {e:?}"))?;
    if footprint.trace_commit_peak_bytes != inherited.trace_commit_peak_bytes as u64 {
        return Err("independent footprint estimate disagrees with existing planner".into());
    }
    println!(
        "inherited_geometry height={} width={}",
        plan.aggregate_trace.height, plan.aggregate_trace.width
    );
    println!("inherited_commit_footprint {footprint:?}");
    println!(
        "inherited_scratch_lower_bound={:?}",
        footprint.check_scratch_lower_bound(SCRATCH_BUDGET_BYTES)
    );
    println!("gate=BLOCKED bounded_cubic_recursive_air=NOT_IMPLEMENTED depth6=NOT_RUN root_proof=NOT_PRODUCED");
    println!("This rules out reusing the current monolith within the budget; it does not establish infeasibility of a redesigned bounded verifier.");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(2),
        Err(error) => {
            eprintln!("gate=ERROR {error}");
            ExitCode::FAILURE
        }
    }
}
