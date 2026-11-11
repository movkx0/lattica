use super::*;
pub(super) fn run(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    let execution = context(options)?;
    let outcome = lattica_prover_p3::block_v2::gpu_hash::aggregation_kernel_screen(
        options.seconds.saturating_sub(15),
    );
    let cleanup = execution.close_without_completion()?;
    let mut report = outcome?;
    deadline.check()?;
    report["session"] = cleanup;
    Ok(report)
}
