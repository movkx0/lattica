//! Process-wide request ceilings for a private wallet assignment. These charge
//! existing and in-flight Rust allocations, including full spill backing. They
//! do not reserve a whole proof's GPU capacity or cover foreign allocator/RSS
//! ownership. An assigned process must keep its caller and thread contract fixed.
use super::{Assignment, Budget};
use crate::block_v2::execution::worker_budget;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Limits {
    system: usize,
    host: usize,
}

impl Limits {
    pub(super) fn for_budget(budget: &Budget) -> Result<Self, String> {
        let system = worker_budget::system_request_limit_bytes(budget.host_bytes, budget.threads)
            .map_err(|e| e.to_string())?;
        let host = worker_budget::host_request_limit_bytes(budget.host_bytes, budget.threads)
            .map_err(|e| e.to_string())?;
        if budget.host_output_bytes > host {
            return Err(
                "wallet host output allowance overlaps stacks, staging or retained heap".into(),
            );
        }
        Ok(Self {
            system: usize::try_from(system).map_err(|_| "wallet System request limit overflow")?,
            host: usize::try_from(host).map_err(|_| "wallet host request limit overflow")?,
        })
    }
}

// Failed installation cannot be retried under a different environment. Successful
// limits also survive GPU shutdown/reinitialization, as the allocator does.
static RUNTIME: OnceLock<Result<Assignment, String>> = OnceLock::new();

pub(super) fn is_pinned() -> bool {
    RUNTIME.get().is_some()
}

pub(super) fn check_assignment(assignment: Option<&Assignment>) -> Result<(), String> {
    match RUNTIME.get() {
        None => Ok(()),
        Some(Ok(pinned)) if assignment == Some(pinned) => Ok(()),
        Some(Ok(_)) => Err("wallet runtime resource assignment cannot change".into()),
        Some(Err(error)) => Err(error.clone()),
    }
}

pub(super) fn initialize(assignment: Option<&Assignment>) -> Result<(), String> {
    initialize_with(assignment, install)
}

fn initialize_with(
    assignment: Option<&Assignment>,
    install_runtime: impl FnOnce(&Assignment) -> Result<(), String> + std::panic::UnwindSafe,
) -> Result<(), String> {
    check_assignment(assignment)?;
    let Some(assignment) = assignment else {
        return Ok(());
    };
    RUNTIME
        .get_or_init(|| {
            // The native ABI catches panics. Catch inside this OnceLock too:
            // unwinding its initializer would otherwise leave it empty while
            // allocator ceilings may already be installed.
            std::panic::catch_unwind(|| {
                if crate::block_v2::gpu_hash::is_enabled() {
                    return Err("wallet runtime admission must precede GPU initialization".into());
                }
                install_runtime(assignment)?;
                Ok(assignment.clone())
            })
            .unwrap_or_else(|_| Err("wallet runtime admission panicked".into()))
        })
        .as_ref()
        .map_err(Clone::clone)?;
    check_ready(Some(assignment))
}

#[cfg(all(target_os = "linux", feature = "stream"))]
fn install(assignment: &Assignment) -> Result<(), String> {
    use crate::block_v2::execution::gpu_admission;
    let limits = Limits::for_budget(&assignment.budget)?;
    gpu_admission::validate_wallet_caller_stack().map_err(|e| e.to_string())?;
    #[cfg(target_env = "gnu")]
    crate::spill_alloc::host_backing::admit_worker_startup("before_wallet_rayon")
        .map_err(|e| e.to_string())?;
    // The allocator atomically includes requests made before activation; a
    // concurrent allocation must retry against the installed ceiling.
    crate::spill_alloc::system_budget::admit_worker(limits.system)?;
    crate::spill_alloc::host_budget::admit_worker(limits.host)?;
    // Native owners may already have used CPU verification. Permit their Rayon
    // pool only after observing its actual count and stack/guard/signal backing.
    if rayon::current_num_threads() != assignment.budget.threads as usize {
        return Err("wallet worker Rayon pool differs from assignment".into());
    }
    gpu_admission::validate_wallet_rayon_stacks(assignment.budget.threads)
        .map_err(|e| e.to_string())?;
    if std::env::var("LATTICA_PROVING_REPORT").as_deref() == Ok("1") {
        eprintln!("bounded_wallet_runtime host_bytes={} system_request_bytes={} combined_request_bytes={} threads={} full_spill_backing_charged=true immutable_until_exit=true before_gpu=true complete_proof_reservation=false",
            assignment.budget.host_bytes, limits.system, limits.host, assignment.budget.threads);
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "stream")))]
fn install(_: &Assignment) -> Result<(), String> {
    Err("assigned wallet host request admission requires Linux and the stream allocator".into())
}

pub(super) fn check_ready(assignment: Option<&Assignment>) -> Result<(), String> {
    check_assignment(assignment)?;
    let Some(assignment) = assignment else {
        return Ok(());
    };
    if !matches!(RUNTIME.get(), Some(Ok(pinned)) if pinned == assignment) {
        return Err("wallet runtime resources were not admitted".into());
    }
    #[cfg(all(target_os = "linux", feature = "stream"))]
    {
        let limits = Limits::for_budget(&assignment.budget)?;
        let system = crate::spill_alloc::system_budget::snapshot();
        let host = crate::spill_alloc::host_budget::snapshot();
        if !system.accounting_valid
            || !host.accounting_valid
            || system.limit_bytes != Some(limits.system)
            || host.limit_bytes != Some(limits.host)
            || system.reserved_request_bytes > limits.system
            || host.reserved_request_bytes > limits.host
            || rayon::current_num_threads() != assignment.budget.threads as usize
        {
            return Err("wallet runtime allocation or Rayon contract changed".into());
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "linux", feature = "stream")))]
    Err("wallet runtime resource checks unavailable".into())
}

#[cfg(test)]
mod tests;
