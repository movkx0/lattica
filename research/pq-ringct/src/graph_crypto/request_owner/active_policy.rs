//! Exact source-only policy used by the guarded full opt-validator at 24 GiB.
//! This accepts its unchanged partition, not a larger managed-device allowance.
use super::*;

fn check(policy: Policy) -> Result<()> {
    if policy.maximum_aes_blocks != 64
        || policy.maximum_shake_permutations != 32
        || policy.child_memory_budget_bytes != 24u64 << 30
        || policy.admission != Admission::Estimated
    {
        return Err(Error::Policy);
    }
    Ok(())
}

impl<'source> ShakeRequestPlan<'source> {
    /// Copy/admit only immutable request storage using the exact existing
    /// opt-validator policy: estimated max AES64/SHAKE32 and native24GiB.
    /// The original Request::new decides any pre-dispatch batch reduction.
    ///
    /// This is not complete graph/source authentication, native phase admission
    /// or dispatch authority. In particular the actual managed device ceiling
    /// remains 8 GiB and the worker host ceiling remains 32 GiB. The existing
    /// default constructor and graph collection keep their 8 GiB estimate gate.
    pub(crate) fn new_active_opt_validate_v1(
        profile: [u8; 32],
        operation: usize,
        subrequest: u32,
        input: &'source [u8],
        output_len: usize,
        policy: Policy,
    ) -> Result<Self> {
        check(policy)?;
        let (descriptor, bounds, requirements) = Self::source_geometry_with_estimate_ceiling(
            operation,
            subrequest,
            input.len(),
            output_len,
            policy,
            24u64 << 30,
        )?;
        Ok(Self {
            input,
            profile,
            operation,
            subrequest,
            descriptor,
            policy,
            bounds,
            requirements,
        })
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;
