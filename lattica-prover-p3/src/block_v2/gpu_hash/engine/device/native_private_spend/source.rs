//! Source-only census for the fixed, non-oracle n10 native spend controller.
//! No constructor here creates a context, reads entropy, reserves memory or
//! authorizes a proof. The caller supplies original ledger reservations.
use super::*;
use crate::block_v2::native_gpu::private_spend::{InputSource, PrivateSpendRequest};
use crate::ringct_research_quota::{Bytes, Category, Requirements};
use core::mem::size_of;

mod memory;
mod ocl_storage;
mod pins;
#[cfg(all(test, feature = "stream"))]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSpendSourceError {
    Configuration,
    Source,
    Overflow,
    Request,
    Output,
    Evidence,
}
type Result<T> = core::result::Result<T, NativeSpendSourceError>;

/// Immutable source facts, never a reservation, execution receipt or token.
/// Input request backing is reported separately because its fixture owner
/// already retains that storage. Returned output has a separate original.
pub struct NativeSpendOperationPlan {
    limits: SpendLimits,
    operation: Requirements,
    shared: Requirements,
    output: Requirements,
    fingerprint: [u8; 32],
    managed: usize,
}

impl NativeSpendOperationPlan {
    pub fn new(limits: SpendLimits) -> Result<Self> {
        // Canonical research execution profile. The 24 GiB value is the API
        // ceiling, not a requested host allocation or replacement allowance.
        let expected = SpendLimits::bounded(24 << 30);
        if cfg!(feature = "native-spend-oracle")
            || size_of::<usize>() != 8
            || limits.host_bytes != expected.host_bytes
            || limits.max_attempts != expected.max_attempts
            || limits.random_call_limit != expected.random_call_limit
            || limits.proposal_limit != expected.proposal_limit
        {
            return Err(NativeSpendSourceError::Configuration);
        }
        let fingerprint = pins::check()?;
        let managed = memory::managed_bytes()?;
        let host = memory::operation_host_bytes()?;
        if host > limits.host_bytes
            || add(InputSource::input_backing_bytes(), host)? > limits.host_bytes
        {
            return Err(NativeSpendSourceError::Configuration);
        }
        Ok(Self {
            limits,
            operation: requirement(Category::PhaseScratch, host, managed)?,
            shared: requirement(Category::RegisteredMetadata, memory::static_bytes()?, 0)?,
            output: requirement(Category::NativeProof, memory::output_bytes()?, 0)?,
            fingerprint,
            managed,
        })
    }
    pub fn requirements(&self) -> Requirements { self.operation }
    pub fn shared_static_requirements(&self) -> Requirements { self.shared }
    pub fn output_requirements(&self) -> Requirements { self.output }
    pub fn input_backing_bytes(&self) -> usize { InputSource::input_backing_bytes() }
    pub fn packed_backing_bytes(&self) -> usize { InputSource::packed_backing_bytes() }
    pub fn managed_bytes(&self) -> usize { self.managed }
    pub fn source_fingerprint(&self) -> [u8; 32] { self.fingerprint }
    pub fn limits(&self) -> SpendLimits { self.limits }
    pub fn check_request(&self, request: &PrivateSpendRequest) -> Result<()> {
        if InputSource::check_request(request) { Ok(()) }
        else { Err(NativeSpendSourceError::Request) }
    }
    pub fn check_output(&self, output: &PrivateSpendOutput) -> Result<()> {
        if InputSource::check_output(output) { Ok(()) }
        else { Err(NativeSpendSourceError::Output) }
    }
    pub fn check_evidence(&self, evidence: &SpendEvidence) -> Result<()> {
        if evidence.prelude_steps != PRELUDE_MASK
            || evidence.accepted_attempt_steps != ACCEPTED_MASK
            || evidence.managed_bytes != self.managed
            || evidence.kernel_source_sha256 != SOURCE_SHA256
        { return Err(NativeSpendSourceError::Evidence); }
        Ok(())
    }
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(NativeSpendSourceError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(NativeSpendSourceError::Overflow)
}
fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0, add)
}
fn requirement(category: Category, host: usize, device: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(host).map_err(|_| NativeSpendSourceError::Overflow)?,
        device: u64::try_from(device).map_err(|_| NativeSpendSourceError::Overflow)?,
    }))
}
